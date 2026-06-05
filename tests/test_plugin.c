#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static const size_t page_size = 4096;

typedef enum {
	ARCH_X86_32,
	ARCH_ARM,
	ARCH_MIPS,
	ARCH_UNKNOWN
} arch_t;

typedef struct {
    int prot;
    bool written;
    uint64_t write_count;
    uint64_t last_write;
} page_t;

static GHashTable *pages = NULL;

static arch_t current_arch = ARCH_UNKNOWN;

static uint64_t oep_addr = 0;

static void do_dump(uint64_t oep) {
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, pages);

	FILE *f = fopen("unpacked.bin", "wb");
	if (!f) return;

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		uint64_t page_start = (uint64_t)(uintptr_t)key;
		page_t *p = (page_t*)value;
		if (p->prot & 0x4) {
			GByteArray *data = g_byte_array_new();
			bool ok = qemu_plugin_read_memory_vaddr(page_start, data, page_size);
			if (ok && data->len > 0) {
				fwrite(data->data, 1, data->len, f);
			}
			g_byte_array_free(data, TRUE);
		}
	}
	fclose(f);
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
	uint64_t vaddr = (uint64_t)(uintptr_t) udata;
	uint64_t page = vaddr & ~(page_size - 1);
	
	if (oep_addr != 0) return;
	page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page);
	if (p && p->written && (p->prot & 0x4)) {
		oep_addr = vaddr;
		fprintf(stderr, "[OEP] 0x%lx\n", oep_addr);
		do_dump(oep_addr);
	}
	//fprintf(stderr, "[INSN] 0x%012lx\n", vaddr);
}

static void vcpu_mem(unsigned int vcpu_idx, qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
	if (qemu_plugin_mem_is_store(info)) {
		page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t)(vaddr & ~(page_size - 1)));
		if (p) {
			p->written = true;
			p->write_count++;
			p->last_write = vaddr;
			//fprintf(stderr, "[MEM-W] addr=0x%012lx page=0x%012lx count=%lu\n", vaddr, vaddr & ~0xFFF, p->write_count);
		} else {
			page_t *np = g_new0(page_t, 1);
			np->written = true;
			np->write_count = 1;
			np->last_write = vaddr;
			g_hash_table_insert(pages, (gpointer)(uintptr_t)(vaddr & ~(page_size - 1)), np);
		}
	}
}

static void vpcu_syscall(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
	//x86
	if (num == 192 || num == 90) { //mmap
		int prot = (int)a3;
		if (prot & 0x2 || prot & 0x4) {
			fprintf(stderr, "[SYSCALL] mmap/mmap2(0x%lx, 0x%lx, prot=0x%lx, flags=0x%lx, fd=%lu, offset=0x%lx)\n", a1, a2, a3, a4, a5, a6);
			uint64_t page_start = a1 & ~(page_size - 1);
			uint64_t page_end = (a1 + a2 + page_size - 1) & ~(page_size - 1);
			for (uint64_t addr = page_start; addr < page_end; addr += page_size) {
				page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t)addr);
				if (p) {
					p->prot = prot;
				} else {
					page_t *np = g_new0(page_t, 1);
					np->prot = prot;
					g_hash_table_insert(pages, (gpointer)(uintptr_t)addr, np);
				}
			}
			if ((prot & 0x4) && a5 != (uint64_t)-1) {
				for (uint64_t addr = page_start; addr < page_end; addr += page_size) {
					page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t)addr);
					if (p) p->written = true;
				}
				fprintf(stderr, "[HEURISTIC] mmap EXEC file 0x%lx-0x%lx\n", page_start, page_end);
			}
		}
	} else if (num == 125 || num == 380) { //mprotect
		int prot = (int) a3;
		uint64_t page_start = a1 & ~(page_size - 1);
		uint64_t page_end = (a1 + a2 + page_size - 1) & ~(page_size- 1);
		if (prot & 0x2 || prot & 0x4) {
			fprintf(stderr, "[HEURISTIC] mprotect/pkey_mprotect with PROT_EXEC\n");
			for (uint64_t addr = page_start; addr < page_end; addr += page_size) {
				page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t) addr);
				if (p) {
					p->prot = prot;
				} else {
					page_t *np = g_new0(page_t, 1);
					np->prot = prot;
					g_hash_table_insert(pages, (gpointer)(uintptr_t)addr, np);
				}
			}
		}
	} else if (num == 91) { //munmap
		uint64_t page_start = a1 & ~(page_size - 1);
		uint64_t page_end = (a1 + a2 + page_size - 1) & ~(page_size- 1);
		for (uint64_t addr = page_start; addr < page_end; addr += page_size) {
			page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t) addr);
			if (p) {
				if (p->written && (p->prot & 0x4) && oep_addr == 0) {
					do_dump(addr);
				}
				g_hash_table_remove(pages, (gpointer)(uintptr_t) addr);
				g_free(p);
			}
		}
		fprintf(stderr, "[SYSCALL] munmap(0x%lx, 0x%lx)\n", a1, a2);
	}
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
	size_t n_insns = qemu_plugin_tb_n_insns(tb);
	for (size_t i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
		qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (gpointer)(uintptr_t)vaddr);
		qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_W, NULL);
	}
}


QEMU_PLUGIN_EXPORT int qemu_plugin_install(
    qemu_plugin_id_t id,
    const qemu_info_t *info,
    int argc, char **argv)
{
	const char *target = info->target_name;

	if (strstr(target, "i386")) {
		current_arch = ARCH_X86_32;
	} else if (strstr(target, "arm")) {
		current_arch = ARCH_ARM;
	} else if (strstr(target, "mips")) {
		current_arch = ARCH_MIPS;
	} else {
		fprintf(stderr, "[PLUGIN] ERROR:%s", target);
		return -1;
	}
	fprintf(stderr, "[PLUGIN] Loaded for architecture: %s (enum=%d)\n", target, current_arch);
	
	pages = g_hash_table_new(g_direct_hash, g_direct_equal);

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_vcpu_syscall_cb(id, vpcu_syscall);

	return 0;
}
