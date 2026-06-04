#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef enum {
	ARCH_X86_32,
	ARCH_ARM,
	ARCH_MIPS,
	ARCH_UNKNOWN
} arch_t;

static arch_t current_arch = ARCH_UNKNOWN;

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
	uint64_t vaddr = GPOINTER_TO_UINT(udata);
	//fprintf(stderr, "[INSN] 0x%012lx\n", vaddr);
}

static void vcpu_mem(unsigned int vcpu_idx, qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata) {
	if (qemu_plugin_mem_is_store(info)) {
		fprintf(stderr, "[WRITE] addr:0x%012lx, size=%u\n", vaddr, 1u << qemu_plugin_mem_size_shift(info));
	}
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
	size_t n_insns = qemu_plugin_tb_n_insns(tb);
	for (size_t i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
		qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, GUINT_TO_POINTER(vaddr));
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

	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

	return 0;
}
