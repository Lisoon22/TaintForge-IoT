#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <qemu-plugin.h>
#include <math.h>
#include "dta.h"
#include <capstone/capstone.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "trace.h"
#include "dse.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static size_t page_size = 4096;

//OEP scoring
#define W_DSE    0.70
#define W_UNMAP  0.20
#define W_PROL   0.10
#define W_ACTIVE (W_DSE + W_UNMAP + W_PROL)
//tolerance
#define SCORE_EPS 1e-9

typedef enum {
	ARCH_X86_32,
	ARCH_ARM,
	ARCH_MIPS,
	ARCH_UNKNOWN
} arch_t;

typedef struct {
	int prot;
	bool written;
	bool exec_after_write;
	bool dyn_exec;
	uint64_t write_count;
	uint64_t last_write;
	uint8_t *wbitmap;
	uint32_t gen_written;
	bool exec_seen;
} page_t;

//multiple OEP vatiants
typedef struct {
	uint64_t addr;
	uint64_t jump_site;
	uint32_t generation;
	uint64_t icount;
	bool dse_confirmed;
	uint32_t dse_concretized;
	uint32_t dse_total;
	bool has_prologue;
	bool jump_from_unmapped;
} oep_cand_t;

//got table reconstruct helper
typedef struct {
	uint64_t got_slot;
	uint64_t resolved_addr;
	const char *module;
	uint64_t lib_base;
} resolved_import_t;

static GHashTable *pages = NULL;
static ShadowMemory *g_shadow = NULL;
static bool oep_found = false;
static uint64_t oep_addr = 0;
static __thread uint64_t g_current_ip = 0;
static csh cs_handle;
static RegShadow reg_shadow;
static TraceBuffer *g_trace = NULL;
static DseAuxRing *g_aux = NULL;
static __thread InsnAux *g_cur_aux = NULL;
static bool g_taint_seen = false;
static struct qemu_plugin_register *g_reg_handle[REG_COUNT];
static bool g_regs_ready = false;
static const char *g_reg_name_i386[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
static bool g_reg_read_error_reported[REG_COUNT];
//auxv read for threshold and determine precise page size
#ifndef AT_NULL
#define AT_NULL 0 //vector end
#define AT_PHDR 3 //phdr
#define AT_PHENT 4 //size of phdr
#define AT_PHNUM 5 //number of phdr
#define AT_PAGESZ 6 //page size
#define AT_BASE 7 // base of ld
#define AT_ENTRY 9 //entry point addr
#endif
//boundaries for main code
static uint64_t g_main_lo = 0;
static uint64_t g_main_hi = 0;
static bool g_main_known = false;
//ld base
static uint64_t g_ld_base = 0;
//AT_ENTRY in packed file typically points to packer's stub
static uint64_t g_stub_entry = 0;
static bool g_auxv_done = false;
//TODO stub for multiarch
static const DseArch *g_plugin_arch = &dse_arch_x86;
//additional OEP checks
static uint64_t g_icount = 0;
static uint32_t g_unpack_gen = 0;
static uint64_t g_last_cand_icount = 0;
static uint32_t g_layer = 0;
static bool g_layer_dirty = false;
static bool g_layer_has_cand = false;
static GList *oep_cands = NULL;
static GHashTable *unmapped_pages = NULL; //for munmaped pages

//addtional info for last indirect jump
static __thread uint64_t prev_jump_site = 0;
static __thread int prev_target_reg = REG_INVALID;
static __thread uint64_t prev_mem_taddr = 0;
static __thread bool prev_jump_pending = false;
static __thread uint64_t prev_mem_target_value = 0;
static __thread bool prev_mem_target_valid = false;

typedef struct {
	bool active;
	int64_t syscall_num;
	uint64_t requested_addr;
	uint64_t size;
	int prot;
	uint32_t flags;
	int32_t fd;
	uint64_t offset;
} pending_mmap_t;
static __thread pending_mmap_t g_pending_mmap;
//read <=8 raw bytes from guest memory
static bool guest_read_bytes(uint64_t gaddr, uint8_t *out, uint32_t n) {
	GByteArray *b = g_byte_array_new();
	bool ok = qemu_plugin_read_memory_vaddr(gaddr, b, n) && b->len >= n;
	if (ok) memcpy(out, b->data, n);
	g_byte_array_free(b, TRUE);
	return ok;
}

//read uint of sz bytes, saves the active endianness.
static bool guest_read_uint(uint64_t gaddr, uint32_t sz, uint64_t *out) {
	uint8_t raw[8];
	if (sz > 8 || !guest_read_bytes(gaddr, raw, sz)) return false;
	uint64_t v = 0;
	if (g_plugin_arch && g_plugin_arch->big_endian)
		for (uint32_t i = 0; i < sz; i++) v = (v << 8) | raw[i];
	else
		for (uint32_t i = 0; i < sz; i++) v |= (uint64_t)raw[i] << (8 * i);
	*out = v;
	return true;
}

//32 -> 4, 64 -> 8
static uint32_t guest_ptr_bytes(void) {
	uint32_t w;
	if (g_plugin_arch) {
		w = g_plugin_arch->natural_width;
	} else { 
		w = 32;
	}
	return (w >= 64) ? 8 : 4;
}

static bool read_socketcall_args(uint64_t block_addr, uint32_t out[6]) {
	if (!guest_read_bytes(block_addr, (uint8_t *)out, 24)) return false;
	return true;
}

gint compare_keys(gconstpointer a, gconstpointer b) {
	uint64_t addr_a = (uint64_t)(uintptr_t)a;
	uint64_t addr_b = (uint64_t)(uintptr_t)b;
	if (addr_a < addr_b) return -1;
	if (addr_a > addr_b) return 1;
	return 0;
}

static arch_t current_arch = ARCH_UNKNOWN;
static bool is_i386 = false;

typedef struct {
	char *path;
	bool write;
} file_dep_t;
typedef struct {
	char *path;
	uint64_t base;
	uint64_t size;
	uint64_t end;
} lib_mapping_t;
typedef struct {
	int fd;
	char op[16];
	int domain;
	int type;
	char ip[INET6_ADDRSTRLEN];
	uint16_t port;
	char *payload_hex;
} net_dep_t;
static GList *file_deps = NULL;
static GList *net_deps = NULL;
static GList *lib_deps = NULL;
static GHashTable *g_sockets = NULL;
static GHashTable *file_fd = NULL;
//fd
static char *pending_open_path = NULL;
static bool pending_open_is_lib = false;
static bool pending_open_write = false;

static GList *resolved_imports = NULL;
static GHashTable *resolved_imports_by_slot = NULL; //got slot thing

//stub for dynamic reconstruction
static const char *addr_lib_path(uint64_t addr) {
	if (addr == 0) return NULL;
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		if (!lm->base) continue;
		uint64_t end = (lm->end > lm->base) ? lm->end : (lm->base + lm->size);
		if (end <= lm->base) continue;
		if (addr >= lm->base && addr < end) return lm->path;
	}
	return NULL;
}

static uint64_t addr_lib_base(uint64_t addr) {
	if (addr == 0) return 0;
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		if (!lm->base) continue;
		uint64_t end = (lm->end > lm->base) ? lm->end : (lm->base + lm->size);
		if (end <= lm->base) continue;
		if (addr >= lm->base && addr < end) return lm->base;
	}
	return 0;
}

static const char *base_name(const char *path) {
	if (!path) return NULL;
	const char *s = strrchr(path, '/');
	return s ? s + 1 : path;
}

static bool syscall_ret_is_error(int64_t ret)
{
    if (is_i386) {
        const uint32_t raw_ret = (uint32_t)ret;
        return raw_ret >= UINT32_MAX - 4094U;
    }
    return ret < 0;
}

static void record_resolved_import(uint64_t got_slot, uint64_t resolved_addr) {
	if (!resolved_addr) return;
	uint64_t lib_base = addr_lib_base(resolved_addr);
	if (!lib_base) return;
	if (addr_lib_base(got_slot)) return;
	if (g_main_known && (got_slot < g_main_lo || got_slot >= g_main_hi)) return;
	if (resolved_imports_by_slot && g_hash_table_contains(resolved_imports_by_slot, (gpointer)(uintptr_t)got_slot)) return;
	resolved_import_t *ri = g_new0(resolved_import_t, 1);
	ri->got_slot = got_slot;
	ri->resolved_addr = resolved_addr;
	ri->module = addr_lib_path(resolved_addr);
	ri->lib_base = lib_base;
	resolved_imports = g_list_append(resolved_imports, ri);
	if (resolved_imports_by_slot) g_hash_table_add(resolved_imports_by_slot, (gpointer)(uintptr_t)got_slot);
}


static bool parse_guest_sockaddr(uint64_t gaddr, int addrlen, char *ip_out, size_t ip_size, uint16_t *port_out) {
	if (addrlen <= 0 || gaddr == 0 || !ip_out || !port_out) return false;
	memset(ip_out, 0, ip_size);
	*port_out = 0;

	GByteArray *arr = g_byte_array_new();
	if (!qemu_plugin_read_memory_vaddr(gaddr, arr, addrlen)) {
		g_byte_array_free(arr, TRUE);
		return false;
	}
	
	bool parsed = false;
	if (arr->len >= sizeof(struct sockaddr_in)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)arr->data;
		if (sin->sin_family == AF_INET) {
			inet_ntop(AF_INET, &sin->sin_addr, ip_out, ip_size);
			*port_out = ntohs(sin->sin_port);
			parsed = true;
		} else if (sin->sin_family == AF_INET6 && arr->len >= sizeof(struct sockaddr_in6)) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)arr->data;
			inet_ntop(AF_INET6, &sin6->sin6_addr, ip_out, ip_size);
			*port_out = ntohs(sin6->sin6_port);
			parsed = true;
		}
	}
	g_byte_array_free(arr, TRUE);
	return parsed;
}



static char *read_guest_string(uint64_t gaddr) {
	if (gaddr == 0) return NULL;

	GString *s = g_string_new(NULL);
	uint8_t chunk[64];
	for (size_t off = 0; off < 4096; off += sizeof chunk) {
		if (!guest_read_bytes(gaddr + off, chunk, sizeof chunk)) break;
		size_t i = 0;
		for (; i < sizeof chunk; i++) {
			if (chunk[i] == '\0') break;
			g_string_append_c(s, chunk[i]);
		}
		if (i < sizeof chunk) break;
	}

	if (s->len == 0) {
		g_string_free(s, TRUE);
		return NULL;
	}
	return g_string_free(s, FALSE);
}

//dse helpers
static void dse_init_reg_handles(void) {
	GArray *regs = qemu_plugin_get_registers();
	if (!regs) {
		fprintf(stderr, "[REG] failed to enumerate QEMU registers\n");
		return;
	}
	memset(g_reg_handle, 0, sizeof(g_reg_handle));
	int found = 0;
	for (guint i = 0; i < regs->len; i++) {
		qemu_plugin_reg_descriptor *d = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
		for (int r = 0; r < 8; r++)
			if (d->name && g_ascii_strcasecmp(d->name, g_reg_name_i386[r]) == 0) {
				if (!g_reg_handle[r]) found++;
				g_reg_handle[r] = d->handle;
				fprintf(stderr, "[REG] QEMU reg: %s\n", d->name ? d->name : "(null)");
			}
	}
	g_array_free(regs, TRUE);
	g_regs_ready = (found == 8);
	if (!g_regs_ready) {
		fprintf(stderr, "[REG] incomplete i386 register set: found %d/8\n", found);
	}
}

static void dse_vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index) {
	(void)id; (void)vcpu_index;
	if (!g_regs_ready) dse_init_reg_handles();
}

static bool dse_read_reg(int rid, uint64_t *out) {
	if (!out || rid < 0 || rid >= REG_COUNT || !g_regs_ready || !g_reg_handle[rid]) return false;
	static __thread GByteArray *buf = NULL;
	if (!buf) buf = g_byte_array_new();
	g_byte_array_set_size(buf, 0);
	int rc = qemu_plugin_read_register(g_reg_handle[rid], buf);
	if (rc <= 0 || buf->len == 0) {
		if (!g_reg_read_error_reported[rid]) {
			fprintf(stderr, "[REG] read failed for %s: rc=%d len=%u\n",
				g_reg_name_i386[rid], rc, buf->len);
			g_reg_read_error_reported[rid] = true;
		}
		return false;
	}

	size_t n = buf->len < 4 ? buf->len : 4;
	uint64_t v = 0;
	for (size_t i = 0; i < n; i++) v |= (uint64_t)buf->data[i] << (8 * i);
	*out = v & 0xFFFFFFFFULL;
	return true;
}

static bool dse_resolve_mem_target(uint64_t vaddr, const InsnMeta *meta, uint64_t *out_addr, uint64_t *out_val) {
	if (!g_regs_ready) dse_init_reg_handles();
	uint64_t taddr = 0;
	if (meta->insn_id == X86_INS_RET) {
		if (!dse_read_reg(REG_RSP, &taddr)) return false;
		taddr &= 0xFFFFFFFFULL;
	} else {
		uint8_t code[16];
		GByteArray *ib = g_byte_array_new();
		bool okr = qemu_plugin_read_memory_vaddr(vaddr, ib, meta->size > 16 ? 16 : meta->size);
		if (okr && ib->len) memcpy(code, ib->data, ib->len > 16 ? 16 : ib->len);
		g_byte_array_free(ib, TRUE);
		if (!okr) return false;

		cs_insn *insn = NULL;
		size_t n = cs_disasm(cs_handle, code, meta->size, vaddr, 1, &insn);
		if (n == 0) return false;
		bool ok = false;
		cs_x86 *x86 = &insn->detail->x86;
		if (x86->op_count >= 1 && x86->operands[0].type == X86_OP_MEM) {
			x86_op_mem *m = &x86->operands[0].mem;
			uint64_t ea = 0;
			if (m->base != X86_REG_INVALID) {
				uint64_t base = 0;
				int rid = x86_reg_to_rid(m->base);
				if (rid < 0 || !dse_read_reg(rid, &base)) {
					cs_free(insn, n);
					return false;
				}
				ea += base;
			}
			if (m->index != X86_REG_INVALID) {
				uint64_t index = 0;
				int rid = x86_reg_to_rid(m->index);
				if (rid < 0 || !dse_read_reg(rid, &index)) {
					cs_free(insn, n);
					return false;
				}
				ea += index * (uint64_t)m->scale;
			}
			ea += (uint64_t)(int64_t)m->disp;
			taddr = ea & 0xFFFFFFFFULL;
			ok = true;
		}
		cs_free(insn, n);
		if (!ok) return false;
	}
	GByteArray *arr = g_byte_array_new();
	bool read_ok = qemu_plugin_read_memory_vaddr(taddr, arr, 4);
	if (!read_ok || arr->len < 4) {
		g_byte_array_free(arr, TRUE);
		return false;
	}

	uint64_t value = 0;
	for (uint32_t i = 0; i < 4; i++) {
		value |= (uint64_t)arr->data[i] << (8 * i);
	}
	g_byte_array_free(arr, TRUE);

	*out_addr = taddr;
	*out_val = value;
	return true;
}
//separate rewrite and change
static inline bool insn_overwrites_dst(uint16_t id) {
	switch (id) {
		case X86_INS_MOV: case X86_INS_MOVZX: case X86_INS_MOVSX: case X86_INS_POP: case X86_INS_LEA: case X86_INS_XCHG:
			return true;
		default:
			return false;
	}
}
// xchg reg, reg
static bool taint_xchg_reg_reg(uint64_t vaddr, const InsnMeta *meta) {
	if (!meta || meta->insn_id != X86_INS_XCHG || meta->has_mem_read || meta->has_mem_write || meta->size == 0 || meta->size > 15) {
		return false;
	}

	uint8_t code[16] = {0};
	GByteArray *instruction_bytes = g_byte_array_new();
	if (!instruction_bytes)	return false;

	bool read_ok = qemu_plugin_read_memory_vaddr(vaddr, instruction_bytes, meta->size);

	if (!read_ok || instruction_bytes->len < meta->size) {
		g_byte_array_free(instruction_bytes, TRUE);
		return false;
	}

	memcpy(code, instruction_bytes->data, meta->size);
	g_byte_array_free(instruction_bytes, TRUE);

	cs_insn *decoded = NULL;
	size_t decoded_count = cs_disasm(cs_handle,code, meta->size, vaddr, 1, &decoded);
	if (decoded_count != 1 || !decoded || !decoded->detail) {
		if (decoded) {
			cs_free(decoded, decoded_count);
		}
		return false;
	}

	const cs_x86 *x86 = &decoded->detail->x86;
	if (x86->op_count != 2) {
		cs_free(decoded, decoded_count);
		return false;
	}

	const cs_x86_op *left =&x86->operands[0];
	const cs_x86_op *right = &x86->operands[1];
	if (left->type != X86_OP_REG || right->type != X86_OP_REG || left->size == 0 || left->size != right->size) {
		cs_free(decoded, decoded_count);
		return false;
	}

	int left_rid = x86_reg_to_rid(left->reg);
	int right_rid = x86_reg_to_rid(right->reg);
	if (left_rid < 0 || left_rid >= REG_COUNT || right_rid < 0 || right_rid >= REG_COUNT) {
		cs_free(decoded, decoded_count);
		return false;
	}

	uint32_t operand_bytes = (uint32_t)left->size;

	if (operand_bytes == 0 || operand_bytes > 4) {
		cs_free(decoded, decoded_count);
		return false;
	}

	uint32_t left_offset = 0;
	uint32_t right_offset = 0;

	if (left->reg == X86_REG_AH || left->reg == X86_REG_BH || left->reg == X86_REG_CH || left->reg == X86_REG_DH) {
		left_offset = 1;
	}

	if (right->reg == X86_REG_AH || right->reg == X86_REG_BH || right->reg == X86_REG_CH || right->reg == X86_REG_DH) {
		right_offset = 1;
	}

	if ((left_offset + operand_bytes) > 4 || (right_offset + operand_bytes) > 4) {
		cs_free( decoded, decoded_count);
		return false;
	}
	uint8_t left_taint[4] = {0};
	uint8_t right_taint[4] = {0};
	for (uint32_t i = 0; i < operand_bytes; i++) {
		left_taint[i] = reg_shadow.bytes[left_rid][left_offset + i];

		right_taint[i] =reg_shadow.bytes[right_rid][right_offset + i];
	}
	for (uint32_t i = 0; i < operand_bytes; i++) {
		reg_shadow.bytes[left_rid][left_offset + i] = right_taint[i];

		reg_shadow.bytes[right_rid][right_offset + i] = left_taint[i];
	}
	cs_free(decoded, decoded_count);

	return true;
}

static void dse_on_mem(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void *ud) {
	(void)vcpu; (void)ud;
	uint32_t sz = 1u << qemu_plugin_mem_size_shift(info);
	if (qemu_plugin_mem_is_store(info)) {
		if (g_cur_aux) {
			g_cur_aux->has_mem_write  = true;
			g_cur_aux->mem_write_addr = vaddr;
		}
		return;
	}
	//taint byte by byte
	uint8_t tmask = 0;
	for (uint32_t i = 0; i < sz && i < 8; i++) {
		if (shadow_is_tainted(g_shadow, vaddr + i)) tmask |= (1u << i);
	}
	//mem2reg propagate
	InsnMeta *meta = meta_lookup(g_current_ip);
	if (meta && meta->wr_reg >= 0) {
		bool overwrite = insn_overwrites_dst(meta->insn_id);
		propagate_mem2reg(&reg_shadow, meta->wr_reg, meta->wr_mask, tmask, overwrite);
	}
	if (g_cur_aux) {
		g_cur_aux->has_mem_read  = true;
		g_cur_aux->mem_read_addr = vaddr;
		GByteArray *arr = g_byte_array_new();
		uint64_t val = 0;
		if (qemu_plugin_read_memory_vaddr(vaddr, arr, sz)) {
			for (uint32_t i = 0; i < sz && i < arr->len && i < 8; i++) {
				val |= (uint64_t)arr->data[i] << (8 * i);
			}
		}
		g_byte_array_free(arr, TRUE);
		g_cur_aux->mem_read_val   = val;
		g_cur_aux->mem_read_taint = tmask;
	}
}

static bool is_valid_path(const char *s) {
    if (!s || !*s) return false;
    if (*s != '/') return false;
    
    size_t len = strlen(s);
    if (len < 2 || len > 256) return false;
    
    char c = s[1];
    if (!(isalpha((unsigned char)c) || c == '_' || c == '.')) return false;
    
    for (const char *p = s + 2; *p; p++) {
        unsigned char c = *p;
        if (c < 32 || c > 126) return false;
        if (c == '<' || c == '>' || c == '|' || c == '*' || 
            c == '?' || c == '"' || c == '\\' || c == ',' || 
            c == ';' || c == '$') return false;
    }
    return true;
}
//for exact lib dump
static void lib_update_mapping(uint32_t fd, uint64_t addr, uint64_t size) {
	if ((int)fd <= 0 || size == 0) return;
	gpointer val = g_hash_table_lookup(file_fd, (gpointer)(uintptr_t)fd);
	if (!val) return;
	file_dep_t *f = (file_dep_t*)val;
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		if (f->path && lm->path && strcmp(lm->path, f->path) == 0) {
			uint64_t end = addr + size;
			if (lm->base == 0 || addr < lm->base) lm->base = addr;
			if (end > lm->end) lm->end = end;
			return;
		}
	}
}

static void apply_pending_mmap(const pending_mmap_t *pending, uint64_t mapped_addr){
	if (!pending || !pending->active || pending->size == 0) {
		return;
	}
	if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
		fprintf(stderr,"[MMAP] invalid page size: 0x%lx\n",(unsigned long)page_size);
		return;
	}
	if ((pending->size - 1) > UINT64_MAX - mapped_addr) {
		fprintf(stderr,"[MMAP] range overflow: addr=0x%lx size=0x%lx\n", (unsigned long)mapped_addr, (unsigned long)pending->size);
		return;
	}
	const char *name = (pending->syscall_num == 192) ? "mmap2" : "mmap";

	fprintf(stderr, "[SYSCALL] %s requested=0x%lx mapped=0x%lx size=0x%lx prot=0x%x flags=0x%x fd=%d offset=0x%lx\n", name, (unsigned long)pending->requested_addr, (unsigned long)mapped_addr, (unsigned long)pending->size, pending->prot, pending->flags, pending->fd, (unsigned long)pending->offset);
	lib_update_mapping((uint32_t)pending->fd, mapped_addr, pending->size);

	if (!(pending->prot & 0x2) && !(pending->prot & 0x4)) return;

	uint64_t page_mask = (uint64_t)page_size - 1;
	uint64_t last_addr = mapped_addr + pending->size - 1;
	uint64_t page_start = mapped_addr & ~page_mask;
	uint64_t page_last = last_addr & ~page_mask;

	for (uint64_t addr = page_start;; addr += page_size) {
		gpointer key = (gpointer)(uintptr_t)addr;
		page_t *p = g_hash_table_lookup(pages, key);

		if (p) {
			p->prot = pending->prot;
		} else {
			p = g_new0(page_t, 1);
			p->prot = pending->prot;
			g_hash_table_insert(pages, key, p);
		}

		if ((pending->prot & 0x4) && g_hash_table_contains(unmapped_pages, key)) {
			p->dyn_exec = true;
			p->gen_written = g_unpack_gen;

			if (g_layer_has_cand) {
				g_layer_dirty = true;
			}
		}
		if (addr == page_last) {
			break;
		}
	}
}

static void apply_pending_mprotect(const pending_mmap_t *pending) {
	if (!pending || !pending->active || pending->size == 0) {
		return;
	}
	
	uint64_t addr = pending->requested_addr;
	uint64_t size = pending->size;
	int prot = pending->prot;
	uint64_t page_mask = (uint64_t)page_size - 1;
	uint64_t page_start = addr & ~page_mask;
	uint64_t page_end = (addr + size + page_size - 1) & ~page_mask;

	fprintf(stderr, "[SYSCALL] mprotect(0x%lx, 0x%lx, prot=0x%x)\n", (unsigned long)addr, (unsigned long)size, prot);

	for (uint64_t page_addr = page_start; page_addr < page_end; page_addr += page_size) {
		gpointer key = (gpointer)(uintptr_t)page_addr;
		page_t *p = g_hash_table_lookup(pages, key);

		if (p) {
			p->prot = prot;
		} else {
			p = g_new0(page_t, 1);
			p->prot = prot;
			g_hash_table_insert(pages, key, p);
		}
		if (p->written && (prot & 0x4)) {
			p->exec_after_write = true;
		}
		if ((prot & 0x4) && g_hash_table_contains(unmapped_pages, key)) {
			p->dyn_exec = true;
			p->gen_written = g_unpack_gen;

			if (g_layer_has_cand) {
				g_layer_dirty = true;
			}
		}
	}
}

static void apply_pending_munmap(const pending_mmap_t *pending) {
	if (!pending || !pending->active || pending->size == 0) {
		return;
	}

	uint64_t addr = pending->requested_addr;
	uint64_t size = pending->size;
	uint64_t page_mask = (uint64_t)page_size - 1;
	uint64_t page_start = addr & ~page_mask;
	uint64_t page_end = (addr + size + page_size - 1) & ~page_mask;

	for (uint64_t page_addr = page_start; page_addr < page_end; page_addr += page_size) {
		gpointer key = (gpointer)(uintptr_t)page_addr;
		g_hash_table_add(unmapped_pages, key);

		page_t *p = g_hash_table_lookup(pages, key);
		if (p) {
			g_hash_table_remove(pages, key);
			g_free(p->wbitmap);
			g_free(p);
		}
	}
	fprintf(stderr, "[SYSCALL] munmap(0x%lx, 0x%lx)\n", (unsigned long)addr, (unsigned long)size);
}

static file_dep_t *add_file_dep(const char *path, bool is_lib) {
	for (GList *l = file_deps; l; l = l->next) {
		file_dep_t *f = (file_dep_t*)l->data;
		if (f->path && strcmp(f->path, path) == 0) return f;
	}
	file_dep_t *f = g_new0(file_dep_t, 1);
	f->path = g_strdup(path);
	f->write = false;
	file_deps = g_list_append(file_deps, f);
	if (is_lib && !strstr(path, ".cache")) {
		for (GList *l = lib_deps; l; l = l->next) {
			lib_mapping_t *lm = (lib_mapping_t*)l->data;
			if (lm->path && strcmp(lm->path, path) == 0) return f;
		}
		lib_mapping_t *lm = g_new0(lib_mapping_t, 1);
		lm->path = g_strdup(path);
		lm->base = 0;
		lm->size = 0;
		lib_deps = g_list_append(lib_deps, lm);
	}
	return f;
}
//mark write
static void mark_written(uint64_t vaddr, uint32_t size) {
	while (size > 0) {
		uint64_t page_addr = vaddr & ~(page_size - 1);
		uint32_t offset = vaddr & (page_size - 1);
		uint32_t chunk = MIN(size, page_size - offset);
		page_t *page = g_hash_table_lookup(pages,(gpointer)(uintptr_t)page_addr);

		if (!page) {
			page = g_new0(page_t, 1);
			page->prot = 0x3;
			g_hash_table_insert(pages, (gpointer)(uintptr_t)page_addr, page);
		}

		if (!page->wbitmap) page->wbitmap = g_malloc0(page_size / 8);

		for (uint32_t i = 0; i < chunk; i++) {
			uint32_t bit = offset + i;
			page->wbitmap[bit >> 3] |= 1u << (bit & 7);
		}
		page->written = true;
		page->write_count++;
		page->last_write = g_icount;
		page->gen_written = g_unpack_gen;
		page->exec_seen = false;
		if (g_layer_has_cand) g_layer_dirty = true;
		vaddr += chunk;
		size -= chunk;
	}
}

static void on_mem_write(unsigned int vcpu_idx, qemu_plugin_meminfo_t info, uint64_t vaddr, void *userdata) {
	g_taint_seen = true;
	uint32_t size = 1u << qemu_plugin_mem_size_shift(info);
	for (uint32_t i = 0; i < size; i++) {
		shadow_taint_byte(g_shadow, vaddr + i, g_current_ip);
	}
	mark_written(vaddr, size);
}

static bool bin_dumped = false;
static GString *saved_reg = NULL;
static uint64_t saved_base = 0;
static bool saved_base_set = false;
static uint64_t saved_oep = 0;
static double g_oep_confidence = 0.0;
static GString *g_oep_scoring = NULL;
static bool image_captured = false;
static bool g_static_binary = false;

//enhanced logic of choosing oep
static bool addr_in_lib(uint64_t addr) {
	if (addr == 0) return false;
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		if (!lm->base) continue;
		uint64_t end;
		if (lm->end > lm->base) {
			end = lm->end;
		} else {
			end = (lm->base + lm->size);
		}
		if (end <= lm->base) continue;
		if (addr >= lm->base && addr < end) return true;
	}
	return false;
}

static bool cand_in_main_image(const oep_cand_t *c) {
	if (!c) return false;
	if (addr_in_lib(c->addr)) return false;          // target in libc/ld 
	return true;
}

//part of the concrete to total to determine the most accurate OEP
static double cand_dse_ratio(const oep_cand_t *c) {
	if (!c || c->dse_total == 0) return 1.0;
	uint32_t failed = c->dse_concretized;
	if (failed > c->dse_total) {
		failed = c->dse_total;
	}
	return (double)failed / (double)c->dse_total;
}
//check overall measurements
static double cand_dse_strength(const oep_cand_t *c)
{
	if (!c || !c->dse_confirmed || c->dse_total == 0) return 0.0;
	//lifting coverage
	double quality = 1.0 - cand_dse_ratio(c);
	uint32_t depth_total =c->dse_total;

	if (depth_total > MAX_SLICE) {
		depth_total = MAX_SLICE;
	}
	//depth check
	double depth = log1p((double)depth_total) / log1p((double)MAX_SLICE);

	return quality * depth;
}
//comparison of measurements
static bool cand_stronger(const oep_cand_t *a, const oep_cand_t *b) {
	double strength_a = cand_dse_strength(a);
	double strength_b = cand_dse_strength(b);
	if (strength_a != strength_b) {
		return strength_a > strength_b;
	}
	if (a->dse_confirmed && b->dse_confirmed) {
		if (a->dse_total != b->dse_total) {
			return a->dse_total > b->dse_total;
		}
		double ratio_a = cand_dse_ratio(a);
		double ratio_b = cand_dse_ratio(b);
		if (ratio_a != ratio_b) {
			return ratio_a < ratio_b;
		}
	}

	if (a->jump_from_unmapped != b->jump_from_unmapped) {
		return a->jump_from_unmapped;
	}
	if (a->has_prologue != b->has_prologue) {
		return a->has_prologue;
	}
	if (a->icount != b->icount) {
		return a->icount < b->icount;
	}
	return a->addr < b->addr;
}
//read first bytes at candidate addr and checks prologue: push ebp; mov ebp,esp or endbr32
static bool cand_has_prologue(uint64_t addr) {
	uint8_t p[4];
	if (!guest_read_bytes(addr, p, 4)) return false;
	if (p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xe5) return true;              //push ebp;mov ebp,esp
	if (p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfb) return true; //endbr32
	return false;
}
//trying to determine jump from basic code or stub
static bool jump_site_is_unpacker(uint64_t jump_site) {
	if (jump_site == 0) return false; //don't know source
	uint64_t pg = jump_site & ~(page_size - 1);
	page_t *jp = g_hash_table_lookup(pages, (gpointer)(uintptr_t)pg);
	if (!jp) return true; //stub munmapped, high chanse of attempt to hide stub
	if (jp->dyn_exec && !addr_in_lib(jump_site)) return true;//alloc on address of previously used page
	if (jp->written && jp->exec_after_write) return true; //write then execute
	return false; //ordinary page
}

//OEP scroing counting
static double cand_score(const oep_cand_t *c) {
	if (!c) return 0.0;
	double s_dse = cand_dse_strength(c);
	double s_prologue = c->has_prologue ? 1.0: 0.0;
	double s_unmap = c->jump_from_unmapped ? 1.0 : 0.0;
	return W_DSE * s_dse + W_UNMAP * s_unmap + W_PROL * s_prologue;
}
//tiebreak, SCORE_EPS difference
static bool cand_score_better(const oep_cand_t *a,const oep_cand_t *b) {
	double score_a =cand_score(a);
	double score_b =cand_score(b);
	if (score_a - score_b > SCORE_EPS) return true;
	if (score_b - score_a > SCORE_EPS) return false;
	return cand_stronger(a, b);
}
//confidence in [0,1]
static double cand_confidence(const oep_cand_t *c){
	if (W_ACTIVE <= 0.0) return 0.0;

	return cand_score(c) /W_ACTIVE;
}

static bool cand_rank_better(
	const oep_cand_t *a,
	const oep_cand_t *b)
{
	if (!a) return false;
	if (!b) return true;
	bool a_in_main = cand_in_main_image(a);
	bool b_in_main = cand_in_main_image(b);
	if (a_in_main != b_in_main) {
		return a_in_main;
	}

	return cand_score_better(a,b);
}

//union of oep choosing
static oep_cand_t *choose_oep_cand(void) {
	oep_cand_t *best = NULL;
	for (GList *l = oep_cands; l; l = l->next) {
		oep_cand_t *c = (oep_cand_t*)l->data;
		if (!best || cand_rank_better(c, best)) {
			best = c;
		}
	}
	return best;
}

//auxv PT_LOAD union, main logic
static bool window_from_phdrs(uint64_t phdr_va, uint64_t ent, uint64_t num,uint64_t base_adjust) {
	if (!phdr_va || !num || ent < 8) return false;
	bool w64 = (guest_ptr_bytes() == 8);
	uint64_t off_vaddr = w64 ? 16 : 8;
	uint64_t off_memsz = w64 ? 40 : 20;
	uint32_t fld = w64 ? 8 : 4;
	uint64_t lo = UINT64_MAX, hi = 0;
	for (uint64_t i = 0; i < num && i < 512; i++) {
		uint64_t ph = phdr_va + i * ent;
		uint64_t p_type = 0, p_vaddr = 0, p_memsz = 0;
		if (!guest_read_uint(ph, 4, &p_type)) break;
		if (p_type != 1) continue;
		if (!guest_read_uint(ph + off_vaddr, fld, &p_vaddr)) break;
		if (!guest_read_uint(ph + off_memsz, fld, &p_memsz)) break;
		uint64_t start = p_vaddr + base_adjust;
		if (start < lo) lo = start;
		if (start + p_memsz > hi) hi = start + p_memsz;
	}
	if (hi > lo) {
		g_main_lo = lo;
		g_main_hi = hi;
		g_main_known = true;
		return true;
	}
	return false;
}
//read auxv
static void read_auxv_from_stack(void) {
	uint32_t pb = guest_ptr_bytes();
	uint64_t sp = 0;
	if (!dse_read_reg(REG_RSP, &sp)) { fprintf(stderr, "[AUXV] fail: cannot read REG_RSP\n"); return; }
	if (pb == 4) sp &= 0xFFFFFFFFULL;

	uint64_t argc = 0;
	if (!guest_read_uint(sp, pb, &argc)) { fprintf(stderr, "[AUXV] fail: cannot read argc at sp=0x%lx\n", (unsigned long)sp); return; }
	uint64_t p = sp + pb;
	p += argc * pb;
	p += pb;
	for (int guard = 0; guard < 8192; guard++) {
		uint64_t e = 0;
		if (!guest_read_uint(p, pb, &e)) return;
		p += pb;
		if (e == 0) break;
	}

	uint64_t at_phdr = 0, at_phent = 0, at_phnum = 0, ptphdr_vaddr = 0;
	bool have_ptphdr = false;
	uint64_t scan = p;
	for (int guard = 0; guard < 128; guard++) {
		uint64_t type = 0, val = 0;
		if (!guest_read_uint(scan, pb, &type)) { fprintf(stderr, "[AUXV] fail: auxv type read at 0x%lx\n", (unsigned long)scan); return; }
		if (!guest_read_uint(scan + pb, pb, &val)) { fprintf(stderr, "[AUXV] fail: auxv val read at 0x%lx\n", (unsigned long)(scan+pb)); return; }
		scan += 2 * pb;
		if (type == AT_NULL) break;
		switch (type) {
			case AT_PHDR:  at_phdr  = val; break;
			case AT_PHENT: at_phent = val; break;
			case AT_PHNUM: at_phnum = val; break;
			case AT_BASE:  g_ld_base = val; break;
			case AT_ENTRY: g_stub_entry = val; break;
			case AT_PAGESZ:
				if (val && (size_t)val != page_size)
					fprintf(stderr, "[AUXV] AT_PAGESZ=0x%lx differs from page_size=0x%lx\n", (unsigned long)val, (unsigned long)page_size);
				if (val) page_size = (size_t)val;
				break;
		}
	}

	if (!at_phdr || !at_phnum || at_phent <8) { fprintf(stderr, "[AUXV] fail: no AT_PHDR (phdr=0x%lx phnum=%lu phent=%lu)\n", (unsigned long)at_phdr, (unsigned long)at_phnum, (unsigned long)at_phent); return; }

	bool w64 = (guest_ptr_bytes() == 8);
	uint64_t off_vaddr = w64 ? 16 : 8;
	uint32_t fld = w64 ? 8 : 4;
	uint64_t min_load_vaddr = UINT64_MAX;
	for (uint64_t i = 0; i < at_phnum && i < 512; i++) {
		uint64_t ph = at_phdr + i * at_phent;
		uint64_t p_type = 0, p_vaddr = 0;
		if (!guest_read_uint(ph, 4, &p_type)) break;
		if (p_type == 6) { //PT_PHDR
			if (guest_read_uint(ph + off_vaddr, fld, &p_vaddr) && p_vaddr <= at_phdr) {
				ptphdr_vaddr = p_vaddr;
				have_ptphdr = true;
			}
		} else if (p_type == 1) { //PT_LOAD
			if (guest_read_uint(ph + off_vaddr, fld, &p_vaddr) && p_vaddr < min_load_vaddr) {
				min_load_vaddr = p_vaddr;
			}
		}
	}
	uint64_t bias;
	if (have_ptphdr) {
		//bias = runtime phdr address - PT_PHDR.p_vaddr
		bias = at_phdr - ptphdr_vaddr;
	} else if (min_load_vaddr != UINT64_MAX) {
		//fallback for stubs without PT_PHDR
		uint64_t pmask = ~((uint64_t)page_size - 1);
		bias = (at_phdr & pmask) - (min_load_vaddr & pmask);
	} else {
		bias = 0;
	}
	if (window_from_phdrs(at_phdr, at_phent, at_phnum, bias)) {
		fprintf(stderr, "[WINDOW] auxv: main [0x%lx,0x%lx) ld_base=0x%lx entry=0x%lx bias=0x%lx\n", (unsigned long)g_main_lo, (unsigned long)g_main_hi, (unsigned long)g_ld_base, (unsigned long)g_stub_entry,(unsigned long)bias);
	}
}
//bases form ELF phdrs, fallback if no auxv read
static bool window_from_elf_header(uint64_t base) {
	if (!base) return false;
	uint8_t ident[16];
	if (!guest_read_bytes(base, ident, 16)) return false;
	if (!(ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F')) return false;
	bool w64 = (ident[4] == 2);
	uint64_t e_type = 0, e_phoff = 0, e_phnum = 0, e_phentsize = 0;
	uint64_t off_type = 16;
	uint64_t off_phoff = w64 ? 32 : 28;
	uint64_t off_phent = w64 ? 54 : 42;
	uint64_t off_phnum = w64 ? 56 : 44;
	if (!guest_read_uint(base + off_type,  2, &e_type)) return false;
	if (!guest_read_uint(base + off_phoff, w64 ? 8 : 4, &e_phoff)) return false;
	if (!guest_read_uint(base + off_phent, 2, &e_phentsize)) return false;
	if (!guest_read_uint(base + off_phnum, 2, &e_phnum)) return false;
	uint64_t bias = (e_type==3) ? base : 0;
	bool ok = window_from_phdrs(base + e_phoff, e_phentsize, e_phnum, bias);
	if (ok)
		fprintf(stderr, "[WINDOW] elf-header@0x%lx: main [0x%lx,0x%lx)\n", (unsigned long)base, (unsigned long)g_main_lo, (unsigned long)g_main_hi);
	return ok;
}
//get boundaries from contiguity, fallback if not both previous
static void window_from_pagetable(GList *keys) {
	const uint64_t GAP_MAX = 64 * page_size;
	uint64_t lo = 0, hi = 0;
	bool have = false;
	for (GList *k = keys; k; k = k->next) {
		uint64_t addr = (uint64_t)(uintptr_t)k->data;
		if (addr_in_lib(addr) || addr == 0) continue;
		if (!have) {
			lo = addr;
			hi = addr + page_size;
			have = true;
			continue;
		}
		if (addr <= hi + GAP_MAX) hi = addr + page_size;
		else break;
	}
	if (have) {
		g_main_lo = lo; g_main_hi = hi; g_main_known = true;
		fprintf(stderr, "[WINDOW] page-table heuristic: main [0x%lx,0x%lx)\n", (unsigned long)g_main_lo, (unsigned long)g_main_hi);
	}
}
//helper for determine which prefer
static void establish_main_window_fallback(GList *keys) {
	if (g_main_known) return;
	uint64_t base = 0;
	for (GList *k = keys; k; k = k->next) {
		uint64_t addr = (uint64_t)(uintptr_t)k->data;
		if (!addr_in_lib(addr)) {
			base = addr;
			break;
		}
	}
	if (window_from_elf_header(base)) return;
	window_from_pagetable(keys);
}
//is page in boundaries
static bool page_is_program(uint64_t addr, const page_t *p) {
	if (addr_in_lib(addr)) return false;
	if (!g_main_known) return true;
	if (addr >= g_main_lo && addr < g_main_hi) return true;
	if (p && (p->exec_seen || p->exec_after_write || p->dyn_exec)) return true;
	return false;
}


static void do_dump(uint64_t oep) {
	GList *keys = g_hash_table_get_keys(pages);
	keys = g_list_sort(keys, compare_keys);

	establish_main_window_fallback(keys);

	g_static_binary = (lib_deps == NULL);

	if (!bin_dumped) {
		FILE *f_bin = fopen("unpacked.bin", "wb");
		if (f_bin) {
			for (GList *k = keys; k; k = k->next) {
				uint64_t addr = (uint64_t)(uintptr_t)k->data;
				page_t *p = g_hash_table_lookup(pages, k->data);
				if (!p) continue;
				if (!page_is_program(addr, p))continue;
				GByteArray *data = g_byte_array_new();
				if (qemu_plugin_read_memory_vaddr(addr, data, page_size) && data->len > 0) {
					fwrite(data->data, 1, data->len, f_bin);
				}
				g_byte_array_free(data, TRUE);
			}
			fclose(f_bin);
			bin_dumped = true;
		}
	}
	
	if (!saved_reg) {
		saved_reg= g_string_new(NULL);
		g_string_append(saved_reg, "  \"regions\": [\n");
		bool in_region = false;
		bool first_region = true;
		uint64_t main_off = 0;
		uint64_t region_start = 0;
		uint64_t region_size = 0;
		int region_prot = 0;
		const char *region_mod = NULL;
		bool region_is_lib = false;
		uint64_t region_off = 0;
		char modbuf[512];

		for (GList *k = keys; k; k = k->next) {
			uint64_t addr = (uint64_t)(uintptr_t)k->data;
			page_t *p = g_hash_table_lookup(pages, k->data);
			if (!p) continue;
			if (!addr_in_lib(addr) && !page_is_program(addr,p)) continue;

			GByteArray *data = g_byte_array_new();
			size_t written = 0;
			bool ok = qemu_plugin_read_memory_vaddr(addr, data, page_size);
			if (ok && data->len > 0) {
				written = data->len;
			} else {
				written = 0;
			}
			g_byte_array_free(data, TRUE);
			if (written == 0) continue;

			const char *mod = addr_lib_path(addr);
			bool is_lib = (mod != NULL);
			if (in_region && addr == region_start + region_size && p->prot == region_prot && mod == region_mod) {
				region_size += written;
			} else {
				if (in_region) {
					if (!first_region) g_string_append(saved_reg, ",\n");
					first_region = false;
					if (region_mod) {
						snprintf(modbuf, sizeof modbuf, "\"%s\"", base_name(region_mod));
					} else if (g_static_binary) {
					       snprintf(modbuf, sizeof modbuf, "\"static\"");
					}else if (g_main_known && region_start >= g_main_lo && region_start < g_main_hi){
						snprintf(modbuf, sizeof modbuf, "\"main\"");
    					} else {
						snprintf(modbuf, sizeof modbuf, "null");
					}
					g_string_append_printf(saved_reg, "    {\"addr\": \"0x%lx\", \"size\": %lu, \"prot\": %d, \"offset\": %lu, \"lib\": %s, \"module\": %s}", region_start, region_size, region_prot, region_off, region_is_lib ? "true" : "false", modbuf);
				}
				region_start = addr;
				region_size = written;
				region_prot = p->prot;
				region_mod = mod;
				region_is_lib = is_lib;
				region_off = main_off;
				if (!is_lib && !saved_base_set) {
					saved_base = region_start;
					saved_base_set = true;
				}
				in_region = true;
			}
			if (!is_lib) {
				main_off += written;
			}
		}
		if (in_region) {
			if (!first_region) g_string_append(saved_reg, ",\n");
			if (region_mod){
				snprintf(modbuf, sizeof modbuf, "\"%s\"", base_name(region_mod));
			}else if (g_static_binary) {
				snprintf(modbuf, sizeof modbuf, "\"static\"");
			} else if (g_main_known && region_start >= g_main_lo && region_start < g_main_hi) {
				snprintf(modbuf, sizeof modbuf, "\"main\"");
			}else {
				snprintf(modbuf, sizeof modbuf, "null");
			}
			g_string_append_printf(saved_reg, "    {\"addr\": \"0x%lx\", \"size\": %lu, \"prot\": %d, \"offset\": %lu, \"lib\": %s, \"module\": %s}\n", region_start, region_size, region_prot, region_off, region_is_lib ? "true" : "false", modbuf);
		}
		g_string_append(saved_reg, "  ],\n");
	}
	g_list_free(keys);
	image_captured = true;
	fprintf(stderr, "[DUMP] unpacked.bin captured (oep=0x%lx)\n", (unsigned long)oep);
}

static void write_report(void) {
	if (!image_captured) do_dump(saved_oep);

	FILE *f_json = fopen("unpacked.json", "w");
	if (!f_json) return;

	fprintf(f_json, "{\n");
	fprintf(f_json, "  \"oep\": \"0x%lx\",\n", saved_oep);
	fprintf(f_json, "  \"arch\": \"x86\",\n");
	fprintf(f_json, "  \"oep_confidence\": %.4f,\n", g_oep_confidence);
	if (g_oep_scoring) fprintf(f_json, "%s", g_oep_scoring->str);
	fprintf(f_json, "  \"base\": \"0x%lx\",\n", saved_base);
	fprintf(f_json, "%s", saved_reg ? saved_reg->str : "  \"regions\": [],\n");

	// files
	fprintf(f_json, "  \"file_dependencies\": [");
	bool first = true;
	for (GList *l = file_deps; l; l = l->next) {
		file_dep_t *f = (file_dep_t*)l->data;
		if (!f->path) continue;
		if (!first) fprintf(f_json, ",\n");
		fprintf(f_json, "    {\"path\": \"%s\", \"write\": %s}", f->path, f->write ? "true" : "false");
		first = false;
	}
	fprintf(f_json, "],\n");

	// libraries
	fprintf(f_json, "  \"library_dependencies\": [");
	first = true;
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		if (!lm->path || !*lm->path || *lm->path != '/' || !is_valid_path(lm->path)) continue;
		uint64_t span;
		if (lm->end > lm->base) {
			span = (lm->end - lm->base);
		} else {
			span = lm->size;
		}
		if (!first) fprintf(f_json, ", ");
		fprintf(f_json, "{\"path\": \"%s\", \"base\": \"0x%lx\", \"size\": %lu}", lm->path, lm->base, span);
		first = false;
	}
	fprintf(f_json, "],\n");

	//got reconstruct
	fprintf(f_json, "  \"resolved_imports\": [");
	first = true;
	for (GList *l = resolved_imports; l; l = l->next) {
		resolved_import_t *ri = (resolved_import_t*)l->data;
		if (!ri || !ri->module) continue;
		if (g_main_known && (ri->got_slot < g_main_lo || ri->got_slot>=g_main_hi)) continue;
		if (!first) fprintf(f_json, ", ");
		fprintf(f_json, "{\"got_slot\": \"0x%lx\", \"resolved_addr\": \"0x%lx\", \"module\": \"%s\", \"offset\": \"0x%lx\"}",(unsigned long)ri->got_slot, (unsigned long)ri->resolved_addr,ri->module, (unsigned long)( ri->resolved_addr - ri->lib_base));
		first = false;
	}
	fprintf(f_json, "],\n");

	// network
	fprintf(f_json, "  \"network_dependencies\": [\n");
	bool net_first = true;
	for (GList *l = net_deps; l; l = l->next) {
		net_dep_t *n = (net_dep_t*)l->data;
		if (!n) continue;
		if (!net_first) fprintf(f_json, ",\n");
		net_first = false;
		const char *type_str = (n->type == SOCK_STREAM) ? "tcp" :
				       (n->type == SOCK_DGRAM)  ? "udp" :
				       (n->type == SOCK_RAW)    ? "raw" : "unknown";
		const char *domain_str = (n->domain == AF_INET)  ? "AF_INET" :
					 (n->domain == AF_INET6) ? "AF_INET6" : "unknown";
		if (strcmp(n->op, "socket") == 0) {
			fprintf(f_json, "    {\"op\":\"socket\",\"fd\":%d,\"domain\":\"%s\",\"type\":\"%s\"}", n->fd, domain_str, type_str);
		} else if (strcmp(n->op, "bind") == 0 || strcmp(n->op, "connect") == 0) {
			fprintf(f_json, "    {\"op\":\"%s\",\"fd\":%d,\"ip\":\"%s\",\"port\":%d,\"type\":\"%s\"}", n->op, n->fd, n->ip, n->port, type_str);
		} else if (strcmp(n->op, "accept") == 0 && n->ip[0]) {
			fprintf(f_json, "    {\"op\":\"accept\",\"fd\":%d,\"peer_ip\":\"%s\",\"peer_port\":%d}", n->fd, n->ip, n->port);
		} else {
			fprintf(f_json, "    {\"op\":\"%s\",\"fd\":%d}", n->op, n->fd);
		}
	}
	fprintf(f_json, "\n  ]\n}\n");

	fclose(f_json);
	fprintf(stderr, "[DUMP] unpacked.json complete\n");
}

//collect top-3 candidates by weighted score
static void build_oep_scoring(oep_cand_t *chosen) {
	g_oep_confidence = chosen ? cand_confidence(chosen): 0.0;
	guint count = g_list_length(oep_cands);
	oep_cand_t **candidates = g_new0( oep_cand_t *, count ? count : 1);
	guint actual_count = 0;

	for (GList *l = oep_cands;l;l = l->next) {
		candidates[actual_count++] = (oep_cand_t *)l->data;
	}
	guint top_count = actual_count < 3 ? actual_count : 3;
	for (guint i = 0; i < top_count; i++) {
		guint best_index = i;
		for (guint j = i + 1; j < actual_count;j++) {
			if (cand_rank_better(candidates[j],candidates[best_index])) {
				best_index = j;
			}
		}
		oep_cand_t *temporary = candidates[i];
		candidates[i] =candidates[best_index];
		candidates[best_index] = temporary;
	}

	if (g_oep_scoring) {
		g_string_free(g_oep_scoring, TRUE);
	}
	g_oep_scoring = g_string_new(NULL);
	g_string_append(g_oep_scoring, "  \"oep_candidates\": [\n");

	for (guint i = 0;i < top_count; i++) {
		oep_cand_t *candidate = candidates[i];
		g_string_append_printf(g_oep_scoring,"    {\"addr\": \"0x%lx\", \"score\": %.4f, \"confidence\": %.4f, \"dse_confirmed\": %s, \"concretized\": %u, \"total\": %u, \"generation\": %u}%s\n",(unsigned long) candidate->addr, cand_score(candidate), cand_confidence(candidate), candidate->dse_confirmed ? "true" : "false", candidate->dse_concretized, candidate->dse_total, candidate->generation, (i + 1) < top_count ? "," : "");
	}

	g_string_append(g_oep_scoring,"  ],\n");
	g_free(candidates);
}

static oep_cand_t *find_oep_cand(uint64_t addr) {
	for (GList *l = oep_cands; l; l = l->next) {
		oep_cand_t *candidate = (oep_cand_t *)l->data;
		if (candidate->addr == addr) return candidate;
	}
	return NULL;
}

static void plugin_exit(qemu_plugin_id_t id, void *udata) {
	//oep choose
	oep_cand_t *chosen = NULL;
	if (oep_found) {
		chosen = find_oep_cand(oep_addr);
	}

	if (!oep_found && oep_cands) {
		chosen = choose_oep_cand();
		if (chosen) {
			oep_addr = chosen->addr;
			oep_found = true;
		}
	}
	if (oep_cands) {
		build_oep_scoring(chosen);
	}

	
	//write json-report
	saved_oep = oep_addr;
	write_report();
	//memory free
	for (GList *l = file_deps; l; l = l->next) {
		file_dep_t *f = (file_dep_t*)l->data;
		g_free(f->path);
		g_free(f);
	}
	g_list_free(file_deps);
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		g_free(lm->path);
		g_free(lm);
	}
	g_list_free(lib_deps);
	for (GList *l = net_deps; l; l = l->next) {
		net_dep_t *n = (net_dep_t*)l->data;
		g_free(n->payload_hex);
		g_free(n);
	}
	g_list_free(net_deps);
	g_hash_table_destroy(file_fd);
	
	if (unmapped_pages) {
		g_hash_table_destroy(unmapped_pages);
		unmapped_pages = NULL;
	}

	if (g_sockets) {
		GHashTableIter iter;
		gpointer key, value;
		g_hash_table_iter_init(&iter, g_sockets);
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			net_dep_t *n = value;
			g_free(n->payload_hex);
			g_free(n);
		}
	}
	g_hash_table_destroy(g_sockets);
	
	//fd
	g_free(pending_open_path);

	//capstone handle
	cs_close(&cs_handle);
	meta_free();

	//tracer
	trace_buffer_destroy(g_trace);
	g_trace = NULL;
	
	//oeps
	if (saved_reg) {
		g_string_free(saved_reg, TRUE);
		saved_reg = NULL;
	}
	g_list_free_full(oep_cands, g_free);
	oep_cands = NULL;
	//got
	g_list_free_full(resolved_imports, g_free);
	resolved_imports = NULL;
	if (resolved_imports_by_slot) {
		g_hash_table_destroy(resolved_imports_by_slot);
		resolved_imports_by_slot = NULL;
	}
}

static int mask_first_reg(uint32_t mask) {
	for (int i = 0; i < REG_COUNT; i++) {
		if (mask & (1U << i)) return i;
	}
	return -1;
}

static bool insn_is_unpacked(uint64_t vaddr, size_t size) {
	for (size_t i = 0; i < size; i++) {
		uint64_t addr = vaddr + i;
		uint64_t page_addr = addr & ~(page_size - 1);
		page_t *page = g_hash_table_lookup(pages,(gpointer)(uintptr_t)page_addr);

		if (!page || !(page->prot & 0x4)) continue;

		if (page->dyn_exec) return true;

		if (page->wbitmap) {
			unsigned offset = addr & (page_size - 1);
			if (page->wbitmap[offset >> 3] & (1u << (offset & 7))) return true;
		}
	}
	return false;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
	uint64_t vaddr = (uint64_t)(uintptr_t) udata;
	g_current_ip = vaddr;
	g_icount++;

	if (!g_auxv_done) { 
		if (!g_regs_ready) dse_init_reg_handles();
		g_auxv_done = true;
		read_auxv_from_stack();
	}

	InsnMeta *meta = meta_lookup(vaddr);
	if (!meta) {
		prev_jump_pending = false;
		prev_jump_site = 0;
		prev_target_reg =REG_INVALID;
		prev_mem_taddr = 0;
		prev_mem_target_value = 0;
		prev_mem_target_valid = false;
		return;
}

	//tracer
	if (g_trace) {
		TraceEntry ent = {0};
		ent.pc = vaddr;
		ent.size = meta->size;
		uint8_t need;
		if (meta->size > 15) {
			need = 15;
		} else {
			need = meta->size;
		}
		GByteArray *ib = g_byte_array_new();
		if (qemu_plugin_read_memory_vaddr(vaddr, ib, need)) {
			memcpy(ent.instr_bytes, ib->data, ib->len > 15 ? 15 : ib->len);
		}
		g_byte_array_free(ib, TRUE);
		if (g_aux && g_taint_seen) {
			if (!g_regs_ready) dse_init_reg_handles();
			InsnAux aux;
			memset(&aux, 0, sizeof(aux));
			aux.valid = true;
			aux.pc = vaddr;
			for (int r = 0; r < REG_COUNT; r++) {
				uint64_t rv = 0;
				dse_read_reg(r, &rv);
				aux.reg_vals[r] = rv;
				uint8_t m = 0;
				for (int b = 0; b < 4; b++) {
					if (reg_shadow.bytes[r][b]) m |= (1u << b);
				}
				aux.reg_taint[r] = m;
			}
			uint32_t idx = g_trace->head_pointer & (g_aux->capacity - 1);
			dse_aux_record(g_aux, g_trace, &aux);
			g_cur_aux = &g_aux->entries[idx];
		} else {
			g_cur_aux = NULL;
		}
		trace_append(g_trace, &ent);
	}
	//detect mov to upacked code
	bool now_unpacked = insn_is_unpacked(vaddr, meta->size);
	page_t *cur_pg = NULL;
	if (now_unpacked) {
		uint64_t page_addr = vaddr & ~(page_size - 1);
		cur_pg = g_hash_table_lookup(pages,(gpointer)(uintptr_t)page_addr);
	}
	
	bool prev_jump_matches = prev_jump_pending;
	if (prev_jump_matches && prev_mem_target_valid) {
		prev_jump_matches = ((uint32_t)vaddr == (uint32_t)prev_mem_target_value);
	}

	bool new_layer = now_unpacked && !oep_found && cur_pg && !cur_pg->exec_seen &&prev_jump_matches;
	if (cur_pg) cur_pg->exec_seen = true;

	if (new_layer) {
		oep_cand_t *c = g_new0(oep_cand_t, 1);
		c->addr = vaddr;
		c->has_prologue =cand_has_prologue(vaddr);
		if (prev_jump_matches) {
			c->jump_site = prev_jump_site;
		} else {
			c->jump_site= 0;
		}
		c->jump_from_unmapped = jump_site_is_unpacker(c->jump_site);
		if (g_layer_dirty) {
			g_layer++;
			g_layer_dirty = false;
			g_layer_has_cand = false;
		}
		c->generation = g_layer;
		c->icount = g_icount;
		//dse confirming
		if (prev_jump_matches) {
			if (prev_target_reg >= 0) {
				c->dse_confirmed = dse_verify_oep_candidate(g_trace, prev_jump_site, prev_target_reg, vaddr,g_shadow, cs_handle);
			} else if (prev_mem_target_valid) {
				c->dse_confirmed = dse_verify_oep_candidate_mem(g_trace, g_aux, prev_jump_site, prev_mem_taddr, vaddr, g_shadow, cs_handle);
			}
		}
		c->dse_concretized = dse_lift_concretized_count();
		c->dse_total =dse_lift_total_count();
		fprintf(stderr,"[OEP-CAND gen=%u] 0x%lx (jmp@0x%lx) dse=%s ""(concretized %u/%u; aux_miss %u, unsup %u)\n", c->generation, (unsigned long)c->addr, (unsigned long)c->jump_site, c->dse_confirmed ? "CONFIRMED" : "unconfirmed", dse_lift_concretized_count(), dse_lift_total_count(), dse_lift_aux_miss_count(), dse_lift_unsupported_count());
		//proceed to next layer
		oep_cands = g_list_append(oep_cands, c);
		g_layer_has_cand = true;
		g_last_cand_icount = g_icount;
	}
	prev_jump_pending = false;
	prev_jump_site = 0;
	prev_target_reg = REG_INVALID;
	prev_mem_taddr = 0;
	prev_mem_target_value = 0;
	prev_mem_target_valid = false;
	//if we are too long in unpacked code without proceeding further - we end cycle
	if (now_unpacked && !oep_found && g_last_cand_icount && (g_icount - g_last_cand_icount) > 200000) {
		oep_cand_t *chosen = choose_oep_cand();
		if (chosen) {
			oep_addr  = chosen->addr;
			oep_found = true;
			fprintf(stderr, "[OEP-FINAL gen=%u] 0x%lx\n", chosen->generation, (unsigned long)chosen->addr);
			do_dump(oep_addr);
		}
	}
	//taint propagation
	//xchg
	if (meta->insn_id == X86_INS_XCHG) {
		if (meta->has_mem_read || meta->has_mem_write) {
			goto record_branch;
		}

		if (!taint_xchg_reg_reg(vaddr, meta)) {
			uint32_t affected = meta->regs_read_mask | meta->regs_written_mask;
			for (int rid = 0; rid < REG_COUNT; rid++) {
				if (!(affected & (1U << rid))) {
					continue;
				}

				for (int byte = 0; byte < 4; byte++) {
					reg_shadow.bytes[rid][byte] = 1;
				}
			}
		}

	goto record_branch;
	}
	//xor or sub with itself, like sub al, al or xor al, al. have to lead to taint clean
	if ((meta->insn_id == X86_INS_XOR || meta->insn_id == X86_INS_SUB) && meta->regs_read_mask == meta->regs_written_mask && meta->regs_read_mask != 0) {
		int reg = mask_first_reg(meta->regs_written_mask);
		if (reg >= 0) reg_propagate_clear(&reg_shadow, reg);
		goto record_branch;
	}
	//if const have been changed we will see at mem_taint
	if (meta->regs_read_mask == 0 && meta->regs_written_mask != 0 && !meta->has_mem_read && !meta->has_mem_write) {
		int dst = mask_first_reg(meta->regs_written_mask);
		if (dst >= 0) reg_propagate_clear(&reg_shadow, dst);
		goto record_branch;
	}
	// lea with two registers
	if (meta->insn_id == X86_INS_LEA) {
		int dst = meta->wr_reg;
		int src1 = -1, src2 = -1;
		for (int i = 0; i < REG_COUNT; i++) {
			if (meta->mem_addr_reg_mask & (1U << i)) {
				if (src1 < 0){ 
					src1 = i;
				}else { 
					src2 = i;
					break;
				}
			}
		}
		if (dst >= 0 && src1 >= 0) {
			propagate_reg2reg_arith(&reg_shadow, dst, src1, src2, meta->insn_id);
		} else if (dst >= 0) {
			reg_propagate_clear(&reg_shadow, dst);   // lea eax,[const]
		}
		goto record_branch;
	}
	int num_src_regs = __builtin_popcount(meta->regs_read_mask);
	if (!meta->has_mem_read) {
		if (num_src_regs == 1 && meta->wr_reg >= 0 && meta->rd_reg >= 0) {
			propagate_reg2reg(&reg_shadow, meta->wr_reg, meta->wr_off, meta->wr_mask, meta->rd_reg, meta->rd_off,meta->rd_mask, meta->insn_id);
		} else if (num_src_regs >= 2 && meta->regs_written_mask) { //reg2reg with arith
			int dst = mask_first_reg(meta->regs_written_mask);
			int src1 = -1, src2 = -1;
			for (int i = 0; i < REG_COUNT; i++) {
				if (meta->regs_read_mask & (1U << i)) {
					if (src1 < 0) {
				       		src1 = i;
					} else { 
						src2 = i; 
						break;
					}
				}
			}
			if (src1 >= 0 && dst >= 0) {
				propagate_reg2reg_arith(&reg_shadow, dst, src1, src2, meta->insn_id);
			}
		}
	}
	record_branch:
		if (meta->is_indirect_branch && !oep_found) { //indirect check
			bool target_tainted = false;
			uint64_t taddr = 0;
			uint64_t tval = 0;
			bool mem_target_valid = false;
			if (meta->branch_target_reg >= 0 && meta->branch_target_reg < REG_COUNT) { //on reg
				target_tainted = reg_is_tainted(&reg_shadow, meta->branch_target_reg, 0x0F);
			} else if (meta->branch_target_reg == REG_INVALID) { // on mem with reg, like [eax]
				if (dse_resolve_mem_target(vaddr,meta,&taddr,&tval)) {
					for (uint32_t i = 0; i < 4; i++) {
						if (shadow_is_tainted(g_shadow, taddr + i)) {
							target_tainted = true;
							break;
						}
					}
					mem_target_valid = target_tainted;
				}
			}
			if (target_tainted) {
				prev_jump_site = vaddr;
				prev_jump_pending = true;
				prev_target_reg = meta->branch_target_reg;
				//valid target or not
				if (mem_target_valid) {
					prev_mem_taddr = taddr;
					prev_mem_target_value = (uint64_t)(uint32_t)tval;
					prev_mem_target_valid = true;
				} else {
					prev_mem_taddr = 0;
					prev_mem_target_value = 0;
					prev_mem_target_valid = false;
				}
			}
		}
		//got
		if (meta->is_indirect_branch && meta->branch_target_reg == REG_INVALID &&meta->insn_id != X86_INS_RET && lib_deps) {
			uint64_t slot = 0, val = 0;
			if (dse_resolve_mem_target(vaddr, meta, &slot, &val)) record_resolved_import(slot, val);
		}
}

//for network
static int pending_socketcall_subcall = -1;
static int pending_socket_domain = -1;
static int pending_socket_type = -1;

//for dup fd check
static int pending_dup_fd = -1;

static void vpcu_syscall(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8) {
	//x86
	if (num == 5) {  //open
		char *path = read_guest_string(a1);
		if (path && *path && is_valid_path(path)) {
			pending_open_is_lib = ((g_str_has_suffix(path, ".so") || strstr(path, ".so.")) && !g_str_has_suffix(path, ".cache"));
			pending_open_write = ((int)a2 & (1 | 2)) != 0; // w | r
			pending_open_path = g_strdup(path);
			g_free(path);
		} else {
			g_free(path);
		}
	} else if (num == 295) {  //openat
		char *path = read_guest_string(a2);
		if (path && *path && is_valid_path(path)) {
			pending_open_is_lib = ((g_str_has_suffix(path, ".so") || strstr(path, ".so.")) && !g_str_has_suffix(path, ".cache"));
			pending_open_write = ((int)a3 & (1 | 2)) != 0; // w | r
			pending_open_path = g_strdup(path);
			g_free(path);
		} else {
			g_free(path);
		}
	} else if (num == 4 || num == 146 || num == 181) {  // write, writev pwrite
		gpointer val = g_hash_table_lookup(file_fd, GINT_TO_POINTER((int)a1));
		if (val) {
			file_dep_t *f = (file_dep_t*)val;
			f->write = true;
		}
	} else if ((is_i386 && num == 41) || (!is_i386 && num == 32)) {  // dup
		pending_dup_fd = (int)a1;
	} else if ((is_i386 && num == 63) || (!is_i386 && num == 33)) {  // dup2
		gpointer val = g_hash_table_lookup(file_fd, GINT_TO_POINTER((int)a1));
		if (val) {
			g_hash_table_insert(file_fd, GINT_TO_POINTER((int)a2), val);
		}
	} else if ((is_i386 && num == 330) || (!is_i386 && num == 292)) {  // dup3
		gpointer val = g_hash_table_lookup(file_fd, GINT_TO_POINTER((int)a1));
		if (val) {
			g_hash_table_insert(file_fd, GINT_TO_POINTER((int)a2), val);
		}
	} else if (num == 6) {  // close
		g_hash_table_remove(file_fd, GINT_TO_POINTER((int)a1));
	} else if (num == 33) {  // access
		char *path = read_guest_string(a1);
		if (path && *path && is_valid_path(path)) {
			add_file_dep(path, false);
		} else {
			g_free(path);
		}
	} else if (num == 307) { //faccessat
		char *path = read_guest_string(a2);
		if (path && *path && is_valid_path(path)) {
			add_file_dep(path, false);
		} else {
			g_free(path);
		}
	} else if (num == 102) {  // socketcall
		int subcall = (int)a1;
		uint32_t args[6] = {0};
		if (!read_socketcall_args(a2, args)) {
			fprintf(stderr, "[NET] socketcall: failed to read args block\n");
			return;
		}
		switch (subcall) {
			case 1: { //socket
					pending_socketcall_subcall = 1;
					pending_socket_domain = (int)args[0];
					pending_socket_type = (int)args[1];
					fprintf(stderr, "[NET] socketcall socket(domain=%d, type=%d)\n", pending_socket_domain, pending_socket_type);
					break;
				}
			case 2: { //bind
					int fd = (int)args[0];
					uint64_t addr_ptr = args[1];
					int addrlen = (int)args[2];
					char ip[INET6_ADDRSTRLEN] = {0};
					uint16_t port = 0;
					if (parse_guest_sockaddr(addr_ptr, addrlen, ip, sizeof(ip), &port)) {
						net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
						if (!n) {
							n = g_new0(net_dep_t, 1);
							n->fd = fd;
							g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
						}
						g_strlcpy(n->op, "bind", sizeof(n->op));
						g_strlcpy(n->ip, ip, sizeof(n->ip));
						n->port = port;
						net_dep_t *event = g_new0(net_dep_t, 1);
						memcpy(event, n, sizeof(net_dep_t));
						event->payload_hex = NULL;
						net_deps = g_list_append(net_deps, event);
						fprintf(stderr, "[NET] bind fd=%d -> %s:%d\n", fd, ip, port);
					} else {
						fprintf(stderr, "[NET] bind fd=%d: malformed sockaddr\n", fd);
					}
					break;
				}
			case 3: { //connect
					int fd = (int)args[0];
					uint64_t addr_ptr = args[1];
					int addrlen = (int)args[2];
					char ip[INET6_ADDRSTRLEN] = {0};
					uint16_t port = 0;
					if (parse_guest_sockaddr(addr_ptr, addrlen, ip, sizeof(ip), &port)) {
						net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
						if (!n) {
							n = g_new0(net_dep_t, 1);
							n->fd = fd;
							n->domain = (pending_socket_domain != -1) ? pending_socket_domain : AF_UNSPEC;
							n->type = (pending_socket_type   != -1) ? pending_socket_type   : SOCK_STREAM;
							g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
						}
						g_strlcpy(n->op, "connect", sizeof(n->op));
						g_strlcpy(n->ip, ip, sizeof(n->ip));
						n->port = port;
						net_dep_t *event = g_new0(net_dep_t, 1);
						memcpy(event, n, sizeof(net_dep_t));
						event->payload_hex = NULL;
						net_deps = g_list_append(net_deps, event);
						fprintf(stderr, "[NET] connect fd=%d -> %s:%d\n", fd, ip, port);
					} else {
						fprintf(stderr, "[NET] connect fd=%d: malformed sockaddr\n", fd);
					}
					break;
				}
			case 4: { //listen
					int fd = (int)args[0];
					net_dep_t *event = g_new0(net_dep_t, 1);
					event->fd = fd;
					g_strlcpy(event->op, "listen", sizeof(event->op));
					net_deps = g_list_append(net_deps, event);
					fprintf(stderr, "[NET] listen fd=%d\n", fd);
					break;
				}
			case 5: { //accepnt
					int fd = (int)args[0];
					uint64_t addr_ptr = args[1];
					char ip[INET6_ADDRSTRLEN] = {0};
					uint16_t port = 0;
					if (addr_ptr) {
						GByteArray *tmp = g_byte_array_new();
						if (qemu_plugin_read_memory_vaddr(args[2], tmp, sizeof(uint32_t))) {
							uint32_t guest_addrlen = *(uint32_t*)tmp->data;
							parse_guest_sockaddr(addr_ptr, (int)guest_addrlen, ip, sizeof(ip), &port);
						}
					g_byte_array_free(tmp, TRUE);
					}

					net_dep_t *event = g_new0(net_dep_t, 1);
					event->fd = fd;
					g_strlcpy(event->op, "accept", sizeof(event->op));
					g_strlcpy(event->ip, ip, sizeof(event->ip));
					event->port = port;
					net_deps = g_list_append(net_deps, event);
					fprintf(stderr, "[NET] accept fd=%d peer=%s:%d\n", fd, ip[0] ? ip : "?", port);
					break;
				}
			case 9: { //send
					int fd = (int)args[0];
					net_dep_t *event = g_new0(net_dep_t, 1);
					event->fd = fd;
					g_strlcpy(event->op, "send", sizeof(event->op));
					net_deps = g_list_append(net_deps, event);
					fprintf(stderr, "[NET] send fd=%d\n", fd);
					break;
				}
			case 10: { //recv
					int fd = (int)args[0];
					net_dep_t *event = g_new0(net_dep_t, 1);
					event->fd = fd;
					g_strlcpy(event->op, "recv", sizeof(event->op));
					net_deps = g_list_append(net_deps, event);
					fprintf(stderr, "[NET] recv fd=%d\n", fd);
					break;
				 }
			case 11: { //sendto
					int fd = (int)args[0];
					uint64_t addr_ptr = args[4];
					int addrlen = (int)args[5];
					char ip[INET6_ADDRSTRLEN] = {0};
					uint16_t port = 0;
					if (addr_ptr && parse_guest_sockaddr(addr_ptr, addrlen, ip, sizeof(ip), &port)) {
						net_dep_t *event = g_new0(net_dep_t, 1);
						event->fd = fd;
						g_strlcpy(event->op, "sendto", sizeof(event->op));
						g_strlcpy(event->ip, ip, sizeof(event->ip));
						event->port = port;
						net_deps = g_list_append(net_deps, event);
						fprintf(stderr, "[NET] sendto fd=%d -> %s:%d\n", fd, ip, port);
					} else {
						net_dep_t *event = g_new0(net_dep_t, 1);
						event->fd = fd;
						g_strlcpy(event->op, "send", sizeof(event->op));
						net_deps = g_list_append(net_deps, event);
						fprintf(stderr, "[NET] sendto fd=%d (no addr)\n", fd);
					}
					break;
				 }
			case 12: {//recvfrom
					int fd = (int)args[0];
					net_dep_t *event = g_new0(net_dep_t, 1);
					event->fd = fd;
					g_strlcpy(event->op, "recv", sizeof(event->op));
					net_deps = g_list_append(net_deps, event);
					fprintf(stderr, "[NET] recvfrom fd=%d\n", fd);
					break;
				 }
			case 13: { //shutdown
					int fd = (int)args[0];
					int how = (int)args[1];
					net_dep_t *event = g_new0(net_dep_t, 1);
					event->fd = fd;
					g_strlcpy(event->op, "shutdown", sizeof(event->op));
					net_deps = g_list_append(net_deps, event);
					fprintf(stderr, "[NET] shutdown fd=%d how=%d\n", fd, how);
					break;
				 }

			default: fprintf(stderr, "[SYSCALL] unknown socketcall subcall=%d\n", subcall);
		}
	} else if ((is_i386 && num == 359) || (!is_i386 && num == 41)) {  /* socket */
		pending_socket_domain = (int)a1;
		pending_socket_type = (int)a2;
		fprintf(stderr, "[NET] socket(domain=%ld, type=%ld)\n", a1, a2);
	} else if ((is_i386 && num == 361)|| (!is_i386 && num == 49)) {  /* bind */
		int fd = (int)a1;
		char ip[INET6_ADDRSTRLEN] = {0};
		uint16_t port = 0;

		if (parse_guest_sockaddr(a2, (int)a3, ip, sizeof(ip), &port)) {
			net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
			if (!n) {
				n = g_new0(net_dep_t, 1);
				n->fd = fd;
				g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
			}
			g_strlcpy(n->op, "bind", sizeof(n->op));
			g_strlcpy(n->ip, ip, sizeof(n->ip));
			n->port = port;
			net_dep_t *event = g_new0(net_dep_t, 1);
			memcpy(event, n, sizeof(net_dep_t));
			event->payload_hex = NULL;
			net_deps = g_list_append(net_deps, event);
			fprintf(stderr, "[NET] bind fd=%d -> %s:%d\n", fd, ip, port);
		} else {
			fprintf(stderr, "[NET] bind fd=%d: malformed sockaddr\n", fd);
		}
	} else if ((is_i386 && num == 362) || (!is_i386 && num == 42)) {  /* connect */
		int fd = (int)a1;
		char ip[INET6_ADDRSTRLEN] = {0};
		uint16_t port = 0;

		if (parse_guest_sockaddr(a2, (int)a3, ip, sizeof(ip), &port)) {
			net_dep_t *n = g_hash_table_lookup(g_sockets, GINT_TO_POINTER(fd));
			if (!n) {
				n = g_new0(net_dep_t, 1);
				n->fd = fd;
				n->domain = (pending_socket_domain != -1) ? pending_socket_domain : AF_UNSPEC;
				n->type = (pending_socket_type   != -1) ? pending_socket_type   : SOCK_STREAM;
				g_hash_table_insert(g_sockets, GINT_TO_POINTER(fd), n);
			}
			g_strlcpy(n->op, "connect", sizeof(n->op));
			g_strlcpy(n->ip, ip, sizeof(n->ip));
			n->port = port;
			net_dep_t *event = g_new0(net_dep_t, 1);
			memcpy(event, n, sizeof(net_dep_t));
			event->payload_hex = NULL;
			net_deps = g_list_append(net_deps, event);
			fprintf(stderr, "[NET] connect fd=%d -> %s:%d\n", fd, ip, port);
		} else {
			fprintf(stderr, "[NET] connect fd=%d: malformed sockaddr\n", fd);
		}
	} else if ((is_i386 && num == 363) || (!is_i386 && num == 50)) {  /* listen */
		net_dep_t *event = g_new0(net_dep_t, 1);
		event->fd = (int)a1;
		g_strlcpy(event->op, "listen", sizeof(event->op));
		net_deps = g_list_append(net_deps, event);
		fprintf(stderr, "[NET] listen fd=%d\n", (int)a1);
	} else if ((is_i386 && num == 364) || (!is_i386 && num == 43)) {  /* accept */
		net_dep_t *event = g_new0(net_dep_t, 1);
		event->fd = (int)a1;
		g_strlcpy(event->op, "accept", sizeof(event->op));
		net_deps = g_list_append(net_deps, event);
		fprintf(stderr, "[NET] accept fd=%d\n", (int)a1);
	} else if (!is_i386 && num == 288) {  // accept4
		net_dep_t *event = g_new0(net_dep_t, 1);
		event->fd = (int)a1;
		g_strlcpy(event->op, "accept4", sizeof(event->op));
		net_deps = g_list_append(net_deps, event);
		fprintf(stderr, "[NET] accept4 fd=%d flags=%ld\n", (int)a1, a3);
	} else if ((is_i386 && num ==369) || (!is_i386 && num == 44)) {  // sendto
		char ip[INET6_ADDRSTRLEN] = {0};
		uint16_t port = 0;
		if (a5 && parse_guest_sockaddr(a5, (int)a6, ip, sizeof(ip), &port)) {
			net_dep_t *event = g_new0(net_dep_t, 1);
			event->fd = (int)a1;
			g_strlcpy(event->op, "sendto", sizeof(event->op));
			g_strlcpy(event->ip, ip, sizeof(event->ip));
			event->port = port;
			net_deps = g_list_append(net_deps, event);
			fprintf(stderr, "[NET] sendto fd=%d -> %s:%d\n", (int)a1, ip, port);
		} else {
			net_dep_t *event = g_new0(net_dep_t, 1);
			event->fd = (int)a1;
			g_strlcpy(event->op, "send", sizeof(event->op));
			net_deps = g_list_append(net_deps, event);
			fprintf(stderr, "[NET] sendto fd=%d (no addr)\n", (int)a1);
		}
	} else if ((is_i386 && num == 372) || (!is_i386 && num == 45)) {  // recvfrom
		net_dep_t *event = g_new0(net_dep_t, 1);
		event->fd = (int)a1;
		g_strlcpy(event->op, "recv", sizeof(event->op));
		net_deps = g_list_append(net_deps, event);
		fprintf(stderr, "[NET] recvfrom fd=%d\n", (int)a1);
	} else if ((is_i386 && num == 373) || (!is_i386 && num == 48)) {  // shutdown
		net_dep_t *event = g_new0(net_dep_t, 1);
		event->fd = (int)a1;
		g_strlcpy(event->op, "shutdown", sizeof(event->op));
		net_deps = g_list_append(net_deps, event);
		fprintf(stderr, "[NET] shutdown fd=%d how=%ld\n", (int)a1, a2);
	}else if (num == 192) { //mmap2
		memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));

		g_pending_mmap.active = true;
		g_pending_mmap.syscall_num = num;
		g_pending_mmap.requested_addr = (uint32_t)a1;
		g_pending_mmap.size = (uint32_t)a2;
		g_pending_mmap.prot = (int)a3;
		g_pending_mmap.flags = (uint32_t)a4;
		g_pending_mmap.fd = (int32_t)(uint32_t)a5;
		g_pending_mmap.offset = ((uint64_t)(uint32_t)a6) << 12;
	} else if (num == 90) { //mmap
		memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));
		GByteArray *buf = g_byte_array_new();
		if (qemu_plugin_read_memory_vaddr(a1, buf, 24) && buf->len >= 24) {
			uint32_t args[6];
			memcpy(args, buf->data, sizeof(args));
			g_pending_mmap.active = true;
			g_pending_mmap.syscall_num = num;
			g_pending_mmap.requested_addr = args[0];
			g_pending_mmap.size = args[1];
			g_pending_mmap.prot = (int)args[2];
			g_pending_mmap.flags = args[3];
			g_pending_mmap.fd = (int32_t)args[4];
			g_pending_mmap.offset = args[5];
		} else {
			fprintf(stderr, "[MMAP] failed to read old mmap arguments at 0x%lx\n", (unsigned long)a1);
		}
		g_byte_array_free(buf, TRUE);		
	} else if (num == 125 || num == 380 || num == 91) { //munmap & mprotect
		memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));
		g_pending_mmap.active = true;
		g_pending_mmap.syscall_num = num;
		g_pending_mmap.requested_addr = (uint32_t)a1;
		g_pending_mmap.size = (uint32_t)a2;
		g_pending_mmap.prot = (num == 91) ? 0 : (int)(uint32_t)a3;
	}
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
	size_t n_insns = qemu_plugin_tb_n_insns(tb);
	for (size_t i = 0; i < n_insns; i++) {
		struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
		uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
		size_t size = qemu_plugin_insn_size(insn);
		uint8_t *bytes = g_malloc(size);
		size_t copied = qemu_plugin_insn_data(insn, (char*)bytes, size);

		//capstone
		InsnMeta *meta = meta_decode(bytes, copied, vaddr, cs_handle);
		if (meta) meta_store(vaddr, meta);
		g_free(bytes);

		//callbacks
		qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_R_REGS, (gpointer)(uintptr_t)vaddr);
		qemu_plugin_register_vcpu_mem_cb(insn, on_mem_write, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_W, NULL);
		qemu_plugin_register_vcpu_mem_cb(insn, dse_on_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, NULL);
	}
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, int64_t ret) {
	const bool syscall_failed = syscall_ret_is_error(ret);

	if (g_pending_mmap.active) {
		pending_mmap_t pending = g_pending_mmap;
		memset(&g_pending_mmap, 0, sizeof(g_pending_mmap));
		if (pending.syscall_num != num) {
			fprintf(stderr, "[SYSCALL] pending operation mismatch: expected=%ld actual=%ld\n", (long)pending.syscall_num, (long)num);
		} else if (syscall_failed) {
			fprintf(stderr, "[SYSCALL] memory operation failed: num=%ld ret=%ld\n", (long)num, (long)ret);
		} else if (pending.syscall_num == 90 || pending.syscall_num == 192) { //mmap
			uint64_t mapped_addr = is_i386 ? (uint64_t)(uint32_t)ret: (uint64_t)ret;
			apply_pending_mmap(&pending, mapped_addr);
		} else if (pending.syscall_num == 125 || pending.syscall_num == 380) { //mprotect
			apply_pending_mprotect(&pending);
		} else if (pending.syscall_num == 91) { //munmap
			apply_pending_munmap(&pending);
		}
	}

	if (syscall_failed) {
		pending_socketcall_subcall = -1;
		pending_socket_domain = -1;
		pending_dup_fd = -1;
		g_free(pending_open_path);
		pending_open_path = NULL;
		return;
	}

	if (pending_open_path) {
		file_dep_t *f = add_file_dep(pending_open_path, pending_open_is_lib);
		f->write = pending_open_write;
		g_hash_table_insert(file_fd, GINT_TO_POINTER((int)ret), f);
		g_free(pending_open_path);
		pending_open_path = NULL;
	}

	if (pending_dup_fd >= 0) { //dup
		gpointer val = g_hash_table_lookup(file_fd, GINT_TO_POINTER(pending_dup_fd));
		if (val) {
			g_hash_table_insert(file_fd, GINT_TO_POINTER((int)ret), val);
		}
		pending_dup_fd = -1;
		return;
	}

	if ((is_i386 && num == 359) || (!is_i386 && num == 41)) {  // socket
		if (pending_socket_domain != -1) {
			net_dep_t *n = g_new0(net_dep_t, 1);
			n->fd = (int)ret;
			g_strlcpy(n->op, "socket", sizeof(n->op));
			n->domain = pending_socket_domain;
			n->type = pending_socket_type;
			g_hash_table_insert(g_sockets, (gpointer)(uintptr_t)(n->fd), n);
			net_dep_t *event = g_new0(net_dep_t, 1);
			memcpy(event, n, sizeof(net_dep_t));
			event->payload_hex = NULL;
			net_deps = g_list_append(net_deps, event);
			pending_socket_domain = -1;
			pending_socket_type = -1;
		}
	} else if (num == 102) {  // socketcall
		if (pending_socketcall_subcall == 1) {  // SYS_SOCKET
			net_dep_t *n = g_new0(net_dep_t, 1);
			n->fd = (int)ret;
			g_strlcpy(n->op, "socket", sizeof(n->op));
			n->domain = pending_socket_domain;
			n->type = pending_socket_type;
			g_hash_table_insert(g_sockets, (gpointer) (uintptr_t)(n->fd), n);
			pending_socketcall_subcall = -1;
			pending_socket_domain = -1;
			pending_socket_type = -1;
			net_dep_t *event = g_new0(net_dep_t, 1);
			memcpy(event, n, sizeof(net_dep_t));
			event->payload_hex = NULL;
			net_deps = g_list_append(net_deps, event);
			pending_socketcall_subcall = -1;
			pending_socket_domain = -1;
			pending_socket_type = -1;
		}
	}
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(
    qemu_plugin_id_t id,
    const qemu_info_t *info,
    int argc, char **argv)
{
	const char *target = info->target_name;
	
	//arch choose
	if (strstr(target, "i386")) {
		current_arch = ARCH_X86_32;
		is_i386 = true;
	} else if (strstr(target, "arm")) {
		current_arch = ARCH_ARM;
	} else if (strstr(target, "mips")) {
		current_arch = ARCH_MIPS;
	} else {
		fprintf(stderr, "[PLUGIN] ERROR:%s", target);
		return -1;
	}
	fprintf(stderr, "[PLUGIN] Loaded for architecture: %s (enum=%d)\n", target, current_arch);

	//dse
	//qemu_plugin_register_vcpu_init_cb(id, dse_vcpu_init);

	//shadow mem init
	g_shadow = shadow_create(32);
	if (!g_shadow) {
		return -1;
	}
	
	//register taint handler
	memset(&reg_shadow, 0, sizeof(reg_shadow));
	//capstone initialization
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) {
		fprintf(stderr, "[PLUGIN] Capstone init failed\n");
		return -1;
	}
	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
	meta_init();

	//needed hashtables
	pages = g_hash_table_new(g_direct_hash, g_direct_equal);
	file_fd = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_sockets = g_hash_table_new(g_direct_hash, g_direct_equal);
	//munmaped pages
	unmapped_pages = g_hash_table_new(g_direct_hash, g_direct_equal);

	//got
	resolved_imports_by_slot = g_hash_table_new(g_direct_hash, g_direct_equal);

	//callback funcs
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_vcpu_syscall_cb(id, vpcu_syscall);
	qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
	
	//tracer
	g_trace = trace_buffer_create(256 * 1024);
	if (!g_trace) {
		fprintf(stderr, "[PLUGIN] Trace buffer init failed\n");
	return -1;
	}
	g_aux = dse_aux_create(256 * 1024);
	if (!g_aux) {
		fprintf(stderr, "[PLUGIN] aux ring init failed\n");
		return -1;
	}

	dse_lift_attach(g_trace, g_aux, &dse_arch_x86);

	//exit
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}
