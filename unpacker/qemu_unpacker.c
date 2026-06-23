#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <qemu-plugin.h>
#include "dta.h"
#include <capstone/capstone.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
    bool exec_after_write;
    uint64_t write_count;
    uint64_t last_write;
} page_t;

static GHashTable *pages = NULL;
static ShadowMemory *g_shadow = NULL;
static bool oep_found = false;
static uint64_t oep_addr = 0;
static __thread uint64_t g_current_ip = 0;
static csh cs_handle;
static RegShadow reg_shadow;

static bool read_socketcall_args(uint64_t block_addr, uint32_t out[6]) {
	GByteArray *arr = g_byte_array_new();
	if (!qemu_plugin_read_memory_vaddr(block_addr, arr, 24)) {
		g_byte_array_free(arr, TRUE);
		return false;
	}
	memcpy(out, arr->data, 24);
	g_byte_array_free(arr, TRUE);
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
	GByteArray *arr = g_byte_array_new();

	for (size_t i = 0; i < 1024; i++) {
		g_byte_array_set_size(arr, 0);
		if (!qemu_plugin_read_memory_vaddr(gaddr + i, arr, 1)) break;
		if (arr->len == 0) break;
		guint8 ch = arr->data[0];
		if (ch == '\0') break;
		g_string_append_c(s, ch);
	}

	g_byte_array_free(arr, TRUE);

	if (s->len == 0) {
		g_string_free(s, TRUE);
		return NULL;
	}
	return g_string_free(s, FALSE);
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

static void on_mem_write(unsigned int vcpu_idx, qemu_plugin_meminfo_t info, uint64_t vaddr, void *userdata) {
	shadow_taint_byte(g_shadow, vaddr, g_current_ip);

	page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t) (vaddr & ~(page_size - 1)));
	if (p) {
		p->written = true;
		p->write_count++;
		p->last_write = g_current_ip;
	}
}

static bool bin_dumped = false;
static GString *saved_reg = NULL;

static void do_dump(uint64_t oep) {
	GList *keys = g_hash_table_get_keys(pages);
	keys = g_list_sort(keys, compare_keys);
	static uint64_t base_addr = 0;
	
	if (!bin_dumped) {
		FILE *f_bin = fopen("unpacked.bin", "wb");
		if (f_bin) {
			for (GList *k = keys; k; k = k->next) {
				uint64_t addr = (uint64_t)(uintptr_t)k->data;
				page_t *p = g_hash_table_lookup(pages, k->data);
				if (!p) continue;
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
		uint64_t offset = 0;
		uint64_t region_start = 0;
		uint64_t region_size = 0;
		int region_prot = 0;

		for (GList *k = keys; k; k = k->next) {
			uint64_t addr = (uint64_t)(uintptr_t)k->data;
			page_t *p = g_hash_table_lookup(pages, k->data);
			if (!p) continue;

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

			if (in_region && addr == region_start + region_size && p->prot == region_prot) {
				region_size += written;
			} else {
				if (in_region) {
					if (!first_region) g_string_append(saved_reg, ",\n");
					first_region = false;
					g_string_append_printf(saved_reg, "    {\"addr\": \"0x%lx\", \"size\": %lu, \"prot\": %d, \"offset\": %lu}", region_start, region_size, region_prot, offset - region_size);
				}
				region_start = addr;
				region_size = written;
				region_prot = p->prot;
				in_region = true;
			}
			offset += written;
		}
		if (in_region) {
			if (!first_region) g_string_append(saved_reg, ",\n");
			g_string_append_printf(saved_reg, "    {\"addr\": \"0x%lx\", \"size\": %lu, \"prot\": %d, \"offset\": %lu}\n", region_start, region_size, region_prot, offset - region_size);
		}
		g_string_append(saved_reg, "  ],\n");
	}

	FILE *f_json = fopen("unpacked.json", "w");
	if (!f_json) { g_list_free(keys); return; }

	if (base_addr == 0) {
		base_addr = oep & ~(page_size - 1);
	}
	fprintf(f_json, "{\n");
	fprintf(f_json, "  \"oep\": \"0x%lx\",\n", oep);
	fprintf(f_json, "  \"arch\": \"x86\",\n");
	fprintf(f_json, "  \"base\": \"0x%lx\",\n", base_addr);
	fprintf(f_json, "%s", saved_reg ? saved_reg->str : "  \"regions\": [],\n");

	// files
	fprintf(f_json, "  \"file_dependencies\": [");
	bool first = true;
	for (GList *l = file_deps; l; l = l->next) {
		file_dep_t *f = (file_dep_t*)l->data;
		if (!f->path) continue;
		//if (!path || !*path || *path != '/' || !is_valid_path(path)) continue;
		//if (!first) fprintf(f_json, ", ");
		if (!first) fprintf(f_json, ",\n");
		fprintf(f_json, "    {\"path\": \"%s\", \"write\": %s}", f->path, f->write ? "true" : "false");
		//fprintf(f_json, "\"%s\"", (char*)l->data);
		first = false;
	}
	fprintf(f_json, "],\n");

	// libraries
	fprintf(f_json, "  \"library_dependencies\": [");
	first = true;
	for (GList *l = lib_deps; l; l = l->next) {
		lib_mapping_t *lm = (lib_mapping_t*)l->data;
		if (!lm->path || !*lm->path || *lm->path != '/' || !is_valid_path(lm->path)) continue;
		if (!first) fprintf(f_json, ", ");
		fprintf(f_json, "{\"path\": \"%s\", \"base\": \"0x%lx\", \"size\": %lu}", lm->path, lm->base, lm->size);
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
	g_list_free(keys);
	fprintf(stderr, "[DUMP] unpacked.bin + unpacked.json complete\n");
}


static void plugin_exit(qemu_plugin_id_t id, void *udata) {
	//dump check
	do_dump(oep_addr);
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
	if (saved_reg) {
		g_string_free(saved_reg, TRUE);
	}
	
	//fd
	g_free(pending_open_path);

	//capstone handle
	cs_close(&cs_handle);
	meta_free();
}

static int mask_first_reg(uint32_t mask) {
	for (int i = 0; i < REG_COUNT; i++) {
		if (mask & (1U << i)) return i;
	}
	return -1;
}

static void vcpu_insn_exec(unsigned int cpu_index, void *udata) {
	uint64_t vaddr = (uint64_t)(uintptr_t) udata;
	g_current_ip = vaddr;
	
	InsnMeta *meta = meta_lookup(vaddr);
	if (!meta) goto fallback_oep;
	
	//xor or sub with itself, like sub al, al or xor al, al. have to lead to taint clean
	if ((meta->insn_id == X86_INS_XOR || meta->insn_id == X86_INS_SUB) && meta->regs_read_mask == meta->regs_written_mask && meta->regs_read_mask != 0) {
		int reg = mask_first_reg(meta->regs_written_mask);
		if (reg >= 0) reg_propagate_clear(&reg_shadow, reg);
		goto check_oep;
	}
	//if const have been changed we will see at mem_taint
	if (meta->regs_read_mask == 0 && meta->regs_written_mask != 0 && !meta->has_mem_read && !meta->has_mem_write) {
		int dst = mask_first_reg(meta->regs_written_mask);
		if (dst >= 0) reg_propagate_clear(&reg_shadow, dst);
		goto check_oep;
	}
	// lea with two registers
	if (meta->insn_id == X86_INS_LEA) {
		int dst = mask_first_reg(meta->regs_written_mask);
		int src = mask_first_reg(meta->regs_read_mask);
		if (dst >= 0 && src >= 0) {
			propagate_reg2reg(&reg_shadow, dst, 0x0F, src, 0x0F);
		}
		goto check_oep;
	}
	//mem2reg
	if (meta->has_mem_read && meta->regs_written_mask) {
		int dst = mask_first_reg(meta->regs_written_mask);
		if (dst >= 0) {
			propagate_mem2reg(&reg_shadow, dst, 0x0F, true);
		}
	}
	int num_src_regs = __builtin_popcount(meta->regs_read_mask);
	//reg2reg, count 1 in bytes representation, TODO add al, ah resolve
	if (num_src_regs == 1 && meta->regs_written_mask) {
		int src = mask_first_reg(meta->regs_read_mask);
		int dst = mask_first_reg(meta->regs_written_mask);
		if (src >= 0 && dst >= 0) {
			propagate_reg2reg(&reg_shadow, dst, 0x0F, src, 0x0F);
		}
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
	check_oep:
		if (meta->is_indirect_branch && !oep_found) { //indirect check
			bool target_tainted = false;
			if (meta->branch_target_reg >= 0 && meta->branch_target_reg < REG_COUNT) { //on reg
				target_tainted = reg_is_tainted(&reg_shadow, meta->branch_target_reg, 0x0F);
			} else if (meta->branch_target_reg == REG_INVALID) { // on mem with reg, like [eax]
				target_tainted = shadow_page_has_taint(g_shadow, vaddr);
			}
			if (target_tainted) {
				uint64_t page = vaddr & ~(page_size - 1);
				page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page);
				if (p && (p->prot & 0x4)) {
					oep_found = true;
					oep_addr = vaddr;
					fprintf(stderr, "[OEP-REG] 0x%lx\n", vaddr);
					do_dump(oep_addr);
					return;
				}
			}
		}
	fallback_oep: //enough for direct jumps, TODO mb add direct jump sink
		if (oep_addr != 0) return;
		uint64_t page = vaddr & ~(page_size - 1);
		page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t)page);
		if (p && ((p->written && (p->prot & 0x4)) || p->exec_after_write)) {
			oep_addr = vaddr;
			fprintf(stderr, "[OEP-LEGACY] 0x%lx\n", oep_addr);
			do_dump(oep_addr);
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
		int prot = (int)a3;
		if (prot & 0x2 || prot & 0x4) {
			fprintf(stderr, "[SYSCALL] mmap2(0x%lx, 0x%lx, prot=0x%x, flags=0x%x, fd=%d, offset=0x%x)\n", a1, a2, (int)a3, (int)a4, (int)a5, (int)a6);
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
			if (a5 > 0) { //fd check
				gpointer val = g_hash_table_lookup(file_fd, (gpointer)(uintptr_t)a5);
				if (val) {
					file_dep_t *f = (file_dep_t*)val;
					for (GList *l = lib_deps; l; l = l->next) {
						lib_mapping_t *lm = (lib_mapping_t*)l->data;
						if (f->path && strcmp(lm->path, f->path) == 0) {
							lm->base = a1;
							lm->size = a2;
							break;
						}
					}
				} else { // fallback if fd was open before check
					for (GList *l = lib_deps; l; l = l->next) {
						lib_mapping_t *lm = (lib_mapping_t*)l->data;
						if (lm->base == 0) {
							lm->base = a1;
							lm->size = a2;
							break;
						}
					}
				}
			}
		}
	} else if (num == 90) { //mmap
		GByteArray *buf = g_byte_array_new();
		if (qemu_plugin_read_memory_vaddr(a1, buf, 24)) {
			uint32_t *args = (uint32_t*)buf->data;
			uint64_t addr = args[0];
			uint64_t size = args[1];
			int prot = args[2];
			uint32_t flags = args[3];
			uint32_t fd = args[4];
			uint32_t off = args[5];
			if (prot & 0x2 || prot & 0x4) {
				fprintf(stderr, "[SYSCALL] mmap(0x%lx, 0x%lx, prot=0x%x, flags=0x%x, fd=%u, offset=0x%x)\n", addr, size, prot, flags, fd, off);
				uint64_t page_start = addr & ~(page_size - 1);
				uint64_t page_end = (addr + size + page_size - 1) & ~(page_size - 1);
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
				if (fd > 0){
					gpointer val = g_hash_table_lookup(file_fd, (gpointer)(uintptr_t) fd);
					if (val) {
						file_dep_t *f = (file_dep_t*)val;
						for (GList *l = lib_deps; l; l = l->next) {
							lib_mapping_t *lm = (lib_mapping_t*)l->data;
							if (f->path && strcmp(lm->path, f->path) == 0) {
								lm->base = addr;
								lm->size = size;
								break;
							}
						}
					}
				} else {
					for (GList *l = lib_deps; l; l = l->next) {
						lib_mapping_t *lm = (lib_mapping_t*)l->data;
						if (lm->base == 0) {
							lm->base = addr;
							lm->size = size;
							break;
						}
					}
				}
			}
		}
		g_byte_array_free(buf, TRUE);
	} else if (num == 125 || num == 380) { //mprotect
		int prot = (int) a3;
		uint64_t page_start = a1 & ~(page_size - 1);
		uint64_t page_end = (a1 + a2 + page_size - 1) & ~(page_size- 1);
		fprintf(stderr, "[SYSCALL] mprotect(0x%lx, 0x%lx, prot=0x%x)\n", a1, a2, prot);
		for (uint64_t addr = page_start; addr < page_end; addr += page_size) {
			page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t) addr);
			if (p) {
				p->prot = prot;
			} else {
				page_t *np = g_new0(page_t, 1);
				np->prot = prot;
				g_hash_table_insert(pages, (gpointer)(uintptr_t)addr, np);
			}
			if (p && p->written && (prot & 0x4)) {
				p->exec_after_write = true;  // written + потом exec = OEP candidate
			}
		}
	} else if (num == 91) { //munmap
		uint64_t page_start = a1 & ~(page_size - 1);
		uint64_t page_end = (a1 + a2 + page_size - 1) & ~(page_size- 1);
		for (uint64_t addr = page_start; addr < page_end; addr += page_size) {
			page_t *p = g_hash_table_lookup(pages, (gpointer)(uintptr_t) addr);
			if (p) {
				if (p->written && (p->prot & 0x4) && oep_addr == 0) {
					do_dump(oep_addr);
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
		size_t size = qemu_plugin_insn_size(insn);
		uint8_t *bytes = g_malloc(size);
		size_t copied = qemu_plugin_insn_data(insn, (char*)bytes, size);

		//capstone
		InsnMeta *meta = meta_decode(bytes, copied, vaddr, cs_handle);
		if (meta) meta_store(vaddr, meta);
		g_free(bytes);

		//callbacks
		qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec, QEMU_PLUGIN_CB_NO_REGS, (gpointer)(uintptr_t)vaddr);
		qemu_plugin_register_vcpu_mem_cb(insn, on_mem_write, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_W, NULL);
	}
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, int64_t ret) {
	if ((int64_t)ret < 0) {
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
	
	//callback funcs
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
	qemu_plugin_register_vcpu_syscall_cb(id, vpcu_syscall);
	qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
	
	//exit
	qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}
