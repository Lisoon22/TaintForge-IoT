#include "dta.h"
#include<stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <glib.h>
#include <string.h>

#define page_size 4096

struct ShadowMemory {
	uint8_t  arch;
	void    *base;
	size_t   size;
	GHashTable *dirty_pages;
};


ShadowMemory *shadow_create(uint8_t arch) {
	if (arch == 32) {
		ShadowMemory *sm = malloc(sizeof(ShadowMemory));
		if (!sm) return NULL;
		size_t size = 1ULL << 32;
		void *base = mmap(NULL, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (base == MAP_FAILED) {
			free(sm);
			return NULL;
		}
		sm->dirty_pages = g_hash_table_new(g_direct_hash, g_direct_equal);
		if (!sm->dirty_pages) {
			munmap(base, size);
			free(sm);
			return NULL;
		}
		sm->arch = arch;
		sm->base = base;
		sm->size = size;
		return sm;
	} else { //TODO
		return NULL;
	}
}

void shadow_destroy(ShadowMemory *sm) {
	if (!sm) return;
	if (sm->dirty_pages) g_hash_table_destroy(sm->dirty_pages);
	munmap(sm->base, sm->size);
	free(sm);
}

void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip) {
	(void)ip;
	if (sm->arch == 32) {
		addr &= 0xFFFFFFFFULL;
	} else {
		//TODO
	}
	uint64_t page_base = addr & ~((uint64_t)page_size - 1);
	if (!g_hash_table_contains(sm->dirty_pages, GSIZE_TO_POINTER((size_t)page_base))) {
		mprotect((char*)sm->base + page_base, page_size, PROT_READ | PROT_WRITE);
		g_hash_table_add(sm->dirty_pages, GSIZE_TO_POINTER((size_t)page_base));
	}
	*((uint8_t *)sm->base + addr) = 1;
}

bool shadow_taint_range(ShadowMemory *sm, uint64_t addr, uint64_t size, uint64_t ip) {
	(void)ip;
	if (!sm) return false;
	if (size == 0) return true;

	if (sm->arch == 32) {
		addr &= 0xFFFFFFFFULL;
		uint64_t available = (1ULL << 32) - addr;
		if (size > available) size = available;
	} else {
		//TODO
		return false;
	}

	while (size > 0) {
		uint64_t page_base = addr & ~((uint64_t)page_size - 1);
		uint64_t page_off = addr - page_base;
		uint64_t chunk = (uint64_t)page_size - page_off;
		if (chunk > size) chunk = size;
		if (!g_hash_table_contains(sm->dirty_pages, GSIZE_TO_POINTER((size_t)page_base))) {
			if (mprotect((uint8_t *)sm->base + page_base, page_size, PROT_READ | PROT_WRITE) != 0) {
				return false;
			}
			g_hash_table_add(sm->dirty_pages, GSIZE_TO_POINTER((size_t)page_base));
		}
		memset((uint8_t *)sm->base + addr, 1, (size_t)chunk);
		addr += chunk;
		size -= chunk;
	}
	return true;
}

void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr) {
	if (sm->arch == 32) addr &= 0xFFFFFFFFULL;
	uint8_t *p = (uint8_t *)sm->base + addr;
	if (*p == 0) return;
	*p = 0;
}

void shadow_untaint_range(ShadowMemory *sm, uint64_t addr, uint64_t size) {
	if (!sm || size == 0) {
		return;
	}
	if (sm->arch == 32) addr &= 0xFFFFFFFFULL;
	if (addr >= (uint64_t)sm->size) return;

	uint64_t available = (uint64_t)sm->size - addr;
	if (size > available) {
		size = available;
	}

	while (size > 0) {
		uint64_t page_base = addr & ~((uint64_t)page_size - 1);
		uint64_t page_offset = addr - page_base;
		uint64_t chunk = (uint64_t)page_size - page_offset;
		if (chunk > size) chunk = size;
		if (g_hash_table_contains(sm->dirty_pages, GSIZE_TO_POINTER((size_t)page_base))) {
			memset((uint8_t *)sm->base + addr,0, (size_t)chunk);
		}
		addr += chunk;
		size -= chunk;
	}
}

bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr) {
	if (sm->arch == 32) addr &= 0xFFFFFFFFULL;
	return *((uint8_t *)sm->base + addr) != 0;
}

bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr) {
	if (sm->arch == 32) addr &= 0xFFFFFFFFULL;
	uint64_t page_base = addr & ~((uint64_t)page_size - 1);
	if (!g_hash_table_contains(sm->dirty_pages, GSIZE_TO_POINTER((size_t)page_base))) {
		return false;
	}
	const uint64_t *p = (const uint64_t *)((uint8_t *)sm->base + page_base);
	for (size_t i = 0; i < page_size / sizeof(uint64_t); i++) {
		if (p[i]) return true;
	}
	return false;
}

RegSlice reg_slice_invalid(void) {
	RegSlice slice = {.reg_id = REG_INVALID, .byte_offset = 0, .width = 0, .mask = 0};
	return slice;
}

bool reg_slice_is_valid(RegSlice slice) {
	if (slice.reg_id < 0 || slice.reg_id >= REG_COUNT) return false;
	if (slice.width == 0 || slice.width > MAX_REG_BYTES) return false;
	if (slice.byte_offset >= MAX_REG_BYTES) return false;
	if (slice.width > MAX_REG_BYTES - slice.byte_offset) return false;
	uint16_t low_bits = (uint16_t)((1U << slice.width) - 1U);
	uint8_t expected_mask = (uint8_t)(low_bits << slice.byte_offset);
	return slice.mask == expected_mask;
}

RegSlice reg_slice_from_x86(unsigned cs_reg, uint8_t size_bytes) {
	int rid = x86_reg_to_rid(cs_reg);
	if (rid < 0 || size_bytes == 0 || size_bytes > MAX_REG_BYTES) {
		return reg_slice_invalid();
	}

	x86_reg reg = (x86_reg)cs_reg;
	uint8_t byte_offset = (reg == X86_REG_AH || reg == X86_REG_BH || reg == X86_REG_CH || reg == X86_REG_DH) ? 1 : 0;

	if (size_bytes > MAX_REG_BYTES - byte_offset) return reg_slice_invalid();

	uint16_t low_bits = (uint16_t)((1U << size_bytes) - 1U);
	RegSlice slice = {.reg_id = (RegId)rid, .byte_offset = byte_offset, .width = size_bytes, .mask = (uint8_t)(low_bits << byte_offset)};
	return slice;
}

bool reg_slice_equal(RegSlice left, RegSlice right) {
	return reg_slice_is_valid(left) && reg_slice_is_valid(right) && left.reg_id == right.reg_id && left.byte_offset == right.byte_offset && left.width == right.width && left.mask == right.mask;
}

RegSlice meta_first_reg_read(const InsnMeta *meta) {
	if (!meta || meta->reg_read_count == 0) return reg_slice_invalid();
	return meta->reg_reads[0];
}

RegSlice meta_first_reg_write(const InsnMeta *meta) {
	if (!meta || meta->reg_write_count == 0) return reg_slice_invalid();
	return meta->reg_writes[0];
}

int x86_reg_to_rid(unsigned cs_reg) {
	switch ((x86_reg)cs_reg) {
		case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH:
			return REG_RAX;
		case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH:
			return REG_RCX;
		case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH:
			return REG_RDX;
		case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH:
			return REG_RBX;
		case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
			return REG_RSP;
		case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
			return REG_RBP;
		case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
			return REG_RSI;
		case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
			return REG_RDI;
		case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return REG_R8;
		case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return REG_R9;
		case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return REG_R10;
		case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return REG_R11;
		case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return REG_R12;
		case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return REG_R13;
		case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return REG_R14;
		case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return REG_R15;
		default:
			return -1;
	}
}

void reg_taint_set(RegShadow *rs, RegId rid, uint8_t byte_mask, uint64_t ip) {
	for (int i = 0; i < MAX_REG_BYTES; i++) {
		if (byte_mask & (1U << i)) rs->bytes[rid][i] = true;
	}
	rs->src_ip[rid] = ip;
}

void reg_taint_clear(RegShadow *rs, RegId rid, uint8_t byte_mask) {
	for (int i = 0; i < MAX_REG_BYTES; i++) {
		if (byte_mask & (1U << i)) rs->bytes[rid][i] = false;
	}
}

bool reg_is_tainted(RegShadow *rs, RegId rid, uint8_t byte_mask) {
	for (int i = 0; i < MAX_REG_BYTES; i++) {
		if ((byte_mask & (1U << i)) && rs->bytes[rid][i]) return true;
	}
	return false;
}

void reg_slice_taint_set(RegShadow *rs, RegSlice slice, uint64_t ip) {
	if (!rs || !reg_slice_is_valid(slice)) return;
	reg_taint_set(rs, slice.reg_id, slice.mask, ip);
}

void reg_slice_taint_clear(RegShadow *rs, RegSlice slice) {
	if (!rs || !reg_slice_is_valid(slice)) return;
	reg_taint_clear(rs, slice.reg_id, slice.mask);
}

bool reg_slice_is_tainted(const RegShadow *rs, RegSlice slice) {
	if (!rs || !reg_slice_is_valid(slice)) return false;
	for (uint8_t i = 0; i < slice.width; i++) {
		uint8_t byte = (uint8_t)(slice.byte_offset + i);
		if (rs->bytes[slice.reg_id][byte]) {
			return true;
		}
	}
	return false;
}

void propagate_reg2reg(RegShadow *rs, RegSlice dst, RegSlice src, uint16_t insn_id) {
	if (!rs || !reg_slice_is_valid(dst) || !reg_slice_is_valid(src)) {
		return;
	}
	uint8_t copy_width = src.width < dst.width ? src.width : dst.width;
	bool source_taint[MAX_REG_BYTES] = {false};
	//save src before write
	for (uint8_t k = 0; k < src.width; k++) {
		uint8_t src_byte = (uint8_t)(src.byte_offset + k);
		source_taint[k] = rs->bytes[src.reg_id][src_byte];
	}
	//copy src to dst
	for (uint8_t k = 0; k < copy_width; k++) {
		uint8_t dst_byte = (uint8_t)(dst.byte_offset + k);
		rs->bytes[dst.reg_id][dst_byte] = source_taint[k];
	}

	if (insn_id == X86_INS_MOVZX) {
		for (uint8_t k = copy_width; k < dst.width; k++) {
			uint8_t dst_byte = (uint8_t)(dst.byte_offset + k);
			rs->bytes[dst.reg_id][dst_byte] = false;
		}
	} else if (insn_id == X86_INS_MOVSX) {
		bool sign_taint = source_taint[src.width - 1];
		for (uint8_t k = copy_width; k < dst.width; k++) {
			uint8_t dst_byte = (uint8_t)(dst.byte_offset + k);
			rs->bytes[dst.reg_id][dst_byte] = sign_taint;
		}
	}
	rs->src_ip[dst.reg_id] = 0;
}

void propagate_mem2reg(RegShadow *rs, RegSlice dst, uint8_t mem_taint_mask, uint8_t mem_width, uint16_t insn_id, bool overwrite) {
	if (!rs || !reg_slice_is_valid(dst) || mem_width == 0) {
		return;
	}
	if (mem_width > MAX_REG_BYTES) {
		mem_width = MAX_REG_BYTES;
	}

	uint8_t copy_width = mem_width < dst.width ? mem_width : dst.width;
	bool strong_update = overwrite || insn_id == X86_INS_MOVZX || insn_id == X86_INS_MOVSX;

	for (uint8_t k = 0; k < copy_width; k++) {
		uint8_t dst_byte = (uint8_t)(dst.byte_offset + k);
		bool tainted = ((mem_taint_mask >> k) & 1U) != 0;
		if (strong_update) {
			rs->bytes[dst.reg_id][dst_byte] = tainted;
		} else {
			rs->bytes[dst.reg_id][dst_byte] |= tainted;
		}
	}
	if (insn_id == X86_INS_MOVZX) {
		for (uint8_t k = copy_width; k < dst.width; k++) {
			uint8_t dst_byte = (uint8_t)(dst.byte_offset + k);
			rs->bytes[dst.reg_id][dst_byte] = false;
		}
	} else if (insn_id == X86_INS_MOVSX) {
		bool sign_taint = ((mem_taint_mask >> (mem_width - 1)) & 1U) != 0;
		for (uint8_t k = copy_width; k < dst.width; k++) {
			uint8_t dst_byte = (uint8_t)(dst.byte_offset + k);
			rs->bytes[dst.reg_id][dst_byte] = sign_taint;
		}
	}
	rs->src_ip[dst.reg_id] = 0;
}

void reg_propagate_clear(RegShadow *rs, RegId rid) {
	for (int i = 0; i < MAX_REG_BYTES; i++) rs->bytes[rid][i] = false;
}

static bool snapshot_slice_byte(const RegShadow *snapshot, RegSlice slice, uint8_t local_byte) {
	if (!snapshot || !reg_slice_is_valid(slice) || local_byte >= slice.width) {
		return false;
	}
	uint8_t byte = (uint8_t)(slice.byte_offset + local_byte);
	return snapshot->bytes[slice.reg_id][byte];
}

static void write_slice_byte(RegShadow *rs, RegSlice slice, uint8_t local_byte, bool tainted) {
	if (!rs || !reg_slice_is_valid(slice) || local_byte >= slice.width) {
		return;
	}
	uint8_t byte = (uint8_t)(slice.byte_offset + local_byte);
	rs->bytes[slice.reg_id][byte] = tainted;
}

static void copy_slice_from_snapshot(RegShadow *rs, const RegShadow *snapshot, RegSlice dst, RegSlice src, uint16_t insn_id) {
	if (!rs || !snapshot || !reg_slice_is_valid(dst) || !reg_slice_is_valid(src)) {
		return;
	}
	uint8_t copy_width = src.width < dst.width ? src.width : dst.width;
	for (uint8_t i = 0; i < copy_width; i++) {
		write_slice_byte(rs, dst, i, snapshot_slice_byte(snapshot, src, i));
	}
	if (insn_id == X86_INS_MOVZX) {
		for (uint8_t i = copy_width; i < dst.width; i++) {
			write_slice_byte(rs, dst, i, false);
		}
	} else if (insn_id == X86_INS_MOVSX) {
		bool sign_taint = snapshot_slice_byte(snapshot, src, (uint8_t)(src.width - 1));
		for (uint8_t i = copy_width; i < dst.width; i++) {
			write_slice_byte(rs, dst, i, sign_taint);
		}
	}
	rs->src_ip[dst.reg_id] = 0;
}

static bool meta_read_state_has_taint(const RegShadow *snapshot, const InsnMeta *meta){
	if (!snapshot || !meta) {
		return false;
	}
	if (meta->reg_read_count > 0) {
		for (uint8_t i = 0; i < meta->reg_read_count; i++) {
			if (reg_slice_is_tainted(snapshot, meta->reg_reads[i])) {
				return true;
			}
		}
		return false;
	}
	for (int rid = 0; rid < REG_COUNT; rid++) {
		if (!(meta->regs_read_mask & (1U << rid))) {
			continue;
		}
		for (uint8_t byte = 0; byte <MAX_REG_BYTES; byte++) {
			if (snapshot->bytes[rid][byte]) {
				return true;
			}
		}
	}
	return false;
}

static DtaTransferResult apply_data_movement(RegShadow *rs, const RegShadow *snapshot, const InsnMeta *meta) {
	RegSlice dst = meta_first_reg_write(meta);
	switch (meta->insn_id) {
	case X86_INS_MOV: case X86_INS_MOVZX: case X86_INS_MOVSX: {
		if (!reg_slice_is_valid(dst)) {
			return DTA_TRANSFER_NOT_APPLICABLE;
		}
		if (meta->insn_id == X86_INS_MOV && meta->has_imm_operand && meta->reg_read_count == 0) {
			reg_slice_taint_clear(rs, dst);
			rs->src_ip[dst.reg_id] = 0;
			return DTA_TRANSFER_EXACT;
		}
		RegSlice src = meta_first_reg_read(meta);
		if (!reg_slice_is_valid(src)) {
			reg_slice_taint_set(rs, dst, 0);
			return DTA_TRANSFER_CONSERVATIVE;
		}
		copy_slice_from_snapshot(rs, snapshot, dst, src, meta->insn_id);
		return DTA_TRANSFER_EXACT;
	}
	case X86_INS_LEA: {
		if (!reg_slice_is_valid(dst)) {
			return DTA_TRANSFER_NOT_APPLICABLE;
		}
		if (meta->mem_addr_reg_mask == 0) {
			reg_slice_taint_clear(rs, dst);
			rs->src_ip[dst.reg_id] = 0;
			return DTA_TRANSFER_EXACT;
		}
		for (uint8_t out_byte = 0;out_byte<dst.width; out_byte++) {
			bool tainted = false;
			for (int rid = 0; rid < REG_COUNT; rid++) {
				if (!(meta->mem_addr_reg_mask & (1U << rid))) {
					continue;
				}
				uint8_t max_input = out_byte < MAX_REG_BYTES ? out_byte : MAX_REG_BYTES - 1;
				for (uint8_t in_byte = 0; in_byte <= max_input;in_byte++) {
					tainted |= snapshot->bytes[rid][in_byte];
				}
			}
			write_slice_byte(rs, dst, out_byte, tainted);
		}
		rs->src_ip[dst.reg_id] = 0;
		return DTA_TRANSFER_CONSERVATIVE;
	}

	case X86_INS_XCHG: {
		if (meta->reg_write_count < 2) {
			uint32_t affected = meta->regs_read_mask | meta->regs_written_mask;
			for (int rid = 0; rid < REG_COUNT; rid++) {
				if (affected & (1U << rid)) {
					reg_taint_set(rs, (RegId)rid, UINT8_MAX, 0);
				}
			}
			return DTA_TRANSFER_CONSERVATIVE;
		}
		RegSlice left = meta->reg_writes[0];
		RegSlice right = meta->reg_writes[1];
		if (!reg_slice_is_valid(left) || !reg_slice_is_valid(right) || left.width != right.width) {
			if (reg_slice_is_valid(left)) {
				reg_slice_taint_set(rs, left, 0);
			}
			if (reg_slice_is_valid(right)) {
				reg_slice_taint_set(rs, right, 0);
			}
			return DTA_TRANSFER_CONSERVATIVE;
		}
		for (uint8_t i = 0; i < left.width; i++) {
			bool left_taint = snapshot_slice_byte(snapshot, left, i);
			bool right_taint = snapshot_slice_byte(snapshot, right, i);
			write_slice_byte(rs, left, i, right_taint);
			write_slice_byte(rs, right, i, left_taint);
		}
		rs->src_ip[left.reg_id] = 0;
		rs->src_ip[right.reg_id] = 0;
		return DTA_TRANSFER_EXACT;
	}

	default:
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
}

static DtaTransferResult apply_logical_transfer(RegShadow *rs, const RegShadow *snapshot, const InsnMeta *meta) {
	RegSlice dst = meta_first_reg_write(meta);
	if (!reg_slice_is_valid(dst)) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	if (meta->is_self_zeroing) {
		reg_slice_taint_clear(rs, dst);
		rs->src_ip[dst.reg_id] = 0;
		return DTA_TRANSFER_EXACT;
	}
	if (meta->reg_read_count == 0) {
		reg_slice_taint_set(rs, dst, 0);
		return DTA_TRANSFER_CONSERVATIVE;
	}

	for (uint8_t out_byte = 0; out_byte < dst.width;out_byte++) {
		bool tainted = false;
		for (uint8_t read_index = 0; read_index < meta->reg_read_count; read_index++) {
			RegSlice src = meta->reg_reads[read_index];
			tainted |= snapshot_slice_byte(snapshot, src, out_byte);
		}
		write_slice_byte(rs, dst, out_byte, tainted);
	}
	rs->src_ip[dst.reg_id] = 0;
	return meta->insn_id == X86_INS_NOT ? DTA_TRANSFER_EXACT : DTA_TRANSFER_CONSERVATIVE;
}

static DtaTransferResult apply_arithmetic_transfer(RegShadow *rs, const RegShadow *snapshot, const InsnMeta *meta) {
	RegSlice dst = meta_first_reg_write(meta);
	if (!reg_slice_is_valid(dst)) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	if (meta->is_self_zeroing) {
		reg_slice_taint_clear(rs, dst);
		rs->src_ip[dst.reg_id] = 0;
		return DTA_TRANSFER_EXACT;
	}

	if (meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB) {
		reg_slice_taint_set(rs, dst, 0);
		return DTA_TRANSFER_CONSERVATIVE;
	}
	if (meta->reg_read_count == 0) {
		reg_slice_taint_set(rs, dst, 0);
		return DTA_TRANSFER_CONSERVATIVE;
	}
	for (uint8_t out_byte = 0; out_byte < dst.width; out_byte++) {
		bool tainted = false;
		for (uint8_t read_index = 0; read_index < meta->reg_read_count;read_index++) {
			RegSlice src = meta->reg_reads[read_index];
			if (!reg_slice_is_valid(src)) continue;
			uint8_t max_input = out_byte < src.width ? out_byte : (uint8_t)(src.width - 1);
			for (uint8_t in_byte = 0; in_byte <= max_input; in_byte++) {
				tainted |= snapshot_slice_byte(snapshot, src, in_byte);
			}
		}
		write_slice_byte(rs, dst, out_byte, tainted);
	}
	rs->src_ip[dst.reg_id] = 0;
	return DTA_TRANSFER_CONSERVATIVE;
}

static DtaTransferResult apply_shift_rotate_transfer( RegShadow *rs, const RegShadow *snapshot, const InsnMeta *meta) {
	RegSlice dst = meta_first_reg_write(meta);
	if (!reg_slice_is_valid(dst)) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	if (meta->insn_id == X86_INS_RCL || meta->insn_id == X86_INS_RCR) {
		reg_slice_taint_set(rs, dst, 0);
		return DTA_TRANSFER_CONSERVATIVE;
	}
	bool tainted = meta_read_state_has_taint(snapshot, meta);
	for (uint8_t i = 0; i < dst.width; i++) {
		write_slice_byte(rs, dst, i, tainted);
	}
	rs->src_ip[dst.reg_id] = 0;
	return DTA_TRANSFER_CONSERVATIVE;
}

static DtaTransferResult apply_unsupported_register_transfer(RegShadow *rs, const InsnMeta *meta) {
	uint32_t explicitly_written = 0;
	bool changed = false;
	for (uint8_t i = 0; i < meta->reg_write_count; i++) {
		RegSlice dst = meta->reg_writes[i];
		if (!reg_slice_is_valid(dst)) {
			continue;
		}
		reg_slice_taint_set(rs, dst, 0);
		explicitly_written |= 1U << dst.reg_id;
		changed = true;
	}
	for (int rid = 0; rid < REG_COUNT; rid++) {
		if (!(meta->regs_written_mask & (1U << rid)) ||
		    (explicitly_written & (1U << rid))) {
			continue;
		}
		reg_taint_set(rs, (RegId)rid, UINT8_MAX, 0);
		changed = true;
	}
	return changed ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_NOT_APPLICABLE;
}

DtaTransferResult dta_apply_reg_transfer(RegShadow *rs, const InsnMeta *meta) {
	if (!rs || !meta) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	if (meta->has_mem_read || meta->has_mem_write) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	RegShadow snapshot = *rs;

	switch (meta->family) {
	case DTA_FAMILY_DATA_MOVEMENT:
		return apply_data_movement(rs, &snapshot, meta);
	case DTA_FAMILY_LOGICAL:
		return apply_logical_transfer(rs, &snapshot, meta);
	case DTA_FAMILY_ARITHMETIC:
		return apply_arithmetic_transfer(rs, &snapshot, meta);
	case DTA_FAMILY_COMPARE:
		return DTA_TRANSFER_EXACT;
	case DTA_FAMILY_SHIFT_ROTATE:
		return apply_shift_rotate_transfer(rs, &snapshot, meta);
	case DTA_FAMILY_STACK: case DTA_FAMILY_STRING:
		return DTA_TRANSFER_NOT_APPLICABLE;

	case DTA_FAMILY_UNSUPPORTED: default:
		return apply_unsupported_register_transfer(rs, meta);
	}
}

static uint8_t dta_width_mask(uint8_t width) {
	if (width == 0) return 0;
	if (width >= MAX_REG_BYTES) return UINT8_MAX;

	return (uint8_t)((1U << width) - 1U);
}

static bool snapshot_address_mask_has_taint(const RegShadow *pre_regs, uint32_t address_reg_mask) {
	if (!pre_regs || address_reg_mask == 0) return false;
	for (int rid = 0; rid < REG_COUNT; rid++) {
		if (!(address_reg_mask & (1U << rid))) {
			continue;
		}
		for (uint8_t byte = 0; byte < MAX_REG_BYTES; byte++) {
			if (pre_regs->bytes[rid][byte]) {
				return true;
			}
		}
	}
	return false;
}

bool dta_address_mask_is_tainted(const RegShadow *pre_regs, uint32_t address_reg_mask) {
	return snapshot_address_mask_has_taint(pre_regs, address_reg_mask);
}

uint8_t dta_effective_mem_read_taint(const RegShadow *pre_regs, const InsnMeta *meta, uint8_t mem_taint_mask, uint8_t mem_width) {
	uint8_t valid_bytes = dta_width_mask(mem_width);
	uint8_t result = mem_taint_mask & valid_bytes;
	if (!pre_regs || !meta || valid_bytes == 0) {
		return result;
	}
	if (snapshot_address_mask_has_taint(pre_regs,meta->mem_read_addr_reg_mask)) {
		result = valid_bytes;
	}
	return result;
}

static uint8_t snapshot_reg_sources_taint(const RegShadow *pre_regs, const InsnMeta *meta, uint8_t width) {
	if (!pre_regs || !meta || width == 0) {
		return 0;
	}
	uint8_t result = 0;
	for (uint8_t read_index = 0; read_index < meta->reg_read_count; read_index++) {
		RegSlice source = meta->reg_reads[read_index];
		if (!reg_slice_is_valid(source)) continue;
		uint8_t copy_width = source.width < width ? source.width : width;
		for (uint8_t byte = 0; byte < copy_width; byte++) {
			uint8_t source_byte = (uint8_t)(source.byte_offset + byte);
			if (pre_regs->bytes[source.reg_id][source_byte]) {
				result |= (uint8_t)(1U << byte);
			}
		}
	}
	return result;
}

static uint8_t snapshot_slice_taint_mask(const RegShadow *pre_regs, RegSlice slice) {
	if (!pre_regs || !reg_slice_is_valid(slice)) {
		return 0;
	}
	uint8_t result = 0;
	for (uint8_t byte = 0; byte < slice.width; byte++) {
		uint8_t source_byte = (uint8_t)(slice.byte_offset + byte);
		if (pre_regs->bytes[slice.reg_id][source_byte]) {
			result |= (uint8_t)(1U << byte);
		}
	}
	return result;
}

static void write_slice_taint_mask(RegShadow *rs, RegSlice slice, uint8_t taint_mask) {
	if (!rs || !reg_slice_is_valid(slice)) {
		return;
	}
	for (uint8_t byte = 0; byte < slice.width; byte++) {
		uint8_t destination_byte = (uint8_t)(slice.byte_offset + byte);
		rs->bytes[slice.reg_id][destination_byte] = (taint_mask & (uint8_t)(1U << byte)) != 0;
	}
	rs->src_ip[slice.reg_id] = 0;
}

static uint8_t snapshot_accumulator_taint(const RegShadow *pre_regs, uint8_t width) {
	if (!pre_regs || width == 0 || width > MAX_REG_BYTES) {
		return 0;
	}
	uint8_t result = 0;
	for (uint8_t byte = 0; byte < width; byte++) {
		if (pre_regs->bytes[REG_RAX][byte]) {
			result |= (uint8_t)(1U << byte);
		}
	}
	return result;
}

static uint8_t prefix_dependency_taint(uint8_t input, uint8_t width) {
	uint8_t result = 0;
	bool lower_dependency = false;
	for (uint8_t byte = 0; byte < width; byte++) {
		lower_dependency |= (input & (uint8_t)(1U << byte)) != 0;
		if (lower_dependency) {
			result |= (uint8_t)(1U << byte);
		}
	}
	return result;
}

DtaTransferResult dta_apply_mem_read_transfer(RegShadow *rs, const RegShadow *pre_regs, const InsnMeta *meta, uint8_t mem_taint_mask, uint8_t mem_width) {
	if (!rs || !pre_regs || !meta || mem_width == 0 || mem_width > MAX_REG_BYTES) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	RegSlice dst = meta_first_reg_write(meta);
	if (!reg_slice_is_valid(dst)) {
		if (meta->family == DTA_FAMILY_UNSUPPORTED) {
			return apply_unsupported_register_transfer(rs, meta);
		}
		return DTA_TRANSFER_NOT_APPLICABLE;
	}

	bool address_tainted = snapshot_address_mask_has_taint(pre_regs, meta->mem_read_addr_reg_mask);
	uint8_t effective_mem_taint = dta_effective_mem_read_taint(pre_regs, meta, mem_taint_mask, mem_width);
	uint8_t destination_mask = dta_width_mask(dst.width);
	uint8_t destination_before = snapshot_slice_taint_mask(pre_regs, dst);
	uint8_t register_sources = snapshot_reg_sources_taint(pre_regs, meta, dst.width);
	switch (meta->family) {
		case DTA_FAMILY_DATA_MOVEMENT:
			switch (meta->insn_id) {
				case X86_INS_MOV:
					if (mem_width != dst.width) {
						reg_slice_taint_set(rs, dst, 0);
						return DTA_TRANSFER_CONSERVATIVE;
					}
					propagate_mem2reg(rs, dst, effective_mem_taint, mem_width, X86_INS_MOV, true);
					return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
				case X86_INS_MOVZX: case X86_INS_MOVSX:
					if (mem_width > dst.width) {
						reg_slice_taint_set(rs, dst, 0);
						return DTA_TRANSFER_CONSERVATIVE;
					}
					propagate_mem2reg(rs, dst, effective_mem_taint, mem_width, meta->insn_id, true);
					return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
				case X86_INS_XCHG:
					if (mem_width != dst.width) {
						reg_slice_taint_set(rs, dst, 0);
						return DTA_TRANSFER_CONSERVATIVE;
					}
					propagate_mem2reg(rs,dst, effective_mem_taint, mem_width, X86_INS_XCHG, true);
					return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
				default:
					reg_slice_taint_set(rs, dst, 0);
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_LOGICAL:
			if (mem_width != dst.width) {
				reg_slice_taint_set(rs, dst, 0);
				return DTA_TRANSFER_CONSERVATIVE;
			}
			switch (meta->insn_id) {
				case X86_INS_XOR: case X86_INS_AND: case X86_INS_OR:
					write_slice_taint_mask(rs, dst, (uint8_t)(destination_before | effective_mem_taint | register_sources));
					return DTA_TRANSFER_CONSERVATIVE;
				default:
					reg_slice_taint_set(rs, dst, 0);
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_ARITHMETIC:
			if (mem_width != dst.width) {
				reg_slice_taint_set(rs, dst, 0);
				return DTA_TRANSFER_CONSERVATIVE;
			}
			if (meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB) {
				reg_slice_taint_set(rs, dst, 0);
				return DTA_TRANSFER_CONSERVATIVE;
			}
			switch (meta->insn_id) {
				case X86_INS_ADD: case X86_INS_SUB: case X86_INS_INC: case X86_INS_DEC: case X86_INS_NEG:
					write_slice_taint_mask(rs, dst, prefix_dependency_taint((uint8_t)(destination_before | effective_mem_taint | register_sources), dst.width));
					return DTA_TRANSFER_CONSERVATIVE;
				default:
					reg_slice_taint_set(rs, dst, 0);
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_SHIFT_ROTATE:
			if ((destination_before | effective_mem_taint | register_sources) != 0) {
				write_slice_taint_mask(rs, dst, destination_mask);
			} else {
				write_slice_taint_mask(rs, dst, 0);
			}
			return DTA_TRANSFER_CONSERVATIVE;
		case DTA_FAMILY_STACK:
			if (meta->insn_id != X86_INS_POP || mem_width != dst.width) {
				return DTA_TRANSFER_NOT_APPLICABLE;
			}
			propagate_mem2reg(rs, dst, effective_mem_taint, mem_width, X86_INS_POP, true);
			return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
		case DTA_FAMILY_STRING:
			switch (meta->insn_id) {
				case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ: {
					if (meta->string_element_size == 0 || meta->string_element_size != mem_width || dst.reg_id != REG_RAX || dst.byte_offset != 0 || dst.width != mem_width) {
						return DTA_TRANSFER_NOT_APPLICABLE;
					}
					propagate_mem2reg(rs, dst, effective_mem_taint, mem_width, X86_INS_MOV, true);
					RegSlice source_index = reg_slice_from_x86(X86_REG_ESI, 4);
					uint8_t source_index_before = snapshot_slice_taint_mask(pre_regs, source_index);
					write_slice_taint_mask(rs,source_index, prefix_dependency_taint(source_index_before, 4));
					return address_tainted ? DTA_TRANSFER_CONSERVATIVE : DTA_TRANSFER_EXACT;
				}
				default:
					return DTA_TRANSFER_NOT_APPLICABLE;
			}
		case DTA_FAMILY_COMPARE:
			return DTA_TRANSFER_NOT_APPLICABLE;
		case DTA_FAMILY_UNSUPPORTED:
		default:
			return apply_unsupported_register_transfer(rs, meta);
	}
}

DtaTransferResult dta_compute_mem_write_taint(const RegShadow *pre_regs, const InsnMeta *meta, uint8_t old_mem_taint, bool source_mem_valid, uint8_t source_mem_taint, uint8_t width, uint8_t *result_taint) {
	if (!pre_regs || !meta || !result_taint || width == 0 || width > MAX_REG_BYTES) {
		return DTA_TRANSFER_NOT_APPLICABLE;
	}
	uint8_t valid_bytes = dta_width_mask(width);
	old_mem_taint &= valid_bytes;
	source_mem_taint &= valid_bytes;
	uint8_t reg_sources = snapshot_reg_sources_taint(pre_regs, meta, width);
	switch (meta->family) {
		case DTA_FAMILY_DATA_MOVEMENT:
			switch (meta->insn_id) {
				case X86_INS_MOV:
					//if imm - replace
					if (meta->has_imm_operand && meta->reg_read_count == 0) {
						*result_taint = 0;
						return DTA_TRANSFER_EXACT;
					}
					//mov [mem], reg
					if (meta->reg_read_count > 0) {
						*result_taint = reg_sources;
						return DTA_TRANSFER_EXACT;
					}
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
				case X86_INS_XCHG:
					if (meta->reg_read_count >0){
						*result_taint = reg_sources;
						return DTA_TRANSFER_EXACT;
					}
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
				default:
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_LOGICAL:
			switch (meta->insn_id) {
				case X86_INS_NOT:
					//just old taint
					*result_taint = old_mem_taint;
					return DTA_TRANSFER_EXACT;
				case X86_INS_XOR: case X86_INS_AND: case X86_INS_OR:
					//depends on old bytes
					if (meta->reg_read_count == 0 && !meta->has_imm_operand) {
						*result_taint = valid_bytes;
						return DTA_TRANSFER_CONSERVATIVE;
					}
					*result_taint = (uint8_t)(old_mem_taint | reg_sources);
					return DTA_TRANSFER_CONSERVATIVE;
				default:
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_ARITHMETIC:
			if (meta->insn_id == X86_INS_ADC || meta->insn_id == X86_INS_SBB) {
				*result_taint = valid_bytes;
				return DTA_TRANSFER_CONSERVATIVE;
			}
			if ((meta->insn_id == X86_INS_ADD || meta->insn_id== X86_INS_SUB) && meta->reg_read_count == 0 && !meta->has_imm_operand) {
				*result_taint = valid_bytes;
				return DTA_TRANSFER_CONSERVATIVE;
			}
			*result_taint = prefix_dependency_taint((uint8_t)(old_mem_taint | reg_sources),width);
			return DTA_TRANSFER_CONSERVATIVE;
		case DTA_FAMILY_SHIFT_ROTATE:
			if (meta->insn_id == X86_INS_RCL || meta->insn_id == X86_INS_RCR) {
				*result_taint = valid_bytes;
				return DTA_TRANSFER_CONSERVATIVE;
			}
			*result_taint = (old_mem_taint | reg_sources) != 0 ? valid_bytes : 0;
			return DTA_TRANSFER_CONSERVATIVE;
		case DTA_FAMILY_STACK:
			switch (meta->insn_id) {
				case X86_INS_CALL:
					*result_taint = 0;
					return DTA_TRANSFER_EXACT;
				case X86_INS_PUSHF: case X86_INS_PUSHFD: case X86_INS_PUSHFQ:
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
				case X86_INS_PUSH:
					if (meta->has_mem_read) {
						//push [mem]
						if (source_mem_valid) {
							*result_taint = source_mem_taint;
							return DTA_TRANSFER_EXACT;
						}
						*result_taint = valid_bytes;
						return DTA_TRANSFER_CONSERVATIVE;
					}
					if (meta->has_imm_operand) {
						//push imm
						*result_taint = 0;
						return DTA_TRANSFER_EXACT;
					}
					if (meta->reg_read_count > 0) {
						//push reg
						*result_taint = reg_sources;
						return DTA_TRANSFER_EXACT;
					}
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
				case X86_INS_POP:
					//pop [mem]
					if (source_mem_valid) {
						*result_taint = source_mem_taint;
						return DTA_TRANSFER_EXACT;
					}
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
				default:
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_STRING:
			switch (meta->insn_id) {
				case X86_INS_MOVSB: case X86_INS_MOVSW:case X86_INS_MOVSD: case X86_INS_MOVSQ:
					if (source_mem_valid) {
						*result_taint = source_mem_taint;
						return DTA_TRANSFER_EXACT;
					}
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
				case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ:
					*result_taint = snapshot_accumulator_taint(pre_regs,width);
					return DTA_TRANSFER_EXACT;
				default:
					*result_taint = valid_bytes;
					return DTA_TRANSFER_CONSERVATIVE;
			}
		case DTA_FAMILY_COMPARE:
			return DTA_TRANSFER_NOT_APPLICABLE;
		case DTA_FAMILY_UNSUPPORTED:
			default:
				*result_taint = valid_bytes;
				return DTA_TRANSFER_CONSERVATIVE;
	}
}

static GHashTable *g_meta_by_id = NULL;
static GHashTable *g_meta_latest_by_pc = NULL;
static MetaId g_next_meta_id = 1;
static GMutex g_meta_lock;
static bool g_meta_lock_initialized = false;

void meta_init(void) {
	if (g_meta_by_id || g_meta_latest_by_pc) return;
	g_mutex_init(&g_meta_lock);
	g_meta_lock_initialized = true;
	g_meta_by_id = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
	g_meta_latest_by_pc = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
	g_next_meta_id = 1;
}

void meta_free(void) {
	if (!g_meta_lock_initialized) return;
	g_mutex_lock(&g_meta_lock);
	if (g_meta_latest_by_pc) {
		g_hash_table_destroy(g_meta_latest_by_pc);
		g_meta_latest_by_pc = NULL;
	}
	if (g_meta_by_id) {
		g_hash_table_destroy(g_meta_by_id);
		g_meta_by_id = NULL;
	}
	g_next_meta_id = 1;
	g_mutex_unlock(&g_meta_lock);
	g_mutex_clear(&g_meta_lock);
	g_meta_lock_initialized = false;
}

const InsnMeta *meta_store(uint64_t pc, InsnMeta *meta) {
	if (!meta) return NULL;
	if (!g_meta_lock_initialized || meta->size == 0 || meta->size > MAX_INSN_BYTES) {
		g_free(meta);
		return NULL;
	}
	g_mutex_lock(&g_meta_lock);
	if (!g_meta_by_id || !g_meta_latest_by_pc) {
		g_mutex_unlock(&g_meta_lock);
		g_free(meta);
		return NULL;
	}
	gint64 pc_lookup_key = (gint64)pc;
	const InsnMeta *latest = g_hash_table_lookup(g_meta_latest_by_pc, &pc_lookup_key);
	if (latest && latest->size == meta->size && memcmp(latest->instr_bytes,meta->instr_bytes,meta->size)==0) {
		g_mutex_unlock(&g_meta_lock);
		g_free(meta);
		return latest;
	}
	if (g_next_meta_id == META_ID_INVALID) {
		g_mutex_unlock(&g_meta_lock);
		g_free(meta);
		return NULL;
	}

	meta->pc = pc;
	meta->meta_id = g_next_meta_id++;
	gint64 *id_key = g_new(gint64, 1);
	gint64 *pc_key = g_new(gint64, 1);
	*id_key = (gint64)meta->meta_id;
	*pc_key = (gint64)pc;

	g_hash_table_insert(g_meta_by_id, id_key, meta);
	g_hash_table_replace(g_meta_latest_by_pc, pc_key,meta);
	g_mutex_unlock(&g_meta_lock);
	return meta;
}

const InsnMeta *meta_lookup(uint64_t pc) {
	if (!g_meta_lock_initialized) return NULL;

	gint64 key = (gint64)pc;
	g_mutex_lock(&g_meta_lock);
	const InsnMeta *meta = g_meta_latest_by_pc ? g_hash_table_lookup(g_meta_latest_by_pc, &key) : NULL;
	g_mutex_unlock(&g_meta_lock);
	return meta;
}

const InsnMeta *meta_lookup_id(MetaId meta_id) {
	if (!g_meta_lock_initialized || meta_id == META_ID_INVALID) {
		return NULL;
	}
	gint64 key = (gint64)meta_id;
	g_mutex_lock(&g_meta_lock);
	const InsnMeta *meta = g_meta_by_id ? g_hash_table_lookup(g_meta_by_id, &key) : NULL;
	g_mutex_unlock(&g_meta_lock);
	return meta;
}

static bool same_reg_slice(const cs_x86_op *left, const cs_x86_op *right) {
	if (!left || !right || left->type != X86_OP_REG || right->type != X86_OP_REG) {
		return false;
	}
	if (left->size == 0 || left->size != right->size) {
		return false;
	}
	RegSlice left_slice = reg_slice_from_x86(left->reg, left->size);
	RegSlice right_slice = reg_slice_from_x86(right->reg, right->size);
	return reg_slice_equal(left_slice, right_slice);
}

static uint32_t x86_mem_address_reg_mask(const cs_x86_op *operand) {
	if (!operand || operand->type != X86_OP_MEM) {
		return 0;
	}
	uint32_t result = 0;
	int base = x86_reg_to_rid(operand->mem.base);
	int index = x86_reg_to_rid(operand->mem.index);
	if (base >= 0) {
		result |= 1U << base;
	}
	if (index >= 0) {
		result |= 1U << index;
	}
	return result;
}

static void append_reg_slice(RegSlice slices[MAX_INSN_REG_SLICES], uint8_t *count, RegSlice slice) {
	if (!count || !reg_slice_is_valid(slice)) {
		return;
	}
	for (uint8_t index = 0; index < *count; index++) {
		if (reg_slice_equal(slices[index], slice)) {
			return;
		}
	}
	if (*count >= MAX_INSN_REG_SLICES) return;
	slices[*count] = slice;
	(*count)++;
}

static DtaInsnFamily classify_x86_insn(uint16_t insn_id) {
	switch (insn_id) {
		case X86_INS_MOV: case X86_INS_MOVZX: case X86_INS_MOVSX: case X86_INS_LEA: case X86_INS_XCHG:
			return DTA_FAMILY_DATA_MOVEMENT;
		case X86_INS_XOR: case X86_INS_AND: case X86_INS_OR: case X86_INS_NOT:
			return DTA_FAMILY_LOGICAL;
		case X86_INS_ADD: case X86_INS_SUB: case X86_INS_ADC: case X86_INS_SBB: case X86_INS_INC: case X86_INS_DEC: case X86_INS_NEG:
			return DTA_FAMILY_ARITHMETIC;
		case X86_INS_CMP: case X86_INS_TEST:
			return DTA_FAMILY_COMPARE;
		case X86_INS_SHL: case X86_INS_SAL: case X86_INS_SHR: case X86_INS_SAR: case X86_INS_ROL: case X86_INS_ROR: case X86_INS_RCL: case X86_INS_RCR: case X86_INS_SHLD: case X86_INS_SHRD:
			return DTA_FAMILY_SHIFT_ROTATE;
		case X86_INS_PUSH: case X86_INS_POP: case X86_INS_PUSHF: case X86_INS_PUSHFD: case X86_INS_PUSHFQ: case X86_INS_PUSHAL: case X86_INS_POPAL: case X86_INS_ENTER: case X86_INS_LEAVE: case X86_INS_CALL: case X86_INS_RET:
			return DTA_FAMILY_STACK;
		case X86_INS_MOVSB: case X86_INS_MOVSW: case X86_INS_MOVSD: case X86_INS_MOVSQ: case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ: case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ:
			return DTA_FAMILY_STRING;
		default:
			return DTA_FAMILY_UNSUPPORTED;
	}
}

static X86ConditionCode x86_condition_code(uint16_t insn_id) {
	switch (insn_id) {
		case X86_INS_JO: case X86_INS_CMOVO: case X86_INS_SETO:
			return X86_CC_O;
		case X86_INS_JNO: case X86_INS_CMOVNO: case X86_INS_SETNO:
			return X86_CC_NO;
		case X86_INS_JB: case X86_INS_CMOVB: case X86_INS_SETB:
			return X86_CC_B;
		case X86_INS_JAE: case X86_INS_CMOVAE: case X86_INS_SETAE:
			return X86_CC_AE;
		case X86_INS_JE: case X86_INS_CMOVE: case X86_INS_SETE:
			return X86_CC_E;
		case X86_INS_JNE: case X86_INS_CMOVNE: case X86_INS_SETNE:
			return X86_CC_NE;
		case X86_INS_JBE: case X86_INS_CMOVBE: case X86_INS_SETBE:
			return X86_CC_BE;
		case X86_INS_JA: case X86_INS_CMOVA: case X86_INS_SETA:
			return X86_CC_A;
		case X86_INS_JS: case X86_INS_CMOVS: case X86_INS_SETS:
			return X86_CC_S;
		case X86_INS_JNS: case X86_INS_CMOVNS: case X86_INS_SETNS:
			return X86_CC_NS;
		case X86_INS_JP: case X86_INS_CMOVP: case X86_INS_SETP:
			return X86_CC_P;
		case X86_INS_JNP: case X86_INS_CMOVNP: case X86_INS_SETNP:
			return X86_CC_NP;
		case X86_INS_JL: case X86_INS_CMOVL: case X86_INS_SETL:
			return X86_CC_L;
		case X86_INS_JGE: case X86_INS_CMOVGE: case X86_INS_SETGE:
			return X86_CC_GE;
		case X86_INS_JLE: case X86_INS_CMOVLE: case X86_INS_SETLE:
			return X86_CC_LE;
		case X86_INS_JG: case X86_INS_CMOVG: case X86_INS_SETG:
			return X86_CC_G;
		default:
			return X86_CC_NONE;
	}
}

static uint8_t x86_condition_flag_mask(X86ConditionCode condition) {
	switch (condition) {
		case X86_CC_O: case X86_CC_NO:
			return X86_FLAG_OF;
		case X86_CC_B: case X86_CC_AE:
			return X86_FLAG_CF;
		case X86_CC_E: case X86_CC_NE:
			return X86_FLAG_ZF;
		case X86_CC_BE: case X86_CC_A:
			return X86_FLAG_CF | X86_FLAG_ZF;
		case X86_CC_S: case X86_CC_NS:
			return X86_FLAG_SF;
		case X86_CC_P: case X86_CC_NP:
			return X86_FLAG_PF;
		case X86_CC_L: case X86_CC_GE:
			return X86_FLAG_SF | X86_FLAG_OF;
		case X86_CC_LE: case X86_CC_G:
			return X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_OF;
		case X86_CC_NONE: default:
			return 0;
	}
}

static bool x86_is_conditional_branch(uint16_t insn_id) {
	switch (insn_id) {
		case X86_INS_JO: case X86_INS_JNO: case X86_INS_JB: case X86_INS_JAE: case X86_INS_JE: case X86_INS_JNE: case X86_INS_JBE: case X86_INS_JA: case X86_INS_JS: case X86_INS_JNS: case X86_INS_JP: case X86_INS_JNP: case X86_INS_JL: case X86_INS_JGE: case X86_INS_JLE: case X86_INS_JG:
			return true;
		default:
			return false;
	}
}

static uint8_t x86_written_flag_mask(uint16_t insn_id) {
	switch (insn_id) {
		case X86_INS_ADD: case X86_INS_ADC: case X86_INS_SUB: case X86_INS_SBB: case X86_INS_CMP: case X86_INS_NEG:
			return X86_FLAG_TRACKED;
		case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR: case X86_INS_TEST:
			return X86_FLAG_TRACKED;
		case X86_INS_INC: case X86_INS_DEC:
			return X86_FLAG_PF | X86_FLAG_AF | X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_OF;
		case X86_INS_SHL: case X86_INS_SAL: case X86_INS_SHR: case X86_INS_SAR: case X86_INS_SHLD: case X86_INS_SHRD:
			return X86_FLAG_TRACKED;
		case X86_INS_ROL: case X86_INS_ROR: case X86_INS_RCL: case X86_INS_RCR:
			return X86_FLAG_CF | X86_FLAG_OF;
		case X86_INS_IMUL: case X86_INS_MUL:
			return X86_FLAG_TRACKED;
		case X86_INS_DIV: case X86_INS_IDIV:
			return X86_FLAG_TRACKED;
		default:
			return 0;
	}
}

static bool x86_is_legacy_prefix(uint8_t byte) {
	switch (byte) {
		case 0xf0: case 0xf2: case 0xf3: case 0x2e: case 0x36: case 0x3e: case 0x26: case 0x64: case 0x65: case 0x66: case 0x67:
			return true;
		default:
			return false;
	}
}

static uint8_t x86_string_element_size(const cs_insn *insn) {
	if (!insn || insn->size == 0) {
		return 0;
	}
	bool operand_size_16 = false;
	bool rex_w = false;
	bool allow_rex = insn->id == X86_INS_MOVSQ || insn->id == X86_INS_STOSQ || insn->id == X86_INS_LODSQ;
	size_t opcode_index = 0;
	while (opcode_index < insn->size) {
		uint8_t byte = insn->bytes[opcode_index];
		if (byte == 0x66) {
			operand_size_16 = true;
		}
		if (allow_rex && (byte & 0xf8U) == 0x48U) {
			rex_w = true;
		}
		if (!x86_is_legacy_prefix(byte) && (!allow_rex || (byte & 0xf0U) != 0x40U)) {
			break;
		}
		opcode_index++;
	}
	if (opcode_index >= insn->size) {
		return 0;
	}
	switch (insn->bytes[opcode_index]) {
		case 0xa4: case 0xaa: case 0xac:
			return 1;
		case 0xa5: case 0xab: case 0xad:
			return rex_w ? 8 : (operand_size_16 ? 2 : 4);
		default:
			return 0;
	}
}

InsnMeta *meta_decode(const uint8_t *bytes, size_t size, uint64_t pc, csh handle) {
	if (!bytes || size == 0) return NULL;
	//disasm 1 instr and write it into hashtable
	cs_insn *insn;
	size_t count = cs_disasm(handle, bytes, size, pc, 1, &insn);
	if (count == 0) return NULL;
	if (insn->size == 0 || insn->size > MAX_INSN_BYTES || insn->size > size) {
		cs_free(insn, count);
		return NULL;
	}

	InsnMeta *m = g_new0(InsnMeta, 1);
	m->pc = pc;
	m->size = (uint8_t)insn->size;
	memcpy(m->instr_bytes, bytes, m->size);
	m->insn_id = insn->id;
	m->branch_target_reg = REG_INVALID;
	m->family = classify_x86_insn(insn->id);
	m->condition_code = x86_condition_code(insn->id);
	m->flags_read_mask =x86_condition_flag_mask(m->condition_code);
	m->flags_write_mask = x86_written_flag_mask(insn->id);
	m->is_conditional_branch = x86_is_conditional_branch(insn->id);
	m->string_element_size = x86_string_element_size(insn);
	if (m->family == DTA_FAMILY_STRING && m->string_element_size == 0) {
		m->family = DTA_FAMILY_UNSUPPORTED;
	}
	if (insn->detail) {
		//lookup on W/R flag
		cs_x86 *x86 = &insn->detail->x86;
		for (unsigned prefix_index = 0;prefix_index < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); prefix_index++) {
			if (x86->prefix[prefix_index] == 0xf2 || x86->prefix[prefix_index] == 0xf3) {
				m->has_rep_prefix = true;
			}
		}
		//clear taint for xor and sub
		if ((insn->id == X86_INS_XOR || insn->id == X86_INS_SUB) && x86->op_count == 2 && same_reg_slice(&x86->operands[0],&x86->operands[1])) {
			m->is_self_zeroing = true;
		}
		for (int i = 0; i < x86->op_count; i++) {
			cs_x86_op *op = &x86->operands[i];
			if (op->type == X86_OP_MEM) {
				uint32_t address_reg_mask = x86_mem_address_reg_mask(op);
				m->mem_addr_reg_mask |= address_reg_mask;
				if (op->access & CS_AC_READ) {
					m->has_mem_read = true;
					m->mem_read_addr_reg_mask |=address_reg_mask;
				}
				if (op->access & CS_AC_WRITE) {
					m->has_mem_write = true;
					m->mem_write_addr_reg_mask |= address_reg_mask;
				}
			} else if (op->type == X86_OP_IMM) {
				m->has_imm_operand = true;
			} else if (op->type == X86_OP_REG) {
				RegSlice slice =reg_slice_from_x86(op->reg,op->size);
				if (!reg_slice_is_valid(slice)) continue;
				if (op->access & CS_AC_WRITE) {
					m->regs_written_mask |= 1U << slice.reg_id;
					append_reg_slice(m->reg_writes, &m->reg_write_count, slice);
				}
				if (op->access & CS_AC_READ) {
					m->regs_read_mask |= 1U << slice.reg_id;
					append_reg_slice(m->reg_reads, &m->reg_read_count, slice);
				}
			}
		}
		if (insn->id == X86_INS_LEA) {
			m->has_mem_read = false;
			m->has_mem_write = false;
			m->mem_read_addr_reg_mask = 0;
			m->mem_write_addr_reg_mask = 0;
		}
		if (m->is_self_zeroing && m->reg_write_count == 0) {
			RegSlice dst =reg_slice_from_x86(x86->operands[0].reg,x86->operands[0].size);
			if (reg_slice_is_valid(dst)) {
				append_reg_slice(m->reg_writes, &m->reg_write_count, dst);
				m->regs_written_mask |= 1U << dst.reg_id;
			}
		}
		// Implicit regs
		// READ registers
		for (int i = 0; i < insn->detail->regs_read_count; i++) {
			int rid = x86_reg_to_rid(insn->detail->regs_read[i]);
			if (rid >= 0) {
				m->regs_read_mask |= (1U << rid);
			}
			if (insn->detail->regs_read[i] == X86_REG_EFLAGS && insn->id != X86_INS_INC && insn->id != X86_INS_DEC && m->flags_read_mask == 0) {
				m->flags_read_mask =X86_FLAG_TRACKED;
			}
		}
		//WRITE registers
		for (int i = 0; i < insn->detail->regs_write_count; i++) {
			int rid = x86_reg_to_rid(insn->detail->regs_write[i]);
			if (rid >= 0) {
				m->regs_written_mask |= (1U << rid);
			}
			if (insn->detail->regs_write[i] == X86_REG_EFLAGS && m->flags_write_mask == 0) {
				m->flags_write_mask = X86_FLAG_TRACKED;
			}
		}
		// implicit mem access
		switch (insn->id) {
			case X86_INS_PUSH:
				m->has_mem_write = true;
				m->mem_addr_reg_mask |= 1U << REG_RSP;
				m->mem_write_addr_reg_mask |= 1U << REG_RSP;
				if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {
					uint32_t source_address = x86_mem_address_reg_mask(&x86->operands[0]);
					m->has_mem_read = true;
					m->mem_addr_reg_mask |= source_address;
					m->mem_read_addr_reg_mask |= source_address;
				}
				break;
			case X86_INS_PUSHF: case X86_INS_PUSHFD: case X86_INS_PUSHFQ:
				m->has_mem_write = true;
				m->mem_addr_reg_mask |= UINT32_C(1) << REG_RSP;
				m->mem_write_addr_reg_mask |= UINT32_C(1) << REG_RSP;
				m->regs_read_mask |= UINT32_C(1) << REG_RSP;
				m->regs_written_mask |= UINT32_C(1) << REG_RSP;
				m->flags_read_mask |= X86_FLAG_TRACKED;
				break;
			case X86_INS_CALL:
				m->has_mem_write = true;
				m->mem_addr_reg_mask |= 1U << REG_RSP;
				m->mem_write_addr_reg_mask |= 1U << REG_RSP;
				if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {
					uint32_t source_address = x86_mem_address_reg_mask(&x86->operands[0]);
					m->has_mem_read = true;
					m->mem_addr_reg_mask |= source_address;
					m->mem_read_addr_reg_mask |= source_address;
				}
				break;
			case X86_INS_POP:
				m->has_mem_read = true;
				m->mem_addr_reg_mask |= 1U << REG_RSP;
				m->mem_read_addr_reg_mask |= 1U << REG_RSP;
				if (x86->op_count > 0 && x86->operands[0].type == X86_OP_MEM) {
					uint32_t destination_address = x86_mem_address_reg_mask(&x86->operands[0]);
					m->has_mem_write = true;
					m->mem_addr_reg_mask |= destination_address;
					m->mem_write_addr_reg_mask |= destination_address;
				}
				break;
			case X86_INS_RET:
				m->has_mem_read = true;
				m->mem_addr_reg_mask |= 1U << REG_RSP;
				m->mem_read_addr_reg_mask |= 1U << REG_RSP;
				break;
			case X86_INS_PUSHAL:
				m->has_mem_write = true;
				m->mem_addr_reg_mask |= 1U << REG_RSP;
				m->mem_write_addr_reg_mask |= 1U << REG_RSP;
				break;
			case X86_INS_POPAL:
				m->has_mem_read = true;
				m->mem_addr_reg_mask |= 1U << REG_RSP;
				m->mem_read_addr_reg_mask |= 1U << REG_RSP;
				break;
			case X86_INS_ENTER:
				m->has_mem_read = true;
				m->has_mem_write = true;
				m->mem_addr_reg_mask |= (1U << REG_RSP) | (1U << REG_RBP);
				m->mem_read_addr_reg_mask |= (1U << REG_RSP) | (1U << REG_RBP);
				m->mem_write_addr_reg_mask |= 1U << REG_RSP;
				break;
			case X86_INS_LEAVE:
				m->has_mem_read = true;
				m->mem_addr_reg_mask |= 1U << REG_RBP;
				m->mem_read_addr_reg_mask |= 1U << REG_RBP;
				break;
			case X86_INS_STOSB: case X86_INS_STOSW: case X86_INS_STOSD: case X86_INS_STOSQ:
				if (m->string_element_size != 0) {
					m->has_mem_write = true;
					m->mem_addr_reg_mask |= 1U << REG_RDI;
					m->mem_write_addr_reg_mask |= 1U << REG_RDI;
				}
				break;
			case X86_INS_LODSB: case X86_INS_LODSW: case X86_INS_LODSD: case X86_INS_LODSQ:
				if (m->string_element_size != 0) {
					m->has_mem_read = true;
					m->mem_addr_reg_mask |= UINT32_C(1) << REG_RSI;
					m->mem_read_addr_reg_mask |= UINT32_C(1) << REG_RSI;
					x86_reg accumulator = X86_REG_INVALID;
					switch (m->string_element_size) {
						case 1:
							accumulator = X86_REG_AL;
							break;
						case 2:
							accumulator = X86_REG_AX;
							break;
						case 4:
							accumulator = X86_REG_EAX;
							break;
						case 8:
							accumulator = X86_REG_RAX;
							break;
						default:
							break;
					}
					RegSlice accumulator_write = reg_slice_from_x86(accumulator,m->string_element_size);
					append_reg_slice(m->reg_writes, &m->reg_write_count, accumulator_write);
					m->regs_written_mask |= UINT32_C(1) << REG_RAX;
					RegSlice source_index = reg_slice_from_x86(X86_REG_ESI, 4);
					append_reg_slice(m->reg_reads, &m->reg_read_count, source_index);
					append_reg_slice(m->reg_writes, &m->reg_write_count, source_index);
					m->regs_read_mask |= UINT32_C(1) << REG_RSI;
					m->regs_written_mask |= UINT32_C(1) << REG_RSI;
				}
				break;
			default:
				break;
		}
		//movs mem, mem
		if (m->string_element_size != 0 && (insn->id == X86_INS_MOVSB || insn->id == X86_INS_MOVSW || insn->id == X86_INS_MOVSD || insn->id == X86_INS_MOVSQ)) {
			m->has_mem_read = true;
			m->has_mem_write = true;
			m->mem_addr_reg_mask |= (1U << REG_RSI) | (1U << REG_RDI);
			m->mem_read_addr_reg_mask |= 1U << REG_RSI;
			m->mem_write_addr_reg_mask |= 1U << REG_RDI;
		}
		//indirect jumps/calls/rets
		if (insn->id == X86_INS_RET) {
			m->is_indirect_branch = true;
			m->branch_target_reg = REG_INVALID;
		} else if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
			if (x86->op_count > 0) {
				if (x86->operands[0].type == X86_OP_REG) {
					m->is_indirect_branch = true;
					m->branch_target_reg = x86_reg_to_rid(x86->operands[0].reg);
				} else if (x86->operands[0].type == X86_OP_MEM) {
					uint32_t target_address = x86_mem_address_reg_mask(&x86->operands[0]);
					m->is_indirect_branch = true;
					m->branch_target_reg = REG_INVALID;
					m->has_mem_read = true;
					m->mem_addr_reg_mask |= target_address;
					m->mem_read_addr_reg_mask |= target_address;
				}
			}
		}
	}
	cs_free(insn, count);
	return m;
}
