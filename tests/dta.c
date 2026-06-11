#include "dta.h"
#include<stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <glib.h>

#define page_size 4096

struct ShadowMemory {
	uint8_t  arch;
	void    *base;
	size_t   size;
};


ShadowMemory *shadow_create(uint8_t arch) {
	if (arch == 32) {
		ShadowMemory *sm = malloc(sizeof(ShadowMemory));
		size_t size = 1ULL << 32;
		void *base = mmap(NULL, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (base == MAP_FAILED) {
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
	munmap(sm->base, sm->size);
	free(sm);
}

void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip) {
	(void)ip;
	if (sm->arch == 32) { //IMPLEMENT NOT IN DTA CODE!!!!!!!!!!1
		addr &= 0xFFFFFFFFULL;
	} else {
		//TODO
	}
	mprotect((char*)sm->base + (addr & ~(page_size - 1)), page_size, 3);
	*((uint8_t *)sm->base + addr) = 1;
}

void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr) {
	*((uint8_t *)sm->base + addr) = 0;
}

bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr) {
	return *((uint8_t *)sm->base + addr) != 0;
}

bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr) { //TODO optimize
	uint8_t *base = (uint8_t*)sm->base;
	for(uint64_t i = addr & ~(page_size -1); i < (addr & ~(page_size - 1)) + page_size; i++) {
		if (base[i]) return true;
	}
	return false;
}

static int x86_reg_to_regid(x86_reg reg) {
	switch (reg) {
		case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH:
			return REG_RAX;
		case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH:
			return REG_RCX;
		case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH:
			return REG_RDX;
		case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH:
			return REG_RBX;
		case X86_REG_ESP: case X86_REG_SP:
			return REG_RSP;
		case X86_REG_EBP: case X86_REG_BP:
			return REG_RBP;
		case X86_REG_ESI: case X86_REG_SI:
			return REG_RSI;
		case X86_REG_EDI: case X86_REG_DI:
			return REG_RDI;
		default:
			return -1;
	}
}

static GHashTable *g_meta_table = NULL;

void meta_init(void) {
	g_meta_table = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
}

void meta_free(void) {
	if (g_meta_table) {
		g_hash_table_destroy(g_meta_table);
		g_meta_table = NULL;
	}
}

void meta_store(uint64_t pc, InsnMeta *meta) {
	g_hash_table_insert(g_meta_table, GUINT_TO_POINTER(pc), meta);
}

InsnMeta *meta_lookup(uint64_t pc) {
	return g_hash_table_lookup(g_meta_table, GUINT_TO_POINTER(pc));
}

InsnMeta *meta_decode(const uint8_t *bytes, size_t size, uint64_t pc, csh handle) {
	//disasm 1 instr and write it into hashtable
	cs_insn *insn;
	size_t count = cs_disasm(handle, bytes, size, pc, 1, &insn);
	if (count == 0) return NULL;

	InsnMeta *m = g_new0(InsnMeta, 1);
	m->pc = pc;
	m->size = size;
	m->insn_id = insn->id;
	if (insn->detail) {
		//lookup on W/R flag
		cs_x86 *x86 = &insn->detail->x86;
		for (int i = 0; i < x86->op_count; i++) {
			cs_x86_op *op = &x86->operands[i];
			if (op->type == X86_OP_MEM) {
				if (op->access & CS_AC_READ) m->has_mem_read = true;
				if (op->access & CS_AC_WRITE) m->has_mem_write = true;
			}
		}
		// Implicit regs
		// READ registers
		for (int i = 0; i < insn->detail->regs_read_count; i++) {
			int rid = x86_reg_to_regid(insn->detail->regs_read[i]);
			if (rid >= 0) {
				m->regs_read_mask |= (1U << rid);
			}
		}
		//WRITE registers
		for (int i = 0; i < insn->detail->regs_write_count; i++) {
			int rid = x86_reg_to_regid(insn->detail->regs_write[i]);
			if (rid >= 0) {
				m->regs_written_mask |= (1U << rid);
			}
		}
		// Explicit
		//mask for W/R the register
		for (int i = 0; i < x86->op_count; i++) {
			 cs_x86_op *op = &x86->operands[i];
			 if (op->type == X86_OP_REG) {
				 int rid = x86_reg_to_regid(op->reg);
				 if (rid >= 0) {
					 if (op->access & CS_AC_READ) {
						 m->regs_read_mask |= (1U << rid);
					 }
					 if (op->access & CS_AC_WRITE) {
						 m->regs_written_mask |= (1U << rid);
					 }
				 }
			 }
		}
		//indirect jumps/calls/rets
		if (insn->id == X86_INS_RET) {
			m->is_indirect_branch = true;
			m->branch_target_reg = REG_INVALID;
		} else if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL) {
			if (x86->op_count > 0) {
				if (x86->operands[0].type == X86_OP_REG) {
					m->is_indirect_branch = true;
					m->branch_target_reg = x86_reg_to_regid(x86->operands[0].reg);
				} else if (x86->operands[0].type == X86_OP_MEM) {
					m->is_indirect_branch = true;
					m->branch_target_reg = REG_INVALID;
				}
			}
		}
	}
	cs_free(insn, count);
	return m;
}
