#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"
#include "dse.h"

static bool is_high_byte(x86_reg r) {
	return r == X86_REG_AH || r == X86_REG_BH || r == X86_REG_CH || r == X86_REG_DH;
}

//processing of all types from the disassembler
static SymExpr *get_operand_expr(DSECtx *ctx, const cs_x86_op *op, uint32_t want_w, const InsnAux *aux, const DseArch *arch) {
	if (op->type == X86_OP_REG) {
		int rid = x86_reg_to_rid(op->reg);
		if (rid < 0) return NULL;
		
		uint32_t operand_width = op->size != 0 ? (uint32_t)op->size * 8 : want_w;
		uint32_t low_bit = is_high_byte(op->reg) ? 8 : 0;

		SymExpr *value = dse_read_rid_slice(ctx, aux, rid, low_bit, operand_width, arch->natural_width);
		if (!value) return NULL;
		if (value->width < want_w) {
			value = sym_expr_zext(value, want_w);
		} else if (value->width > want_w) {
			value = sym_expr_extract(value,0, want_w);
		}
		return value;
	}
	if (op->type == X86_OP_IMM)
		return sym_expr_const((uint64_t)(int64_t)op->imm, op->size ? (uint32_t)op->size * 8 : want_w);
	if (op->type == X86_OP_MEM)
		return dse_load_mem(ctx, aux, want_w, arch->big_endian);
	return NULL;
}
//write symexpr to register
static bool commit_reg(DSECtx *ctx, const InsnAux *aux, const DseArch *arch, x86_reg dreg, SymExpr *val, uint32_t w) {
	int rid = x86_reg_to_rid(dreg);
	if (rid < 0) {
		sym_expr_free(val);
		return false;
	}
	if (!val) {
		sym_state_set_reg(&ctx->state, rid, NULL);
		return false;
	}
	uint32_t low_bit = is_high_byte(dreg) ? 8 : 0;

	return dse_commit_slice(ctx, aux, rid, val, low_bit, w, arch->natural_width);
}
//work with operands
static bool commit_operand( DSECtx *ctx, const InsnAux *aux, const DseArch *arch, const cs_x86_op *destination, SymExpr *value, uint32_t width) {
	if (!destination || !value) {
		sym_expr_free(value);
		return false;
	}
	if (value->width < width) {
		value = sym_expr_zext(value, width);
	} else if (value->width > width) {
		value = sym_expr_extract(value, 0, width);
	}
	if (!value) {
		return false;
	}

	if (destination->type == X86_OP_REG) {
		return commit_reg(ctx, aux, arch, destination->reg, value, width);
	}
	if (destination->type == X86_OP_MEM) {
		if (!aux || !aux->has_mem_write) {
			sym_expr_free(value);
			return false;
		}
		dse_store_mem(ctx, aux, value, arch->big_endian);
		return true;
	}
	sym_expr_free(value);
	return false;
}
//lifter for mov inst
static bool lift_mov(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count != 2) return false;
	const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
	uint32_t w = (uint32_t)dst->size * 8;
	SymExpr *src_e = get_operand_expr(ctx, src, (uint32_t)src->size * 8, aux, arch);
	if (!src_e) {
		return false;
	} else {
		uint8_t sw = src_e->width;
		if (sw < w) {
			src_e = (insn->id == X86_INS_MOVSX) ? sym_expr_sext(src_e, w) : sym_expr_zext(src_e, w);
		} else if (sw > w) { 
			src_e = sym_expr_extract(src_e, 0, w);
		}
	}
	return commit_operand(ctx, aux, arch, dst, src_e,w);
}

static bool shift_or_rotate(unsigned int instruction_id){
	switch (instruction_id) {
		case X86_INS_SHL: case X86_INS_SAL: case X86_INS_SHR: case X86_INS_SAR: case X86_INS_ROL: case X86_INS_ROR:
			return true;
		default:
			return false;
	}
}

static SymExpr *mask_x86_shift_count(SymExpr *count, uint32_t operand_width) {
	if (!count) return NULL;
	uint64_t mask = operand_width == 64 ? 0x3f : 0x1f;
	return sym_expr_and(count,sym_expr_const(mask,count->width));
}

//lifter for arithmetics
static bool lift_arith(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count < 2) return false;
	const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
	if (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) return false;
	uint32_t w = (uint32_t)dst->size * 8;
	if (w == 0) return false;
	SymExpr *dst_e = get_operand_expr(ctx, dst, w, aux, arch);
	uint32_t source_width = w;
	if (shift_or_rotate(insn->id) && src->size != 0) {
		source_width = (uint32_t)src->size * 8;
	}
	SymExpr *src_e =get_operand_expr(ctx, src,source_width, aux, arch);
	if (shift_or_rotate(insn->id)) {
		src_e = mask_x86_shift_count(src_e, w);
	}
	if (!dst_e || !src_e) {
		sym_expr_free(dst_e);
		sym_expr_free(src_e);
		return false;
	}
	SymExpr *res = NULL;
	switch (insn->id) {
		case X86_INS_ADD: res = sym_expr_add(dst_e, src_e); break;
		case X86_INS_SUB: res = sym_expr_sub(dst_e, src_e); break;
		case X86_INS_XOR: res = sym_expr_xor(dst_e, src_e); break;
		case X86_INS_AND: res = sym_expr_and(dst_e, src_e); break;
		case X86_INS_OR:  res = sym_expr_or (dst_e, src_e); break;
		case X86_INS_SHL: case X86_INS_SAL: res = sym_expr_shl(dst_e, src_e); break;
		case X86_INS_SHR: res = sym_expr_shr(dst_e, src_e); break;
		case X86_INS_SAR: res = sym_expr_sar(dst_e, src_e); break;
		case X86_INS_ROL: res = sym_expr_rol(dst_e, src_e); break;
		case X86_INS_ROR: res = sym_expr_ror(dst_e, src_e); break;
		default:
			sym_expr_free(dst_e);
			sym_expr_free(src_e);
			return false;
	}
	return commit_operand(ctx, aux, arch, dst, res, w);
}
//lifter for unary
static bool lift_unary(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count != 1) return false;
	const cs_x86_op *dst = &x86->operands[0];
	if (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) return false;
	uint32_t w = (uint32_t)dst->size * 8;
	if (w==0 ) return false;
	SymExpr *e = get_operand_expr(ctx, dst, w, aux, arch);
	if (!e) return false;
	SymExpr *res;
	switch (insn->id) {
		case X86_INS_NOT:
			res = sym_expr_not(e);
			break;
		case X86_INS_NEG:
			res = sym_expr_neg(e);
			break;
		case X86_INS_INC:
			res = sym_expr_add(e, sym_expr_const(1, w));
			break;
		case X86_INS_DEC:
			res = sym_expr_sub(e, sym_expr_const(1, w));
			break;
		default:
			sym_expr_free(e);
			return false;
	}
	return commit_operand(ctx, aux, arch, dst, res, w);
}
//lifter for lua
static bool lift_lea(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)insn;
	if (x86->op_count != 2) return false;
	const cs_x86_op *dst = &x86->operands[0], *m = &x86->operands[1];
	if (dst->type != X86_OP_REG || m->type != X86_OP_MEM) return false;
	uint32_t natw = arch->natural_width;
	SymExpr *addr = NULL;
	if (m->mem.base != X86_REG_INVALID) {
		int rid = x86_reg_to_rid(m->mem.base);
		if (rid >= 0) addr = dse_read_rid_fit(ctx, aux, rid, natw, natw);
	}
	if (m->mem.index != X86_REG_INVALID) {
		int ridx = x86_reg_to_rid(m->mem.index);
		if (ridx >= 0) {
			SymExpr *ix = dse_read_rid_fit(ctx, aux, ridx, natw, natw);
			uint8_t sh = (m->mem.scale == 2) ? 1 : (m->mem.scale == 4) ? 2 : (m->mem.scale == 8) ? 3 : 0;
			if (sh) ix = sym_expr_shl(ix, sym_expr_const(sh, natw));
			addr = addr ? sym_expr_add(addr, ix) : ix;
		}
	}
	if (m->mem.disp) {
		SymExpr *d = sym_expr_const((uint64_t)(int64_t)m->mem.disp, natw);
		addr = addr ? sym_expr_add(addr, d) : d;
	}
	if (!addr) addr = sym_expr_const(0, natw);
	return commit_reg(ctx, aux, arch, dst->reg, addr, natw);
}
//lifter for imul
static bool lift_imul(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)insn;
	if (x86->op_count ==2) {
		const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
		if (dst->type != X86_OP_REG) return false;
		uint32_t w = (uint32_t)dst->size * 8;
		SymExpr *a = get_operand_expr(ctx, dst, w, aux, arch);
		SymExpr *b = get_operand_expr(ctx, src, w, aux, arch);
		if (!a || !b) {
			sym_expr_free(a);
			sym_expr_free(b);
			return commit_reg(ctx, aux, arch, dst->reg, NULL, w);
		}
		return commit_reg(ctx, aux, arch, dst->reg, sym_expr_mul(a, b), w);
	}
	if (x86->op_count == 3) {
		const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1], *imm = &x86->operands[2];
		if (dst->type != X86_OP_REG || imm->type != X86_OP_IMM) return false;
		uint32_t w = (uint32_t)dst->size * 8;
		SymExpr *a = get_operand_expr(ctx, src, w, aux, arch);
		SymExpr *b = sym_expr_const((uint64_t)(int64_t)imm->imm, w);
		if (!a) {
			sym_expr_free(b);
			return commit_reg(ctx, aux, arch, dst->reg, NULL, w);
		}
		return commit_reg(ctx, aux, arch, dst->reg, sym_expr_mul(a, b), w);
	}
	return false;
}

//lifter for push
static bool lift_push(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)insn;
	if (x86->op_count != 1 || !aux || !aux->has_mem_write || arch->natural_width != 32) {
		return false;
	}

	const cs_x86_op *src =&x86->operands[0];
	if (src->type != X86_OP_REG && src->type != X86_OP_IMM && src->type != X86_OP_MEM) {
		return false;
	}

	bool operand_size_16 = false;
	for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
		if (x86->prefix[i] == 0x66) {
			operand_size_16 = true;
			break;
		}
	}
	uint32_t pointer_width = arch->natural_width;
	uint32_t pushed_width = operand_size_16 ? 16u : 32u;
	uint32_t pushed_bytes = pushed_width / 8u;
	uint32_t source_width = src->size != 0 ? (uint32_t)src->size * 8u : pushed_width;

	SymExpr *value = get_operand_expr( ctx, src, source_width, aux, arch);
	if (!value) return false;

	if (value->width < pushed_width) {
		if (src->type == X86_OP_IMM) {
			value = sym_expr_sext(value, pushed_width);
		} else {
			value = sym_expr_zext(value, pushed_width);
		}
	} else if (value->width > pushed_width) {
		value = sym_expr_extract(value, 0, pushed_width);
	}
	if (!value) return false;

	SymExpr *old_stack_pointer = dse_read_rid_fit(ctx, aux, REG_RSP, pointer_width, pointer_width);
	if (!old_stack_pointer) {
		sym_expr_free(value);
		return false;
	}
	SymExpr *new_stack_pointer = sym_expr_sub(old_stack_pointer, sym_expr_const(pushed_bytes, pointer_width));
	if (!new_stack_pointer) {
		sym_expr_free(value);
		return false;
	}
	dse_store_mem(ctx, aux, value, arch->big_endian);
	dse_set_reg(ctx, REG_RSP, new_stack_pointer, pointer_width);

	return true;
}

//lifter for pop
static bool lift_pop(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)insn;
	if (x86->op_count != 1 || !aux || !aux->has_mem_read || arch->natural_width != 32) {
		return false;
	}

	const cs_x86_op *dst = &x86->operands[0];
	if (dst->type != X86_OP_REG && dst->type != X86_OP_MEM) {
		return false;
	}
	if (dst->type == X86_OP_MEM && !aux->has_mem_write) {
		return false;
	}

	bool operand_size_16 = false;
	for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
		if (x86->prefix[i] == 0x66) {
			operand_size_16 = true;
			break;
		}
	}

	uint32_t pointer_width = arch->natural_width;
	uint32_t popped_width = operand_size_16 ? 16u : 32u;
	uint32_t popped_bytes = popped_width / 8u;
	if (dst->size != 0 && (uint32_t)dst->size * 8u != popped_width) {
		return false;
	}

	SymExpr *value = dse_load_mem(ctx, aux, popped_width, arch->big_endian);
	if (!value) return false;
	SymExpr *old_stack_pointer = dse_read_rid_fit(ctx, aux, REG_RSP, pointer_width, pointer_width);
	if (!old_stack_pointer) {
		sym_expr_free(value);
		return false;
	}
	SymExpr *new_stack_pointer = sym_expr_add(old_stack_pointer, sym_expr_const(popped_bytes,pointer_width));
	if (!new_stack_pointer) {
		sym_expr_free(value);
		return false;
	}
	
	dse_set_reg(ctx, REG_RSP, new_stack_pointer,pointer_width);
	return commit_operand(ctx,aux,arch,dst,value,popped_width);
}
//lifter leave
static bool lift_leave(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (!ctx || !x86 || !aux || !aux->has_mem_read || arch->natural_width != 32 || x86->op_count != 0) {
		return false;
	}

	bool operand_size_16 = false;
	bool address_size_16 = false;
	for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
		if (x86->prefix[i] == 0x66) {
			operand_size_16 = true;
		}
		if (x86->prefix[i] == 0x67) {
			address_size_16 = true;
		}
	}
	if (address_size_16) return false;

	uint32_t popped_width = operand_size_16 ? 16u : 32u;
	uint32_t popped_bytes = popped_width / 8u;
	
	SymExpr *old_frame_pointer = dse_read_rid_fit(ctx, aux, REG_RBP, 32, 32);
	if (!old_frame_pointer) return false;
	
	SymExpr *restored_frame_pointer = dse_load_mem(ctx, aux,popped_width, arch->big_endian);
	if (!restored_frame_pointer) {
		sym_expr_free(old_frame_pointer);
		return false;
	}

	SymExpr *new_stack_pointer = sym_expr_add(old_frame_pointer, sym_expr_const(popped_bytes,32));
	if (!new_stack_pointer) {
		sym_expr_free(restored_frame_pointer);
		return false;
	}
	dse_set_reg( ctx, REG_RSP, new_stack_pointer, 32);

	if (operand_size_16) {
		return commit_reg(ctx, aux, arch, X86_REG_BP, restored_frame_pointer, 16);
	}
	dse_set_reg(ctx, REG_RBP, restored_frame_pointer,32);

	return true;
}
//lifter xchg
static bool lift_xchg(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)insn;
	if (x86->op_count != 2) {
		return false;
	}

	const cs_x86_op *left = &x86->operands[0];
	const cs_x86_op *right = &x86->operands[1];

	if ((left->type != X86_OP_REG &&left->type != X86_OP_MEM) ||(right->type != X86_OP_REG && right->type != X86_OP_MEM)) {
		return false;
	}

	uint32_t left_width =(uint32_t)left->size * 8;
	uint32_t right_width =(uint32_t)right->size * 8;

	if (left_width == 0 || left_width != right_width) {
		return false;
	}

	SymExpr *left_value =get_operand_expr( ctx, left, left_width, aux, arch);
	SymExpr *right_value = get_operand_expr(ctx, right, right_width, aux, arch);
	if (!left_value || !right_value) {
		sym_expr_free(left_value);
		sym_expr_free(right_value);
		return false;
	}

	if (!commit_operand(ctx, aux, arch, left, right_value, left_width)) {
		sym_expr_free(left_value);
		return false;
	}
	if (!commit_operand(ctx,aux, arch, right, left_value, right_width)) {
		return false;
	}

	return true;
}
//lifter jmp
static bool lift_jmp(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)ctx;
	(void)insn;
	(void)aux;
	(void)arch;
	if (x86->op_count != 1) return false;
	return x86->op_count == 1;
}
//lifter call
static bool lift_call(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count != 1 || !aux ||!aux->has_mem_write || arch->natural_width != 32) {
		return false;
	}

	const cs_x86_op *target = &x86->operands[0];
	if (target->type != X86_OP_IMM && target->type != X86_OP_REG && target->type != X86_OP_MEM) {
		return false;
	}

	bool operand_size_16 = false;
	for (unsigned i = 0;i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
		if (x86->prefix[i] == 0x66) {
			operand_size_16 = true;
			break;
		}
	}
	uint32_t pointer_width =arch->natural_width;
	uint32_t pushed_width = operand_size_16 ? 16u : 32u;
	uint32_t pushed_bytes = pushed_width / 8u;
	SymExpr *old_stack_pointer = dse_read_rid_fit(ctx, aux, REG_RSP, pointer_width, pointer_width);
	if (!old_stack_pointer)	return false;
	SymExpr *new_stack_pointer = sym_expr_sub(old_stack_pointer, sym_expr_const(pushed_bytes,pointer_width));
	if (!new_stack_pointer) return false;
	SymExpr *return_address = sym_expr_const( insn->address + insn->size, pushed_width);
	if (!return_address) {
		sym_expr_free(new_stack_pointer);
		return false;
	}
	dse_store_mem(ctx, aux, return_address, arch->big_endian);
	dse_set_reg(ctx, REG_RSP, new_stack_pointer, pointer_width);

	return true;
}
//lifter ret
static bool lift_ret(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	(void)insn;
	if (x86->op_count > 1 || arch->natural_width != 32) return false;
	bool operand_size_16 = false;
	for (unsigned i = 0; i < (sizeof(x86->prefix) / sizeof(x86->prefix[0])); i++) {
		if (x86->prefix[i] == 0x66) {
			operand_size_16 = true;
			break;
		}
	}
	uint32_t pointer_width =arch->natural_width;
	uint32_t popped_width = operand_size_16 ? 16u : 32u;
	uint64_t increment = popped_width / 8u;
	if (x86->op_count == 1) {
		const cs_x86_op *immediate = &x86->operands[0];
		if (immediate->type != X86_OP_IMM) return false;
		increment += (uint16_t)immediate->imm;
	}
	SymExpr *old_stack_pointer = dse_read_rid_fit(ctx, aux, REG_RSP, pointer_width, pointer_width);
	if (!old_stack_pointer) return false;
	SymExpr *new_stack_pointer = sym_expr_add(old_stack_pointer,sym_expr_const(increment, pointer_width));
	if (!new_stack_pointer) return false;
	dse_set_reg(ctx, REG_RSP, new_stack_pointer, pointer_width);

	return true;
}
//convert word group
static bool lift_cbw(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
	int accumulator_rid =x86_reg_to_rid(X86_REG_EAX);
	if (accumulator_rid < 0) return false;

	SymExpr *al = dse_read_rid_slice(ctx, aux, accumulator_rid, 0, 8, arch->natural_width);
	if (!al) return false;
	SymExpr *ax = sym_expr_sext(al, 16);
	if (!ax) return false;

	return commit_reg(ctx, aux, arch, X86_REG_AX, ax, 16);
}
static bool lift_cwd(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
	int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
	if (accumulator_rid < 0) return false;
	SymExpr *ax = dse_read_rid_slice(ctx, aux, accumulator_rid, 0, 16, arch->natural_width);
	if (!ax) return false;
	SymExpr *dx = sym_expr_sar(ax, sym_expr_const(15,16));
	if (!dx) return false;

	return commit_reg(ctx, aux, arch, X86_REG_DX, dx, 16);
}
static bool lift_cwde(DSECtx *ctx, const InsnAux *aux, const DseArch *arch){
	int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
	if (accumulator_rid < 0) return false;
	SymExpr *ax = dse_read_rid_slice(ctx,aux, accumulator_rid, 0, 16, arch->natural_width);
	if (!ax) return false;
	SymExpr *eax = sym_expr_sext( ax, 32);
	if (!eax) return false;

	return commit_reg(ctx, aux, arch, X86_REG_EAX, eax, 32);
}
static bool lift_cdq(DSECtx *ctx, const InsnAux *aux, const DseArch *arch) {
	int accumulator_rid = x86_reg_to_rid(X86_REG_EAX);
	if (accumulator_rid < 0) return false;
	SymExpr *eax = dse_read_rid_slice( ctx, aux, accumulator_rid, 0, 32, arch->natural_width);
	if (!eax) return false;
	SymExpr *edx = sym_expr_sar(eax, sym_expr_const(31, 32));
	if (!edx) return false;

	return commit_reg(ctx, aux, arch, X86_REG_EDX, edx, 32);
}
//all in one
static bool x86_lift_one(DSECtx *ctx, const cs_insn *insn, const InsnAux *aux, const DseArch *arch) {
	const cs_x86 *x86 = &insn->detail->x86;
	switch (insn->id) {
		case X86_INS_MOV: case X86_INS_MOVZX: case X86_INS_MOVSX:
			return lift_mov(ctx, insn, x86, aux, arch);
		case X86_INS_LEA:
			return lift_lea(ctx, insn, x86, aux, arch);
		case X86_INS_ADD: case X86_INS_SUB: case X86_INS_XOR: case X86_INS_AND: case X86_INS_OR:  case X86_INS_SHL: case X86_INS_SAL: case X86_INS_SHR: case X86_INS_SAR: case X86_INS_ROL: case X86_INS_ROR:
			return lift_arith(ctx, insn, x86, aux, arch);
		case X86_INS_NOT: case X86_INS_NEG: case X86_INS_INC: case X86_INS_DEC:
			return lift_unary(ctx, insn, x86, aux, arch);
		case X86_INS_IMUL:
			return lift_imul(ctx, insn, x86, aux, arch);
		case X86_INS_PUSH:
			return lift_push(ctx, insn, x86, aux, arch);
		case X86_INS_POP:
			return lift_pop(ctx, insn, x86, aux, arch);
		case X86_INS_LEAVE:
			return lift_leave(ctx, insn, x86, aux, arch);
		case X86_INS_XCHG:
			return lift_xchg(ctx,insn, x86, aux, arch);
		case X86_INS_NOP:
			return true;
		case X86_INS_JMP:
			return lift_jmp(ctx, insn, x86, aux, arch);
		case X86_INS_CALL:
			return lift_call(ctx, insn, x86, aux, arch);
		case X86_INS_RET:
			return lift_ret(ctx, insn, x86, aux, arch);
		case X86_INS_CBW:
			return lift_cbw(ctx, aux, arch);
		case X86_INS_CWDE:
			return lift_cwde(ctx, aux, arch);
		case X86_INS_CWD:
			return lift_cwd(ctx, aux, arch);
		case X86_INS_CDQ:
			return lift_cdq(ctx, aux, arch);
		default:
			return false; //unhandled case
	}
}

const DseArch dse_arch_x86 = {
	.name          = "i386",
	.natural_width = 32,
	.big_endian    = false,
	.reg_to_rid    = x86_reg_to_rid,
	.lift_one      = x86_lift_one,
};
