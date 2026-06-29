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
		return (rid < 0) ? NULL : dse_read_rid_fit(ctx, aux, rid, want_w, arch->natural_width);
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
	uint32_t natw = arch->natural_width;
	if (!val) {
		sym_state_set_reg(&ctx->state, rid, NULL);
		return true;
	}
	if (w >= natw) {
		dse_set_reg(ctx, rid, val, natw);
		return true;
	}
	if (is_high_byte(dreg)) {
		sym_expr_free(val);
		sym_state_set_reg(&ctx->state, rid, NULL);
		return true;
	}
	dse_commit_low(ctx, aux, rid, val, w, natw);
	return true;
}
//lifter for mov inst
static bool lift_mov(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count != 2) return false;
	const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
	uint32_t w = (uint32_t)dst->size * 8;
	SymExpr *src_e = get_operand_expr(ctx, src, (uint32_t)src->size * 8, aux, arch);
	if (src_e) {
		uint8_t sw = src_e->width;
		if (sw < w) {
			src_e = (insn->id == X86_INS_MOVSX) ? sym_expr_sext(src_e, w) : sym_expr_zext(src_e, w);
		} else if (sw > w) { 
			src_e = sym_expr_extract(src_e, 0, w);
		}
		if (!src_e) return false;
	}
	if (dst->type == X86_OP_REG) return commit_reg(ctx, aux, arch, dst->reg, src_e, w);
	if (dst->type == X86_OP_MEM) {
		dse_store_mem(ctx, aux, src_e);
		return true;
	}
	sym_expr_free(src_e);
	return false;
}
//lifter for arithmetics
static bool lift_arith(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count < 2) return false;
	const cs_x86_op *dst = &x86->operands[0], *src = &x86->operands[1];
	if (dst->type != X86_OP_REG) return false;
	uint32_t w = (uint32_t)dst->size * 8;
	SymExpr *dst_e = get_operand_expr(ctx, dst, w, aux, arch);
	SymExpr *src_e = get_operand_expr(ctx, src, w, aux, arch);
	if (!dst_e || !src_e) {
		sym_expr_free(dst_e);
		sym_expr_free(src_e);
		return commit_reg(ctx, aux, arch, dst->reg, NULL, w);
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
	return commit_reg(ctx, aux, arch, dst->reg, res, w);
}
//lifter for unary
static bool lift_unary(DSECtx *ctx, const cs_insn *insn, const cs_x86 *x86, const InsnAux *aux, const DseArch *arch) {
	if (x86->op_count != 1) return false;
	const cs_x86_op *dst = &x86->operands[0];
	if (dst->type != X86_OP_REG) return false;
	uint32_t w = (uint32_t)dst->size * 8;
	SymExpr *e = get_operand_expr(ctx, dst, w, aux, arch);
	if (!e) return commit_reg(ctx, aux, arch, dst->reg, NULL, w);
	SymExpr *res; 
	if (insn->id == X86_INS_NOT) { 
		res = sym_expr_not(e); 
	} else {
	       res = sym_expr_neg(e);
	}
	return commit_reg(ctx, aux, arch, dst->reg, res, w);
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
		case X86_INS_NOT: case X86_INS_NEG:
			return lift_unary(ctx, insn, x86, aux, arch);
		case X86_INS_IMUL:
			return lift_imul(ctx, insn, x86, aux, arch);
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
