#include <stdint.h>
#include <stdbool.h>
#include <z3.h>
#include "dta.h"
#include "trace.h"
#include "dse.h"

//helpers
static inline uint64_t mask_w(uint64_t v, uint8_t w) {
	if (w >= 64) {
	       	return v;
	} else {
		return (v & (((uint64_t)1 << w) - 1));
	}
}

static SymExpr *mk_binary(SymOp op, uint8_t w, SymExpr *a, SymExpr *b) {
	SymExpr *e = malloc(sizeof(SymExpr));
	if (!e) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	e->type = op;
	e->width = w;
	e->binary.a = a;
	e->binary.b = b;
	return e;
}

static SymExpr *mk_unary(SymOp op, uint8_t w, SymExpr *a) {
	SymExpr *e = malloc(sizeof(SymExpr));
	if (!e) {
		sym_expr_free(a);
		return NULL;
	}
	e->type = op;
	e->width = w;
	e->unary.a = a;
	e->unary.ext_to = w;
	e->unary.extract_high = 0;
	e->unary.extract_low = 0;
	return e;
}

SymExpr *sym_expr_const(uint64_t val, uint32_t width) {
	if (width ==0 || width > 64) return NULL;
	SymExpr *expr = malloc(sizeof(SymExpr));
	if (!expr) return NULL;
	expr ->type = SYM_CONST;
	expr->width = width;
	if (width == 64) {
        	expr->const_val = val;
	} else {
		expr->const_val = (val & ((1ULL << width) - 1));
	}
	return expr;
}

SymExpr *sym_expr_var(uint64_t src_addr, uint32_t idx, uint32_t width) {
	if (width ==0 || width > 64) return NULL;
	SymExpr *expr = malloc(sizeof(SymExpr));
	if (!expr) return NULL;
	expr->type = SYM_VAR;
	expr->width = width;
	expr->var.src_addr = src_addr;
	expr->var.id = idx;
	return expr;
}

SymExpr *sym_expr_clone(const SymExpr *e) {
	if (!e) return NULL;
	switch (e->type) {
		case SYM_CONST: return sym_expr_const(e->const_val, e->width);
		case SYM_VAR:   return sym_expr_var(e->var.src_addr, e->var.id, e->width);
		case SYM_ADD: case SYM_SUB: case SYM_XOR: case SYM_AND: case SYM_SHL: case SYM_CONCAT: {
			SymExpr *a = sym_expr_clone(e->binary.a);
			SymExpr *b = sym_expr_clone(e->binary.b);
			if (!a || !b) {
				sym_expr_free(a);
				sym_expr_free(b);
				return NULL;
			}
			return mk_binary(e->type, e->width, a, b);
		}
		case SYM_EXTRACT: case SYM_ZEXT: case SYM_SEXT: {
			SymExpr *a = sym_expr_clone(e->unary.a);
			if (!a) return NULL;
			SymExpr *n = mk_unary(e->type, e->width, a);
			if (n) { 
				n->unary.ext_to=e->unary.ext_to;
				n->unary.extract_high=e->unary.extract_high;
				n->unary.extract_low=e->unary.extract_low; }
			return n;
		}
	}
	return NULL;
}

SymExpr *sym_expr_add(SymExpr *a, SymExpr *b) {
	if (!a || !b || (a->width != b->width)) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	if (a->type == SYM_CONST && a->const_val == 0) {
		sym_expr_free(a);
		return b;
	}
	if (b->type == SYM_CONST && b->const_val == 0) {
		sym_expr_free(b);
		return a;
	}
	uint8_t w = a->width;
	if (a->type == SYM_CONST && b->type == SYM_CONST) {
		uint64_t v = (a->const_val + b->const_val);
		sym_expr_free(a);
		sym_expr_free(b);
		v = mask_w(v, w);
		return sym_expr_const(v, w);
	} 
	SymExpr *expr = mk_binary(SYM_ADD, w, a, b);
	if (!expr) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	return expr;
}

SymExpr *sym_expr_sub(SymExpr *a, SymExpr *b) {
	if (!a || !b || (a->width != b->width)) { 
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	uint8_t w = a->width;
	if (b->type == SYM_CONST && b->const_val == 0) {
		sym_expr_free(b);
		return a;
	}
	if (a->type == SYM_CONST && b->type == SYM_CONST) {
		uint64_t v = mask_w(a->const_val - b->const_val, w);
		sym_expr_free(a);
		sym_expr_free(b);
		return sym_expr_const(v, w);
	}
	SymExpr *expr = mk_binary(SYM_SUB, w, a, b);
	if (!expr) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}

	return expr;
}

SymExpr *sym_expr_xor(SymExpr *a, SymExpr *b) {
	if (!a || !b || a->width != b->width) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	uint8_t w = a->width;
	if (a->type == SYM_CONST && a->const_val == 0) {
		sym_expr_free(a);
		return b;
	}
	if (b->type == SYM_CONST && b->const_val == 0) {
		sym_expr_free(b);
		return a;
	}
	if (a->type == SYM_CONST && b->type == SYM_CONST) {
		uint64_t v = mask_w(a->const_val ^ b->const_val, w);
		sym_expr_free(a); sym_expr_free(b);
		return sym_expr_const(v, w);
	}
	SymExpr *expr = mk_binary(SYM_XOR, w, a, b);
	if (!expr) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}

	return expr;
}

SymExpr *sym_expr_and(SymExpr *a, SymExpr *b) {
	if (!a || !b || a->width != b->width) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	uint8_t w = a->width;
	uint64_t all = mask_w(~0ULL, w);
	if (a->type == SYM_CONST && a->const_val == 0) {
		sym_expr_free(b);
		return a;
	}
	if (b->type == SYM_CONST && b->const_val == 0) {
		sym_expr_free(a);
		return b;
	}
	if (a->type == SYM_CONST && a->const_val == all) {
		sym_expr_free(a);
		return b;
	}
	if (b->type == SYM_CONST && b->const_val == all) {
		sym_expr_free(b);
		return a;
	}
	if (a->type == SYM_CONST && b->type == SYM_CONST) {
		uint64_t v = mask_w(a->const_val & b->const_val, w);
		sym_expr_free(a);
		sym_expr_free(b);
		return sym_expr_const(v, w);
	}
	SymExpr *expr = mk_binary(SYM_AND, w, a, b);
	if (!expr) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}

	return expr;
}

SymExpr *sym_expr_shl(SymExpr *a, SymExpr *b) {
	if (!a || !b) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}
	uint8_t w = a->width;
	if (b->width < w) b = sym_expr_zext(b, w);
	else if (b->width > w) b = sym_expr_extract(b, 0, w);
	if (!b) {
		sym_expr_free(a);
		return NULL;
	}
	if (b->type == SYM_CONST && b->const_val == 0){
		sym_expr_free(b);
		return a;
	}
	if (a->type == SYM_CONST && b->type == SYM_CONST) {
		uint64_t v = mask_w(a->const_val << (b->const_val & 63), w);
		sym_expr_free(a);
		sym_expr_free(b);
		return sym_expr_const(v, w);
	}
	SymExpr *expr = mk_binary(SYM_SHL, w, a, b);
	if (!expr) {
		sym_expr_free(a);
		sym_expr_free(b);
		return NULL;
	}

	return expr;
}

SymExpr *sym_expr_sext(SymExpr *a, uint32_t to_width) {
	if (!a || to_width > 64 || to_width < a->width) {
		sym_expr_free(a);
		return NULL;
	}
	if (to_width == a->width) return a;
	if (a->type == SYM_CONST) {
		uint8_t sw = a->width;
		uint64_t v = mask_w(a->const_val, sw);
		if (sw < 64 && ((v >> (sw - 1)) & 1ULL)) v |= (mask_w(~0ULL, (uint8_t)to_width) & ~mask_w(~0ULL, sw));
		sym_expr_free(a);
		return sym_expr_const(mask_w(v, (uint8_t)to_width), (uint8_t)to_width);
	}
	return mk_unary(SYM_SEXT, (uint8_t)to_width, a);
}

SymExpr *sym_expr_zext(SymExpr *a, uint32_t to_width) {
	if (!a || to_width > 64 || to_width < a->width) {
		sym_expr_free(a);
		return NULL;
	}
	if (to_width == a->width) return a;
	if (a->type == SYM_CONST) {
		uint64_t v = mask_w(a->const_val, a->width);
		sym_expr_free(a);
		return sym_expr_const(v, (uint8_t)to_width);
	}
	return mk_unary(SYM_ZEXT, (uint8_t)to_width, a);
}

SymExpr *sym_expr_extract(SymExpr *a, uint32_t low_bit, uint32_t out_width) {
	if (!a || out_width == 0 || low_bit + out_width > a->width) {
		sym_expr_free(a);
		return NULL;
	}
	if (low_bit == 0 && out_width == a->width) return a;
	if (a->type == SYM_CONST) {
		uint64_t v = mask_w(a->const_val >> low_bit, (uint8_t)out_width);
		sym_expr_free(a);
		return sym_expr_const(v, (uint8_t)out_width);
	}
	SymExpr *e = mk_unary(SYM_EXTRACT, (uint8_t)out_width, a);
	if (e) {
		e->unary.extract_low = low_bit;
		e->unary.extract_high = low_bit + out_width - 1;
	}
	return e;
}

SymExpr *sym_expr_concat(SymExpr *high, SymExpr *low) {
	if (!high || !low) {
		sym_expr_free(high);
		sym_expr_free(low);
		return NULL;
	}
	uint32_t w = (uint32_t)high->width + (uint32_t)low->width;
	if (w == 0 || w > 64) {
		sym_expr_free(high);
		sym_expr_free(low);
		return NULL;
	}
	if (high->type == SYM_CONST && low->type == SYM_CONST) {
		uint64_t v = (mask_w(high->const_val, high->width) << low->width) | mask_w(low->const_val, low->width);
		sym_expr_free(high); sym_expr_free(low);
		return sym_expr_const(v, (uint8_t)w);
	}
	return mk_binary(SYM_CONCAT, (uint8_t)w, high, low);
}

void sym_expr_free(SymExpr *e) {
	if (e == NULL) return;
	if (e->type == SYM_ADD || e->type == SYM_SUB || e->type == SYM_XOR || e->type == SYM_AND || e->type == SYM_SHL || e->type == SYM_CONCAT) {
		sym_expr_free(e->binary.a);
		sym_expr_free(e->binary.b);
	}
	if (e->type == SYM_EXTRACT || e->type == SYM_ZEXT || e->type == SYM_SEXT) {
		sym_expr_free(e->unary.a);
	}
	free(e);
}

void sym_state_init(SymState *st) {
	memset(st, 0, sizeof(*st));
	st->sym_mem = NULL;
}

void sym_state_clear(SymState *st) {
	for (uint8_t i = 0; i < REG_COUNT; i ++) {
		sym_expr_free(st->reg[i]);
		st->reg[i] = NULL;
	}
	if (st->sym_mem != NULL) {
		g_hash_table_destroy(st->sym_mem);
		st->sym_mem = NULL;
	}
	st->var_counter = 0;
}

SymExpr *sym_state_new_var(SymState *st, uint64_t src_addr, uint32_t width) {
	return sym_expr_var(src_addr, st->var_counter++, width);
}

SymExpr *sym_state_get_reg(const SymState *st, RegId rid) {
	if (rid < 0 || rid >= REG_COUNT) {
		return NULL;
	}
	return st->reg[rid];
}


void sym_state_set_reg(SymState *st, RegId rid, SymExpr *e) {
	if (rid < 0 || rid >= REG_COUNT) {
		sym_expr_free(e);
		return;
	}
	if (st->reg[rid] && st->reg[rid] != e) sym_expr_free(st->reg[rid]);
	st->reg[rid] = e;
}

bool dse_ctx_init(DSECtx *ctx) {
	memset(ctx, 0, sizeof(*ctx));
	sym_state_init(&ctx->state);
	Z3_config cfg = Z3_mk_config();
	Z3_set_param_value(cfg, "model", "true"); //witness mode
	ctx->z3_ctx = Z3_mk_context(cfg);
	Z3_del_config(cfg);
	if (!ctx->z3_ctx) return false;
	ctx->z3_solver = Z3_mk_solver(ctx->z3_ctx);
	Z3_solver_inc_ref(ctx->z3_ctx, ctx->z3_solver);
	ctx->path_predicate = Z3_mk_true(ctx->z3_ctx);
	ctx->has_solver = true;
	return true;
}

void dse_ctx_free(DSECtx *ctx) {
	if (!ctx) return;
	sym_state_clear(&ctx->state);
	if (ctx->has_solver && ctx->z3_ctx) {
		Z3_solver_dec_ref(ctx->z3_ctx, ctx->z3_solver);
		Z3_del_context(ctx->z3_ctx);
		ctx->has_solver = false;
	}	
}

static Z3_ast sym_expr_to_z3(DSECtx *ctx, const SymExpr *e) {
	if (!e) return NULL;
	Z3_context c = ctx->z3_ctx;
	switch (e->type) {
		case SYM_CONST: {
			Z3_sort sort = Z3_mk_bv_sort(c, e->width);
			return Z3_mk_unsigned_int64(c, e->const_val, sort);
		}
		case SYM_VAR: {
			Z3_sort sort = Z3_mk_bv_sort(c, e->width);
			Z3_symbol name = Z3_mk_int_symbol(c, (int)e->var.id);
			return Z3_mk_const(c, name, sort);
		}
		case SYM_ADD: case SYM_SUB: case SYM_XOR: case SYM_AND: case SYM_SHL: case SYM_CONCAT: {
			Z3_ast A = sym_expr_to_z3(ctx, e->binary.a);
			Z3_ast B = sym_expr_to_z3(ctx, e->binary.b);
			if (!A || !B) return NULL;
			switch (e->type) {
				case SYM_ADD:    return Z3_mk_bvadd(c, A, B);
				case SYM_SUB:    return Z3_mk_bvsub(c, A, B);
				case SYM_XOR:    return Z3_mk_bvxor(c, A, B);
				case SYM_AND:    return Z3_mk_bvand(c, A, B);
				case SYM_SHL:    return Z3_mk_bvshl(c, A, B);
				case SYM_CONCAT: return Z3_mk_concat(c, A, B);
				default:         return NULL;
			}
		}
		case SYM_ZEXT: case SYM_SEXT: {
			Z3_ast A = sym_expr_to_z3(ctx, e->unary.a);
			if (!A) return NULL;
			unsigned add = (unsigned)(e->width - e->unary.a->width);
			if (e->type == SYM_ZEXT) {
				return Z3_mk_zero_ext(c, add, A);
			} else {
				return Z3_mk_sign_ext(c, add, A);
			}
		}
		case SYM_EXTRACT: {
			Z3_ast A = sym_expr_to_z3(ctx, e->unary.a);
			if (!A) return NULL;
			return Z3_mk_extract(c, e->unary.extract_high, e->unary.extract_low, A);
		}
		default: {
			return NULL;
		}
	}
}

void dse_path_assert(DSECtx *ctx, SymExpr *cond, bool expected) {
	if (!ctx || !cond) return;
	if (cond->type == SYM_CONST) {
		sym_expr_free(cond);
		return;
	}
	Z3_ast c = sym_expr_to_z3(ctx, cond);
	if (c) {
		Z3_sort s = Z3_mk_bv_sort(ctx->z3_ctx, cond->width);
		Z3_ast want = Z3_mk_unsigned_int64(ctx->z3_ctx, expected ? 1u : 0u, s);
		Z3_ast eq = Z3_mk_eq(ctx->z3_ctx, c, want);
		Z3_ast conj[2] = { ctx->path_predicate, eq };
		ctx->path_predicate = Z3_mk_and(ctx->z3_ctx, 2, conj);
	}
	sym_expr_free(cond);
}

int dse_check_oep_reachable(DSECtx *ctx, SymExpr *target_expr, uint64_t oep_candidate) {
	if (!ctx || !ctx->has_solver || !target_expr) return -1;
	Z3_ast t = sym_expr_to_z3(ctx, target_expr);
	if (!t) return -1;
	Z3_sort s = Z3_mk_bv_sort(ctx->z3_ctx, target_expr->width);
	Z3_ast oep = Z3_mk_unsigned_int64(ctx->z3_ctx, mask_w(oep_candidate, target_expr->width), s);
	Z3_ast eq = Z3_mk_eq(ctx->z3_ctx, t, oep);

	Z3_solver_push(ctx->z3_ctx, ctx->z3_solver);
	Z3_solver_assert(ctx->z3_ctx, ctx->z3_solver, ctx->path_predicate);
	Z3_solver_assert(ctx->z3_ctx, ctx->z3_solver, eq);
	Z3_lbool r = Z3_solver_check(ctx->z3_ctx, ctx->z3_solver);
	Z3_solver_pop(ctx->z3_ctx, ctx->z3_solver, 1);

	if (r == Z3_L_TRUE)  return 1;
	if (r == Z3_L_FALSE) return 0;
	return -1;
}
