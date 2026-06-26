#include <stdint.h>
#include <stdbool.h>
#include <z3.h>
#include "dta.h"
#include "trace.h"
#include "dse.h"

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

SymExpr *sym_expr_add(SymExpr *a, SymExpr *b) {
	if (a == NULL || b == NULL || (a->width != b->width)) return NULL;
	if (a->type == SYM_CONST && a->const_val == 0) {
		free(a);
		return b;
	}
	if (b->type == SYM_CONST && b->const_val == 0) {
		free(b);
		return a;
	}
	uint32_t w = a->width;
	if (a->type == SYM_CONST && b->type == SYM_CONST) {
		uint64_t v = (a->const_val + b->const_val);
		free(a);
		free(b);
		if (w < 64) {
			v &= ((1ULL << w) - 1);
		}
		return sym_expr_const(v, w);
	} else {
		SymExpr *expr = malloc(sizeof(SymExpr));
		expr->type = SYM_ADD;
		expr->width = w;
		expr->binary.a = a;
		expr->binary.b = b;
		return expr;
	}
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
	if (rid < 0 || rid >= REG_COUNT) return NULL;
	return st->reg[rid];
}


void sym_state_set_reg(SymState *st, RegId rid, SymExpr *e) {
	if (rid < 0 || rid >= REG_COUNT) return;
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
	switch (e->type) {
		case SYM_CONST: {
			Z3_sort sort = Z3_mk_bv_sort(ctx->z3_ctx, e->width);
			return Z3_mk_unsigned_int64(ctx->z3_ctx, e->const_val, sort);
		}
		case SYM_VAR: {
			Z3_sort sort = Z3_mk_bv_sort(ctx->z3_ctx, e->width);
			Z3_symbol name = Z3_mk_int_symbol(ctx->z3_ctx, (int)e->var.id);
			return Z3_mk_const(ctx->z3_ctx, name, sort);
		}
	}
}
