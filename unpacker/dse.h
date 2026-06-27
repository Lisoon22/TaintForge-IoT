#ifndef DSE_H
#define DSE_H

#include <stdint.h>
#include <stdbool.h>
#include <z3.h>
#include "dta.h"
#include "trace.h"

typedef enum {
	SYM_CONST,
	SYM_VAR,

	SYM_ADD,
	SYM_SUB,
	SYM_XOR,
	SYM_AND,
	SYM_SHL,
    
	SYM_EXTRACT, 	/* extract low from high bytes*/
	SYM_ZEXT,	/* extend low to high with zeroes*/
	SYM_SEXT, 	/* sign extension */
	SYM_CONCAT, 	/* concatinate high and low bytes*/
} SymOp;

typedef struct SymExpr {
	SymOp type;
	uint8_t width; //control width for some operations like add, zext, etc.

	union {
		//for const
		uint64_t const_val;

		//for tainted
		struct {
			uint64_t src_addr;
			uint32_t id; 	/*unique*/
		} var;

		//for bin operations
		struct {
			struct SymExpr *a;
			struct SymExpr *b;
		} binary;

		//for unary operations
		struct {
			struct SymExpr *a;
			uint32_t ext_to; 	/* target width for ZEXT*/
			uint32_t extract_high;	/* amount of high bytes*/
			uint32_t extract_low; 	/* amount of low bytes*/
		} unary;
	};
} SymExpr;

typedef struct {
	//registers state taint/!taint
	SymExpr *reg[REG_COUNT];

	//mem state taint/!taint
	GHashTable *sym_mem;

	uint32_t var_counter;       /* unique id*/
} SymState;

//just DSE shortcut
typedef struct {
	SymState    state;
	Z3_context  z3_ctx;         /* Z3 context*/
	Z3_solver   z3_solver;      /* Z3 solver instance */
	Z3_ast path_predicate;      /* path conditions */
	bool        has_solver;
} DSECtx;

//init and basic operands DSE
SymExpr *sym_expr_const(uint64_t val, uint32_t width);
SymExpr *sym_expr_var(uint64_t src_addr, uint32_t idx, uint32_t width);
SymExpr *sym_expr_clone(const SymExpr *e);
SymExpr *sym_expr_sext(SymExpr *a, uint32_t to_width);
SymExpr *sym_expr_add(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_sub(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_xor(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_and(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_shl(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_zext(SymExpr *a, uint32_t to_width);
SymExpr *sym_expr_extract(SymExpr *a, uint32_t low_bit, uint32_t out_width);
SymExpr *sym_expr_concat(SymExpr *high, SymExpr *low);
void sym_expr_free(SymExpr *e);

//states for DSE
void sym_state_init(SymState *st);
void sym_state_clear(SymState *st);
SymExpr *sym_state_get_reg(const SymState *st, RegId rid);
void sym_state_set_reg(SymState *st, RegId rid, SymExpr *e);
SymExpr *sym_state_new_var(SymState *st, uint64_t src_addr, uint32_t width);

//context DSE
bool dse_ctx_init(DSECtx *ctx);
void dse_ctx_free(DSECtx *ctx);
void dse_path_assert(DSECtx *ctx, SymExpr *cond, bool expected);

//lifter, instr to z3
bool dse_lift_insn(DSECtx *ctx, const TraceEntry *entry, const InsnMeta *meta, csh cs_handle);

//dse check of oep
int  dse_check_oep_reachable(DSECtx *ctx, SymExpr *target_expr, uint64_t oep_candidate);
bool dse_verify_oep_candidate(TraceBuffer *tb, uint64_t trigger_pc, RegId target_reg, uint64_t oep_candidate, ShadowMemory *shadow, csh cs_handle);
#endif
