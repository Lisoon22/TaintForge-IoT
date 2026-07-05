#ifndef DSE_H
#define DSE_H

#include <stdint.h>
#include <stdbool.h>
#include <z3.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"
#include "aux_trace.h"

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
	//for deduplication
	GHashTable *var_cache;

	uint32_t var_counter;       /* unique id*/
} SymState;

//DSE context
typedef struct {
	SymState    state;
	Z3_context  z3_ctx;         /* Z3 context*/
	Z3_solver   z3_solver;      /* Z3 solver instance */
	Z3_ast path_predicate;      /* path conditions */
	bool        has_solver;
} DSECtx;

//multiarch support
typedef struct DseArch {
	const char *name;
	uint32_t natural_width;
	bool big_endian;
	int  (*reg_to_rid)(unsigned cs_reg);
	bool (*lift_one)(DSECtx *ctx, const cs_insn *insn, const InsnAux *aux, const struct DseArch *arch);
} DseArch;
//arch dependent
extern const DseArch dse_arch_x86;

SymExpr *dse_read_rid_fit(DSECtx *ctx, const InsnAux *aux, int rid, uint32_t want_w, uint32_t natural_w);
SymExpr *dse_load_mem (DSECtx *ctx, const InsnAux *aux, uint32_t width_bits, bool big_endian);
void dse_store_mem(DSECtx *ctx, const InsnAux *aux, SymExpr *val, bool big_endian);
void dse_set_reg (DSECtx *ctx, int rid, SymExpr *val, uint32_t natural_w);
void dse_commit_low(DSECtx *ctx, const InsnAux *aux, int rid, SymExpr *val, uint32_t w, uint32_t natural_w);

//init and basic operands DSE
SymExpr *sym_expr_const(uint64_t val, uint32_t width);
SymExpr *sym_expr_var(uint64_t src_addr, uint32_t idx, uint32_t width);
SymExpr *sym_expr_clone(const SymExpr *e);
SymExpr *sym_expr_add(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_sub(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_xor(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_and(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_shl(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_shr(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_sar(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_rol(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_ror(SymExpr *a, SymExpr *count);
SymExpr *sym_expr_mul(SymExpr *a, SymExpr *b);
SymExpr *sym_expr_or (SymExpr *a, SymExpr *b);
SymExpr *sym_expr_sext(SymExpr *a, uint32_t to_width);
SymExpr *sym_expr_zext(SymExpr *a, uint32_t to_width);
SymExpr *sym_expr_extract(SymExpr *a, uint32_t low_bit, uint32_t out_width);
SymExpr *sym_expr_concat(SymExpr *high, SymExpr *low);
SymExpr *sym_expr_not(SymExpr *a);
SymExpr *sym_expr_neg(SymExpr *a);
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
void dse_lift_attach(const TraceBuffer *tb, const DseAuxRing *ring, const DseArch *arch); //attach trace+aux
void dse_lift_begin(DSECtx *ctx);
//void dse_lift_end(void);
uint32_t dse_lift_total_count(void); //counter instr lifted
uint32_t dse_lift_concretized_count(void); //to concrete
uint32_t dse_lift_aux_miss_count(void);
uint32_t dse_lift_unsupported_count(void);
uint64_t dse_eval_expr(const SymExpr *e); //concrete eval of a AST under taint val
bool dse_expr_has_var(const SymExpr *e); //is SYM_VAR in the current AST

//dse check of oep
int  dse_check_oep_reachable(DSECtx *ctx, SymExpr *target_expr, uint64_t oep_candidate);
bool dse_verify_oep_candidate(TraceBuffer *tb, uint64_t trigger_pc, RegId target_reg, uint64_t oep_candidate, ShadowMemory *shadow, csh cs_handle);
//supporters for indirect operations
int trace_get_slice_mem(const TraceBuffer *tb, const DseAuxRing *ring, uint64_t trigger_pc, uint64_t target_addr, const TraceEntry **out_slice, int max_len);
bool dse_verify_oep_candidate_mem(TraceBuffer *tb, const DseAuxRing *ring, uint64_t trigger_pc, uint64_t target_addr, uint64_t oep_candidate, ShadowMemory *shadow, csh cs_handle);
#endif
