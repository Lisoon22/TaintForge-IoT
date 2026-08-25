#ifndef DTA_SHADOW_H
#define DTA_SHADOW_H

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include <capstone/capstone.h>

#define MAX_REG_BYTES 8
#define MAX_INSN_REG_SLICES 8
#define MAX_INSN_BYTES 15U
typedef uint64_t MetaId;
#define META_ID_INVALID ((MetaId)0)

typedef struct ShadowMemory ShadowMemory;
typedef enum {
	REG_RAX = 0, REG_RCX, REG_RDX, REG_RBX,
	REG_RSP, REG_RBP, REG_RSI, REG_RDI,
	REG_R8, REG_R9, REG_R10, REG_R11,
	REG_R12, REG_R13, REG_R14, REG_R15,
	REG_COUNT,
	REG_INVALID = -1 
} RegId;
typedef struct {
	RegId reg_id;
	uint8_t byte_offset;
	uint8_t width;
	uint8_t mask;
} RegSlice;
typedef enum {
	DTA_FAMILY_UNSUPPORTED = 0,
	DTA_FAMILY_DATA_MOVEMENT,
	DTA_FAMILY_LOGICAL,
	DTA_FAMILY_ARITHMETIC,
	DTA_FAMILY_COMPARE,
	DTA_FAMILY_SHIFT_ROTATE,
	DTA_FAMILY_STACK,
	DTA_FAMILY_STRING
} DtaInsnFamily;
typedef enum {
	DTA_TRANSFER_NOT_APPLICABLE = 0,
	DTA_TRANSFER_EXACT,
	DTA_TRANSFER_CONSERVATIVE
} DtaTransferResult;

enum {
	X86_FLAG_CF = 1U << 0,
	X86_FLAG_PF = 1U << 1,
	X86_FLAG_AF = 1U << 2,
	X86_FLAG_ZF = 1U << 3,
	X86_FLAG_SF = 1U << 4,
	X86_FLAG_OF = 1U << 5,
	X86_FLAG_TRACKED = X86_FLAG_CF | X86_FLAG_PF | X86_FLAG_AF | X86_FLAG_ZF | X86_FLAG_SF | X86_FLAG_OF
};

typedef enum {
	X86_CC_NONE = 0,
	X86_CC_O,
	X86_CC_NO,
	X86_CC_B,
	X86_CC_AE,
	X86_CC_E,
	X86_CC_NE,
	X86_CC_BE,
	X86_CC_A,
	X86_CC_S,
	X86_CC_NS,
	X86_CC_P,
	X86_CC_NP,
	X86_CC_L,
	X86_CC_GE,
	X86_CC_LE,
	X86_CC_G
} X86ConditionCode;

typedef struct {
	MetaId meta_id;
	uint64_t pc;
	uint8_t instr_bytes[MAX_INSN_BYTES];
	uint8_t size;
	bool has_mem_read;
	bool has_mem_write;
	uint32_t regs_read_mask;
	uint32_t regs_written_mask;
	bool is_indirect_branch;
	uint16_t insn_id;
	RegId branch_target_reg;
	DtaInsnFamily family;
	uint32_t mem_addr_reg_mask;
	uint32_t mem_read_addr_reg_mask;
	uint32_t mem_write_addr_reg_mask;
	
	RegSlice reg_reads[MAX_INSN_REG_SLICES];
	uint8_t reg_read_count;
	RegSlice reg_writes[MAX_INSN_REG_SLICES];
	uint8_t reg_write_count;

	bool has_imm_operand;
	bool is_self_zeroing;
	
	uint8_t flags_read_mask;
	uint8_t flags_write_mask;
	X86ConditionCode condition_code;
	bool is_conditional_branch;
	bool has_rep_prefix;
	uint8_t string_element_size;
} InsnMeta;

ShadowMemory *shadow_create(uint8_t guest_bits);
void shadow_destroy(ShadowMemory *sm);

void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip);
bool shadow_taint_range(ShadowMemory *sm, uint64_t addr, uint64_t size, uint64_t ip);
void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr);
void shadow_untaint_range(ShadowMemory *sm, uint64_t addr, uint64_t size);
bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr);
bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr);

int x86_reg_to_rid(unsigned cs_reg);

RegSlice reg_slice_invalid(void);
RegSlice reg_slice_from_x86(unsigned cs_reg, uint8_t size_bytes);
bool reg_slice_is_valid(RegSlice slice);
bool reg_slice_equal(RegSlice left, RegSlice right);

RegSlice meta_first_reg_read(const InsnMeta *meta);
RegSlice meta_first_reg_write(const InsnMeta *meta);

typedef struct {
	bool     bytes[REG_COUNT][MAX_REG_BYTES];
	uint64_t src_ip[REG_COUNT];
} RegShadow;

void reg_taint_set(RegShadow *rs, RegId rid, uint8_t byte_mask, uint64_t ip);
void reg_taint_clear(RegShadow *rs, RegId rid, uint8_t byte_mask);
bool reg_is_tainted(RegShadow *rs, RegId rid, uint8_t byte_mask);
void reg_slice_taint_set(RegShadow *rs, RegSlice slice, uint64_t ip);
void reg_slice_taint_clear(RegShadow *rs, RegSlice slice);
bool reg_slice_is_tainted(const RegShadow *rs, RegSlice slice);

void propagate_reg2reg(RegShadow *rs, RegSlice dst, RegSlice src, uint16_t insn_id);
void propagate_mem2reg(RegShadow *rs, RegSlice dst, uint8_t mem_taint_mask, uint8_t mem_width, uint16_t insn_id, bool overwrite);
void reg_propagate_clear(RegShadow *rs, RegId dst);

DtaTransferResult dta_apply_reg_transfer(RegShadow *rs, const InsnMeta *meta);
DtaTransferResult dta_compute_mem_write_taint(const RegShadow *pre_regs, const InsnMeta *meta, uint8_t old_mem_taint, bool source_mem_valid, uint8_t source_mem_taint, uint8_t width, uint8_t *result_taint);
DtaTransferResult dta_apply_mem_read_transfer(RegShadow *rs, const RegShadow *pre_regs, const InsnMeta *meta, uint8_t mem_taint_mask, uint8_t mem_width);
uint8_t dta_effective_mem_read_taint(const RegShadow *pre_regs, const InsnMeta *meta, uint8_t mem_taint_mask, uint8_t mem_width);
bool dta_address_mask_is_tainted(const RegShadow *pre_regs, uint32_t address_reg_mask);

void meta_init(void);
void meta_free(void);
InsnMeta *meta_decode(const uint8_t *bytes, size_t size, uint64_t pc, csh handle);
const InsnMeta *meta_store(uint64_t pc, InsnMeta *m);
const InsnMeta *meta_lookup(uint64_t pc);
const InsnMeta *meta_lookup_id(MetaId meta_id);
#endif
