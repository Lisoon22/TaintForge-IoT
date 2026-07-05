#ifndef DTA_SHADOW_H
#define DTA_SHADOW_H

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>
#include <capstone/capstone.h>

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
	uint64_t pc;
	uint8_t size;
	bool has_mem_read;
	bool has_mem_write;
	uint32_t regs_read_mask;
	uint32_t regs_written_mask;
	bool is_indirect_branch;
	uint16_t insn_id;
	RegId branch_target_reg;
} InsnMeta;

ShadowMemory *shadow_create(uint8_t guest_bits);
void shadow_destroy(ShadowMemory *sm);

void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip);
void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr);
bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr);
bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr);

int x86_reg_to_rid(unsigned cs_reg);

#define MAX_REG_BYTES 8

typedef struct {
    bool     bytes[REG_COUNT][MAX_REG_BYTES];
    uint64_t src_ip[REG_COUNT];
} RegShadow;

void reg_taint_set(RegShadow *rs, RegId rid, uint8_t byte_mask, uint64_t ip);
void reg_taint_clear(RegShadow *rs, RegId rid, uint8_t byte_mask);
bool reg_is_tainted(RegShadow *rs, RegId rid, uint8_t byte_mask);

void propagate_reg2reg(RegShadow *rs, RegId dst, uint8_t dst_mask, RegId src, uint8_t src_mask);
void propagate_reg2reg_arith(RegShadow *rs, RegId dst, RegId src1, RegId src2, uint16_t insn_id);
void propagate_mem2reg(RegShadow *rs, RegId dst, uint8_t dst_mask, bool mem_tainted);
void reg_propagate_clear(RegShadow *rs, RegId dst);

void meta_init(void);
void meta_free(void);
InsnMeta *meta_decode(const uint8_t *bytes, size_t size, uint64_t pc, csh handle);
void meta_store(uint64_t pc, InsnMeta *m);
InsnMeta *meta_lookup(uint64_t pc);
#endif
