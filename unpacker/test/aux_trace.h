#ifndef AUX_TRACE_H
#define AUX_TRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"

#define DSE_MAX_MEM_ACCESSES 8U
#define DSE_MAX_STRING_BYTES_PER_INSN (64U * 1024U)
#define DSE_MAX_STRING_TRACE_BYTES (64U * 1024U * 1024U)

//aux ring for trace add info
typedef struct {
	uint64_t addr;
	uint64_t value;
	uint8_t taint;
	uint8_t effective_taint; //with address taint
	bool address_tainted;
	uint8_t size;
} DseMemRead;

typedef struct {
	uint64_t addr;
	uint64_t value;
	uint8_t size;
	bool value_valid;
} DseMemWrite;

typedef enum {
	DSE_STRING_NONE = 0,
	DSE_STRING_MOVS,
	DSE_STRING_STOS
} DseStringKind;

typedef struct {
	DseStringKind kind;
	bool active;
	bool exact;
	bool overflow;
	bool pattern_mismatch;
	bool has_rep_prefix;
	uint8_t element_size;
	int8_t direction;
	uint32_t expected_iterations;
	uint32_t read_events;
	uint32_t write_events;
	uint32_t bytes_captured;
	uint32_t capacity;
	uint64_t source_first;
	uint64_t destination_first;
	uint8_t *values;
	uint8_t *value_taint;
} DseStringSummary;

typedef struct {
	bool valid;
	bool execution_complete;
	uint64_t seq_id;
	MetaId meta_id;
	uint64_t pc;
	uint64_t reg_vals[REG_COUNT];
	uint8_t reg_taint[REG_COUNT];
	uint32_t reg_value_valid_mask;
	bool eflags_valid;
	uint32_t eflags_before;
	bool next_pc_valid;
	uint64_t next_pc;
	bool has_mem_read;
	uint64_t mem_read_addr;
	uint64_t mem_read_val;
	uint8_t mem_read_taint;
	uint8_t mem_read_effective_taint;
	bool mem_read_address_tainted;
	bool has_mem_write;
	uint64_t mem_write_addr;
	uint8_t mem_write_size;
	uint8_t mem_read_count;
	bool mem_read_overflow;
	uint32_t mem_read_total;
	bool mem_read_range_valid;
	bool mem_read_range_unknown;
	uint64_t mem_read_min_addr;
	uint64_t mem_read_max_addr;
	DseMemRead mem_reads[DSE_MAX_MEM_ACCESSES];
	uint8_t mem_write_count;
	bool mem_write_overflow;
	uint32_t mem_write_total;
	bool mem_write_range_valid;
	bool mem_write_range_unknown;
	uint64_t mem_write_min_addr;
	uint64_t mem_write_max_addr;
	DseMemWrite mem_writes[DSE_MAX_MEM_ACCESSES];
	DseStringSummary string_summary;
} InsnAux;

typedef struct {
	InsnAux *entries;
	uint32_t capacity;
	uint64_t dynamic_bytes;
	uint64_t max_dynamic_bytes;
} DseAuxRing;

DseAuxRing *dse_aux_create(uint32_t capacity);
void dse_aux_destroy(DseAuxRing *r);
InsnAux *dse_aux_record(DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *entry, const InsnAux *aux);
//support for get_slice
void dse_aux_prepare_string(InsnAux *aux, const InsnMeta *meta);
bool dse_aux_capture_string_read(DseAuxRing *ring, InsnAux *aux, uint64_t address, uint64_t value, bool value_valid, uint8_t value_taint, uint32_t size);
void dse_aux_capture_string_write(InsnAux *aux, uint64_t address, uint32_t size);
void dse_aux_finalize(InsnAux *aux, uint64_t next_pc, const uint64_t post_reg_vals[REG_COUNT], uint32_t post_reg_value_valid_mask);
bool dse_aux_has_exact_movs(const InsnAux *aux);
bool dse_aux_has_exact_stos(const InsnAux *aux);
const InsnAux *dse_aux_for(const DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *e);
#endif
