#ifndef AUX_TRACE_H
#define AUX_TRACE_H

#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"

//aux ring for trace add info
typedef struct {
	bool valid;
	uint64_t pc;
	uint64_t reg_vals[REG_COUNT];   /* snapshot before the insn */
	uint8_t reg_taint[REG_COUNT];  /* taint mask*/
	bool has_mem_read;
	uint64_t mem_read_addr;
	uint64_t mem_read_val;
	uint8_t mem_read_taint;
	bool has_mem_write;
	uint64_t mem_write_addr;
} InsnAux;

typedef struct {
    InsnAux *entries;
    uint32_t capacity;
} DseAuxRing;

DseAuxRing *dse_aux_create(uint32_t capacity);
void dse_aux_destroy(DseAuxRing *r);
void dse_aux_record(DseAuxRing *r, const TraceBuffer *tb, const InsnAux *aux);
//support for get_slice
const InsnAux *dse_aux_for(const DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *e);
#endif
