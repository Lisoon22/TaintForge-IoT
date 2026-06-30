#ifndef TRACE_COLLECTOR_H
#define TRACE_COLLECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include "dta.h"

typedef struct {
    uint64_t pc;
    uint8_t  instr_bytes[15];
    uint8_t  size;
} TraceEntry;

typedef struct {
	TraceEntry *entries;
	uint32_t capacity;
	uint32_t head_pointer;
	uint32_t counter;
} TraceBuffer;

TraceBuffer *trace_buffer_create(uint32_t capacity);
void trace_buffer_destroy(TraceBuffer *tb);
void trace_append(TraceBuffer *tb, const TraceEntry *entry);
const TraceEntry *trace_get_last(const TraceBuffer *tb, uint32_t i);
void trace_reset(TraceBuffer *tb);

int trace_get_slice(const TraceBuffer *tb, uint64_t trigger_pc, RegId target_reg, const TraceEntry **out_slice, int max_len);

#endif
