#ifndef TRACE_COLLECTOR_H
#define TRACE_COLLECTOR_H

#include <stdint.h>
#include <stdbool.h>
#include "dta.h"

typedef struct {
	uint64_t seq_id;
	MetaId meta_id;
	uint64_t pc;
	uint8_t  instr_bytes[MAX_INSN_BYTES];
	uint8_t  size;
} TraceEntry;

typedef struct {
	TraceEntry *entries;
	uint32_t capacity;
	uint32_t head_pointer;
	uint32_t counter;
	uint64_t next_seq_id;
} TraceBuffer;

TraceBuffer *trace_buffer_create(uint32_t capacity);
void trace_buffer_destroy(TraceBuffer *tb);
const TraceEntry *trace_append(TraceBuffer *tb, const TraceEntry *entry);
const TraceEntry *trace_get_last(const TraceBuffer *tb, uint32_t i);
void trace_reset(TraceBuffer *tb);
const TraceEntry *trace_find_seq(const TraceBuffer *tb, uint64_t seq_id, uint32_t *back_index);
#endif
