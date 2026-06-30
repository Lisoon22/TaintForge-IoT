#include "trace.h"
#include <stdlib.h>
#include <string.h>
#include "dta.h"

TraceBuffer *trace_buffer_create(uint32_t capacity) {
	if (!(capacity > 0 && (capacity & (capacity-1)) == 0)) return NULL;
	TraceBuffer *buff = malloc(sizeof(TraceBuffer));
	if (!buff) return NULL;
	buff->entries = calloc(capacity, sizeof(TraceEntry));
	if (!buff->entries) {
		free(buff);
		return NULL;
	}
	buff->capacity = capacity;
	buff->head_pointer = 0;
	buff->counter = 0;
	return buff;
}

void trace_buffer_destroy(TraceBuffer *tb) {
	if (!tb) return;
	free(tb->entries);
	free(tb);
}

void trace_append(TraceBuffer *tb, const TraceEntry *entry) {
	if (!tb || !entry) return;
	uint32_t idx = tb->head_pointer & (tb->capacity - 1); //cycle
	tb->entries[idx] = *entry;
	tb->head_pointer++;

	if (tb->counter < tb->capacity) tb->counter ++; //amount of valid data taht we are able to read
}

//for backward reconstruction
const TraceEntry *trace_get_last(const TraceBuffer *tb, uint32_t i) {
	if (!tb) return NULL;
	if (i >= tb->counter) return NULL;
	uint32_t idx = (tb->head_pointer -1 -i) & (tb->capacity - 1);
	return &tb->entries[idx];
}

void trace_reset(TraceBuffer *tb) {
	if (!tb) return;
	tb->head_pointer = 0;
	tb->counter = 0;
}

static int pc_from_end(const TraceBuffer *tb, uint64_t pc, int back_id) {
	for (uint32_t i = back_id; i < tb->counter; i++) {
		const TraceEntry *entry = trace_get_last(tb, i);
		if (entry && entry->pc == pc) return i;
	}
	return -1;
}

int trace_get_slice(const TraceBuffer *tb, uint64_t trigger_pc, RegId target_reg, const TraceEntry **out_slice, int max_len) {
	int offset = pc_from_end(tb, trigger_pc, 0);
	if (offset < 0) return 0;
	
	//regs
	uint32_t worklist = (1U << target_reg);
	int slice_len = 0;

	//create slice
	for (uint32_t i = offset; i < tb->counter; i++) {
		const TraceEntry *entry = trace_get_last(tb, i);
		if (!entry) continue;
		InsnMeta *meta = meta_lookup(entry->pc);
		if (meta == NULL) continue;

		//write in needed reg
		uint32_t written_needed = meta->regs_written_mask & worklist;
		if (written_needed != 0) {
			if (slice_len < max_len) out_slice[slice_len++] = entry; //add to slice
			worklist &= ~written_needed; //clear mask for some reg after work, explanation of the current
			worklist |= meta->regs_read_mask; //add reg from which we read fore previous, explanation for read from
			if (worklist == 0) break; //all explained
		}
		
	}
	//reorder for DSE
	for (int i = 0; i < slice_len / 2; i++) {
		const TraceEntry *tmp = out_slice[i];
		out_slice[i] = out_slice[slice_len - 1 - i];
		out_slice[slice_len - 1 - i] = tmp;
	}
	//fallback
	const TraceEntry *trigger = trace_get_last(tb, offset);
	if (trigger && slice_len < max_len && (slice_len == 0 || out_slice[slice_len-1]->pc != trigger->pc)) {
		 out_slice[slice_len++] = trigger;
	}

	return slice_len;
}
