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
	buff->next_seq_id = 1;
	return buff;
}

void trace_buffer_destroy(TraceBuffer *tb) {
	if (!tb) return;
	free(tb->entries);
	free(tb);
}

const TraceEntry *trace_append(TraceBuffer *tb, const TraceEntry *entry) {
	if (!tb || !entry || tb->next_seq_id == 0) {
		return NULL;
	}
	uint32_t idx = tb->head_pointer & (tb->capacity - 1);
	tb->entries[idx] = *entry;
	tb->entries[idx].seq_id = tb->next_seq_id++;
	tb->head_pointer++;
	if (tb->counter < tb->capacity) tb->counter++;
	return &tb->entries[idx];
}

//for backward reconstruction
const TraceEntry *trace_get_last(const TraceBuffer *tb, uint32_t i) {
	if (!tb) return NULL;
	if (i >= tb->counter) return NULL;
	uint32_t idx = (tb->head_pointer -1 -i) & (tb->capacity - 1);
	return &tb->entries[idx];
}

const TraceEntry *trace_find_seq(const TraceBuffer *tb, uint64_t seq_id, uint32_t *back_index) {
	if (!tb || seq_id == 0) return NULL;
	for (uint32_t i = 0; i < tb->counter; i++) {
		const TraceEntry *entry = trace_get_last(tb, i);
		if (entry && entry->seq_id == seq_id) {
			if (back_index) {
				*back_index = i;
			}
			return entry;
		}
	}
	return NULL;
}

void trace_reset(TraceBuffer *tb) {
	if (!tb) return;
	tb->head_pointer = 0;
	tb->counter = 0;
}

BranchEventBuffer *branch_event_buffer_create(uint32_t capacity) {
	if (capacity == 0 || (capacity & (capacity - 1U)) != 0) {
		return NULL;
	}
	BranchEventBuffer *buffer = calloc(1, sizeof(*buffer));
	if (!buffer) return NULL;
	buffer->events = calloc(capacity, sizeof(*buffer->events));
	if (!buffer->events) {
		free(buffer);
		return NULL;
	}
	buffer->capacity = capacity;
	buffer->next_event_id = 1;
	return buffer;
}

void branch_event_buffer_destroy(BranchEventBuffer *buffer) {
	if (!buffer) return;
	free(buffer->events);
	free(buffer);
}

const BranchEvent *branch_event_append(BranchEventBuffer *buffer, const BranchEvent *event) {
	if (!buffer || !event || buffer->next_event_id == 0) {
		return NULL;
	}
	uint32_t index =buffer->head_pointer & (buffer->capacity - 1U);
	buffer->events[index] = *event;
	buffer->events[index].event_id = buffer->next_event_id++;
	buffer->head_pointer++;
	if (buffer->counter < buffer->capacity) {
		buffer->counter++;
	}
	return &buffer->events[index];
}

const BranchEvent *branch_event_get_last(const BranchEventBuffer *buffer, uint32_t back_index) {
	if (!buffer || back_index >= buffer->counter) {
		return NULL;
	}
	uint32_t index = (buffer->head_pointer - 1U - back_index) & (buffer->capacity - 1U);
	return &buffer->events[index];
}

void branch_event_buffer_reset(BranchEventBuffer *buffer) {
	if (!buffer) return;
	buffer->head_pointer = 0;
	buffer->counter = 0;
}
