#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <capstone/capstone.h>
#include "dta.h"
#include "trace.h"
#include "dse.h"
#include "aux_trace.h"

DseAuxRing *dse_aux_create(uint32_t capacity) {
	if (!(capacity > 0 && (capacity & (capacity - 1)) == 0)) return NULL;
	DseAuxRing *r = malloc(sizeof(*r));
	if (!r) return NULL;
	r->entries = calloc(capacity, sizeof(InsnAux));
	if (!r->entries) { free(r); return NULL; }
	r->capacity = capacity;
	return r;
}

void dse_aux_destroy(DseAuxRing *r) {
	if (!r) return;
	free(r->entries);
	free(r);
}

void dse_aux_record(DseAuxRing *r, const TraceBuffer *tb, const InsnAux *aux) {
	if (!r || !tb || !aux) return;
	r->entries[tb->head_pointer & (r->capacity - 1)] = *aux;
}

const InsnAux *dse_aux_for(const DseAuxRing *r, const TraceBuffer *tb, const TraceEntry *e) {
	if (!r || !tb || !e) return NULL;
	uint32_t idx = (uint32_t)(e - tb->entries);
	if (idx >= r->capacity) return NULL;
	return &r->entries[idx];
}
