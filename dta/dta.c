#include "dta.h"
#include<stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define page_size 4096

struct ShadowMemory {
	uint8_t  arch;
	void    *base;
	size_t   size;
};


ShadowMemory *shadow_create(uint8_t arch) {
	if (arch == 32) {
		ShadowMemory *sm = malloc(sizeof(ShadowMemory));
		size_t size = 1ULL << 32;
		void *base = mmap(NULL, size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (base == MAP_FAILED) {
			free(sm);
			return NULL;
		}
		sm->arch = arch;
		sm->base = base;
		sm->size = size;
		return sm;
	} else { //TODO
		return NULL;
	}
}

void shadow_destroy(ShadowMemory *sm) {
	if (!sm) return;
	munmap(sm->base, sm->size);
	free(sm);
}

void shadow_taint_byte(ShadowMemory *sm, uint64_t addr, uint64_t ip) {
	(void)ip;
	if (sm->arch == 32) { //IMPLEMENT NOT IN DTA CODE!!!!!!!!!!1
		addr &= 0xFFFFFFFFULL;
	} else {
		//TODO
	}
	mprotect((char*)sm->base + (addr & ~(page_size - 1)), page_size, 3);
	*((uint8_t *)sm->base + addr) = 1;
}

void shadow_untaint_byte(ShadowMemory *sm, uint64_t addr) {
	*((uint8_t *)sm->base + addr) = 0;
}

bool shadow_is_tainted(ShadowMemory *sm, uint64_t addr) {
	return *((uint8_t *)sm->base + addr) != 0;
}

bool shadow_page_has_taint(ShadowMemory *sm, uint64_t addr) { //TODO optimize
	uint8_t *base = (uint8_t*)sm->base;
	for(uint64_t i = addr & ~(page_size -1); i < (addr & ~(page_size - 1)) + page_size; i++) {
		if (base[i]) return true;
	}
	return false;
}
