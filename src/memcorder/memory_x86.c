// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memory.h"

#include <Zydis/Decoder.h>

MemcorderStatus memcorder_enumerate_memory_accesses(
	void* instruction,
	void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count)
{
	return MEMCORDER_SUCCESS;
}
