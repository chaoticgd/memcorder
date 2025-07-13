// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_MEMORY_H
#define MEMCORDER_MEMORY_H

#include "util.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION 20

typedef enum {
	MEMCORDER_MEMORY_ACCESS_TYPE_READ = 1 << 0,
	MEMCORDER_MEMORY_ACCESS_TYPE_WRITE = 1 << 1
} MemcorderMemoryAccessType;

typedef struct {
	void* address;
	int size;
	MemcorderMemoryAccessType type;
} MemcorderMemoryAccess;

/**
 * @brief   Enumerate all the memory accesses that would be made if the given
 *          instruction was executed with the given context.
 * @param   instruction      Pointer to the instruction.
 * @param   platform_context Architecture and OS-dependent context structure
 *                           containing the values of all the architectural
 *                           registers, used for determining what addresses
 *                           would be accessed (and, in the case of conditional
 *                           moves, what memory accesses would be made).
 * @param   types            Whether to enumerate reads, writes, or both.
 * @param   output_accesses  The output parameter for the array of memory
 *                           accesses that would be made.
 * @param   output_count     The output parameter for the number of memory
 *                           accesses that would be made.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_INVALID_INSTRUCTION
 */
MemcorderStatus memcorder_enumerate_memory_accesses(
	void* instruction,
	const void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count);

#ifdef __cplusplus
}
#endif

#endif
