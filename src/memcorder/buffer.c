// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "buffer.h"

typedef struct {
	char* buffer;
	size_t size;
} MemcorderBufferEntry;

MemcorderStatus memcorder_register_buffer(
	const char* name,
	char* buffer,
	size_t size,
	MemcorderBuffer* output)
{
	return MEMCORDER_SUCCESS;
}

MemcorderStatus memcorder_lookup_buffer_by_name(
	const char* name,
	MemcorderBuffer* handle_output)
{
	return MEMCORDER_SUCCESS;
}

MemcorderStatus memcorder_lookup_buffer_by_address(
	void* address,
	MemcorderBuffer* handle_output)
{
	return MEMCORDER_SUCCESS;
}
