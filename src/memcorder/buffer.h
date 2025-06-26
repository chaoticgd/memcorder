// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_BUFFERS_H
#define MEMCORDER_BUFFERS_H

/**
 * @file Register your buffers that need to be recorded here.
 */

#include "util.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct A strongly typed handle for a registered buffer.
 */
typedef struct {
	unsigned int index;
} MemcorderBuffer;

/**
 * @brief   Register a buffer to be recorded.
 * @details Ownership of the buffer is not transferred to memcorder and must be
 *          managed by the application.
 * @param   name             A unique string used to identify the buffer.
 * @param   buffer           The pointer to the buffer. Can initially be NULL.
 * @param   size             The size of the buffer in bytes.
 * @param   output           The output parameter for the buffer handle.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_TOO_MANY_BUFFERS
 *           - #MEMCORDER_BUFFER_ALREADY_REGISTERED
 */
MemcorderStatus memcorder_register_buffer(
	const char* name,
	char* buffer,
	size_t size,
	MemcorderBuffer* output);

/**
 * @brief   Lookup a previously registered buffer by its name.
 * @param   name             The name of the buffer, used to look it up.
 * @param   output           The output parameter for the buffer handle.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_BUFFER_NOT_REGISTERED
 */
MemcorderStatus memcorder_lookup_buffer_by_name(
	const char* name,
	MemcorderBuffer* output);

/**
 * @brief   Lookup a previously registered buffer by an address.
 * @param   address          An address that points inside the buffer to be
 *                           output.
 * @param   output           The output parameter for the buffer handle.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_BUFFER_NOT_REGISTERED
 */
MemcorderStatus memcorder_lookup_buffer_by_address(
	void* address,
	MemcorderBuffer* handle_output);

#ifdef __cplusplus
}
#endif

#endif
