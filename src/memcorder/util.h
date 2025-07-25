// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_UTIL_H
#define MEMCORDER_UTIL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Status codes used to report whether a memcorder library function succeeded
 * or failed.
 */
typedef enum {
	/**
	 * The operation succeeded.
	 */
	MEMCORDER_SUCCESS,
	/**
	 * Buffer already registered.
	 */
	MEMCORDER_BUFFER_ALREADY_REGISTERED,
	/**
	 * Buffer not registered.
	 */
	MEMCORDER_BUFFER_NOT_REGISTERED,
	/**
	 * Too many buffers have been registered.
	 */
	MEMCORDER_TOO_MANY_BUFFERS,
	/**
	 * Too many channels have been registered.
	 */
	MEMCORDER_TOO_MANY_CHANNELS,
	/**
	 * Too many event types have been registered.
	 */
	MEMCORDER_TOO_MANY_EVENT_TYPES,
	/**
	 * The instruction could not be decoded.
	 */
	MEMCORDER_DECODER_FAILURE,
	/**
	 * Could not calculate address.
	*/
	MEMCORDER_ADDRESS_CALCULATION_FAILURE,
} MemcorderStatus;

const char* memcorder_status_string(MemcorderStatus status);

#define MEMCORDER_ALIGN(value, alignment) ((value) + (-(value) & ((alignment) - 1)))

#ifdef __cplusplus
}
#endif

#endif
