// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_UTIL_H
#define MEMCORDER_UTIL_H

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
} MemcorderStatus;

const char* memcorder_status_string(MemcorderStatus status);

#ifdef __cplusplus
}
#endif

#endif
