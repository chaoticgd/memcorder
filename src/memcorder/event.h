// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_EVENTS_H
#define MEMCORDER_EVENTS_H

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int index;
} MemcorderEventType;

/**
 * @brief   Register a type of event so that it can be recorded in traces.
 * @param   name             A unique name identifying the type of event.
 * @param   output           The output parameter for the event type handle.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_TOO_MANY_EVENT_TYPES
 */
MemcorderStatus memcorder_register_event_type(
	const char* name,
	MemcorderEventType* output);

#ifdef __cplusplus
}
#endif

#endif
