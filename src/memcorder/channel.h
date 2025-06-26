// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_CHANNEL_H
#define MEMCORDER_CHANNEL_H

#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @struct A strongly typed handle for a channel.
 */
typedef struct {
	unsigned int index;
} MemcorderChannel;

/**
 * @brief   Register a channel which events can belong to.
 * @param   name             The name of the channel
 * @param   parent           The parent of this channel, or NULL if this channel
 *                           has no parent.
 *
 *                           To facilitate the calling of this function from
 *                           inside a global constructor, the #MemcorderChannel
 *                           object pointed to does not have to be valid until
 *                           #memcorder_start_recording is called.
 * @param   output           The output parameter for the channel handle.
 *
 *                           This pointer only to be valid when
 *                           #memcorder_register_channel is called.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_TOO_MANY_CHANNELS
 */
MemcorderStatus memcorder_register_channel(
	const char* name,
	const MemcorderChannel* parent,
	MemcorderChannel* output);

#ifdef __cplusplus
}
#endif

#endif
