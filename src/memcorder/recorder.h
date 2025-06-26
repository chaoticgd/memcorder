// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#ifndef MEMCORDER_RECORDER_H
#define MEMCORDER_RECORDER_H

#include "channel.h"
#include "event.h"
#include "util.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Sets the buffer of memory that the trace shall be recorded into.
 * @details This must be called on the same thread as
 *          #memcorder_start_recording.
 * @param   buffer           The pointer to the buffer.
 * @param   buffer_size      The size of the buffer.
 * @pre     A recording is not in progress.
 */
void memcorder_set_recording_buffer(char* buffer, size_t buffer_size);

typedef enum {
	MEMCORDER_RECORDING_FINISHED,
	MEMCORDER_RECORDING_RAN_OUT_OF_SPACE,
} MemcorderRecordingStoppedReason;

typedef void MemcorderRecordingStoppedFunction(
	MemcorderRecordingStoppedReason stop_reason,
	void* user_data);

/**
 * @brief   Sets the pointer to the function that will be called when a
 *          recording stops.
 * @details This must be called on the same thread as
 *          #memcorder_start_recording.
 * @param   function         The function pointer.
 * @param   user_data        An arbitrary pointer that will be passed to the
 *                           function when it is called.
 * @pre     A recording is not in progress.
 */
void memcorder_set_recording_stopped_function(
	MemcorderRecordingStoppedFunction* function,
	void* user_data);

/**
 * @brief   Begin recording all writes to the registered buffers to the trace
 *          buffer.
 * @return  One of the following status codes:
 *           - #MEMCORDER_SUCCESS
 *           - #MEMCORDER_
 */
MemcorderStatus memcorder_start_recording();

/**
 * @brief   Stop recording to the trace buffer.
 * @details The user-provided recording stopped function will be called with a
 *          status of #MEMCORDER_SUCCESS.
 *
 *          Note that calling this function is not the only way a recording can
 *          stop.
 */
MemcorderStatus memcorder_stop_recording();

/**
 * @brief   Check whether or not memcorder is currently recording a trace.
 * @return  True if memcorder is recording, false otherwise.
 */
int memcorder_is_recording();

/**
 * @brief   Push an packet into the trace buffer indicating that an event has
 *          begun on the calling thread.
 * @param   type             An integer representing the type of event.
 * @param   channel          The channel with which
 */
void memcorder_begin_event(MemcorderEventType type, MemcorderChannel channel);
/**
 * @brief   Push an packet into the trace buffer indicating that an event has 
 *          ended on the calling thread.
 * @param   type             An integer representing the type of event.
 */
void memcorder_end_event(MemcorderEventType type, MemcorderChannel channel);

#ifdef __cplusplus
}
#endif

#endif
