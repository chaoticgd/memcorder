// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "recorder.h"

#include <assert.h>

void* recording_buffer;
size_t s_recording_buffer_size;
MemcorderRecordingStoppedFunction* s_recording_stopped_function;
void* s_recording_stopped_user_data;

int s_is_recording;

void memcorder_set_recording_buffer(
	char* buffer,
	size_t buffer_size)
{
	assert(!memcorder_is_recording());
	
	recording_buffer = buffer;
	s_recording_buffer_size = buffer_size;
}

void memcorder_set_recording_stopped_function(
	MemcorderRecordingStoppedFunction* function,
	void* user_data)
{
	assert(!memcorder_is_recording());
	
	s_recording_stopped_function = function;
	s_recording_stopped_user_data = user_data;
}

static void set_eflags_trap_bit(int trap)
{
	if (trap)
	{
		asm volatile(
			"pushf\n"
			"orl $0x100, (%rsp)\n"
			"popf\n");
	}
	else
	{
		asm volatile(
			"pushf\n"
			"andl $0xfffffffffffffeff, (%rsp)\n"
			"popf\n");
	}
}

MemcorderStatus memcorder_start_recording()
{
	s_is_recording = 1;
	
	set_eflags_trap_bit(1);
	
	return MEMCORDER_SUCCESS;
}

MemcorderStatus memcorder_stop_recording()
{
	set_eflags_trap_bit(0);
	
	s_is_recording = 0;
	
	return MEMCORDER_SUCCESS;
}

int memcorder_is_recording()
{
	return s_is_recording;
}
