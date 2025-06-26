// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "util.h"

const char* memcorder_status_string(MemcorderStatus status)
{
	switch (status)
	{
		case MEMCORDER_SUCCESS:
			return "The operation succeeded.";
		case MEMCORDER_BUFFER_ALREADY_REGISTERED:
			return "Buffer already registered.";
		case MEMCORDER_BUFFER_NOT_REGISTERED:
			return "Buffer not registered.";
		case MEMCORDER_TOO_MANY_BUFFERS:
			return "Too many buffers have been registered.";
		case MEMCORDER_TOO_MANY_CHANNELS:
			return "Too many channels have been registered.";
		case MEMCORDER_TOO_MANY_EVENT_TYPES:
			return "Too many event types have been registered.";
	}
	
	return "Invalid status code.";
}
