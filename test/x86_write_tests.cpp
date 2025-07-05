// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memcorder/memory.h"

#include <gtest/gtest.h>
#include <signal.h>
#include <sys/user.h>

// Here we test the memcorder_enumerate_memory_accesses function by comparing
// the writes it thinks are going to be performed by a given instruction with
// what actually happens on a real x86-64 processor.

#if defined(__linux__) && defined(__x86_64__)

static unsigned char* s_buffer = nullptr;
static unsigned int s_buffer_size = 0;

static unsigned char* s_mirror = nullptr;

static MemcorderMemoryAccess s_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION];
static size_t s_access_count = 0;

static void handle_sigtrap(int sig, siginfo_t* info, void* ucontext)
{
	ucontext_t* context = reinterpret_cast<ucontext_t*>(ucontext);
	void* rip = reinterpret_cast<void*>(context->uc_mcontext.gregs[REG_RIP]);
	
	// Mirror writes made by the last instruction that was executed.
	for (size_t i = 0; i < s_access_count; i++)
	{
		// We're only interested in writes to the main buffer.
		size_t offset = static_cast<unsigned char*>(s_accesses[i].address) - s_buffer;
		if (offset > s_buffer_size || s_buffer_size - offset < s_accesses[i].size)
			continue;
		
		memcpy(s_mirror + offset, s_accesses[i].address, s_accesses[i].size);
	}
	
	// Enumerate writes that will be made by the next instruction.
	MemcorderStatus status = memcorder_enumerate_memory_accesses(
		rip, ucontext, MEMCORDER_MEMORY_ACCESS_TYPE_WRITE, s_accesses, &s_access_count);
	if (status != MEMCORDER_SUCCESS)
		abort();
}

static void set_eflags_trap_bit(bool trap)
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

static void print_diff_row(unsigned char* buffer, unsigned char* other, unsigned int offset, unsigned int size)
{
	for (unsigned int i = 0; i < 0x10; i++)
	{
		if (offset + i >= size)
			break;
		
		if (i % 4 == 0)
			fprintf(stderr, " ");
		
		const char* colour;
		if (buffer[offset + i] == other[offset + i])
			colour = "32"; // green
		else
			colour = "31"; // red
		
		fprintf(stderr, " \033[%sm%02x\033[0m", colour, buffer[offset + i]);
	}
}

static void print_diff(unsigned char* lhs, unsigned char* rhs, unsigned int size)
{
	fprintf(stderr, "****\n");
	fprintf(stderr, "Difference detected between mirror (left) and expected buffer (right):\n");
	fprintf(stderr, "         "
		"   0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f  |"
		"   0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f\n");
	
	for (unsigned int i = 0; i < size; i += 0x10)
	{
		fprintf(stderr, "%8x:", i);
		print_diff_row(lhs, rhs, i, size);
		fprintf(stderr, "  |");
		print_diff_row(rhs, lhs, i, size);
		fprintf(stderr, "\n");
	}
	
	fprintf(stderr, "****\n");
}

static void run_test(void (*run_test_body)(), unsigned int buffer_size)
{
	// Allocate some memory for the buffers if we don't already have some.
	if (buffer_size != s_buffer_size)
	{
		if (s_buffer != nullptr)
			free(s_buffer);
		
		s_buffer = static_cast<unsigned char*>(malloc(buffer_size));
		
		if (s_mirror != nullptr)
			free(s_mirror);
		
		s_mirror = static_cast<unsigned char*>(malloc(buffer_size));
		
		s_buffer_size = buffer_size;
	}
	
	// Fill the buffers so that we can compare them later.
	memset(s_buffer, 0xee, buffer_size);
	memset(s_mirror, 0xee, buffer_size);
	
	// Setup a signal handler to run after each instruction is executed, so that
	// we can detect writes to the main buffer and mirror them.
	static bool handler_set = false;
	if (!handler_set)
	{
		struct sigaction action;
		action.sa_sigaction = handle_sigtrap;
		sigemptyset(&action.sa_mask);
		action.sa_flags = SA_SIGINFO;
		if (sigaction(SIGTRAP, &action, nullptr) != 0)
			abort();
		
		handler_set = true;
	}
	
	// Enable trapping after each instruction. Our signal handler will start
	// getting called after this.
	set_eflags_trap_bit(true);
	
	// Execute the instructions to use for testing.
	run_test_body();
	
	// Disable trapping after each instruction. Our signal handler will stop
	// getting called after this.
	set_eflags_trap_bit(false);

	s_access_count = 0;
	
	// Check if the buffers are equal.
	bool equal = memcmp(s_mirror, s_buffer, buffer_size) == 0;
	
	// If the buffers aren't equal, that means the memory isn't being mirrored
	// correctly, so print out a diff so we can see what went wrong.
	if (!equal)
		print_diff(s_mirror, s_buffer, s_buffer_size);
	
	ASSERT_TRUE(equal);
}

#define X86_WRITE_TEST(name, buffer_size) \
	static void run_test_body_##name(); \
	TEST(MemoryX86, name) \
	{ \
		run_test(run_test_body_##name, buffer_size); \
	} \
	static void run_test_body_##name()

X86_WRITE_TEST(SimpleMov, 64)
{
	s_buffer[0] = 123;
}

#endif
