// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memcorder/memory.h"

#define VERBOSE_X86_READ_TESTS 1

#ifdef VERBOSE_X86_READ_TESTS
#include <Zydis/Decoder.h>
#include <Zydis/Disassembler.h>
#endif

#include <gtest/gtest.h>
#include <signal.h>
#include <sys/user.h>

// Here we test the memcorder_enumerate_memory_accesses function by comparing
// what reads it thinks are going to happen with an expected read that's
// manually defined for each test, and then we do an additional check to make
// sure that the expected read is correct.

#if defined(__linux__) && defined(__x86_64__)

#define BUFFER_SIZE 64

struct ExpectedRead
{
	size_t offset;
	size_t size;
	uint64_t value;
};

static unsigned char s_buffer[BUFFER_SIZE];

static MemcorderMemoryAccess s_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION];
static size_t s_access_count = 0;

static ExpectedRead s_expected_read;
static bool s_found_expected_read = false;

static uint64_t s_input;
static uint64_t s_output;

static void handle_sigtrap(
	int sig,
	siginfo_t* info,
	void* ucontext)
{
	ucontext_t* context = reinterpret_cast<ucontext_t*>(ucontext);
	void* rip = reinterpret_cast<void*>(context->uc_mcontext.gregs[REG_RIP]);
	
#ifdef VERBOSE_X86_READ_TESTS
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	
	ZydisDisassembledInstruction instruction;
	ZyanStatus disassemble_status = ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64, context->uc_mcontext.gregs[REG_RIP], rip, 15, &instruction);
	if (!ZYAN_SUCCESS(disassemble_status))
	{
		fprintf(stderr, "ZydisDisassembleIntel failed\n");
		abort();
	}
	for (size_t i = 0; i < instruction.info.length; i++)
		fprintf(stderr, "%02hhx ", reinterpret_cast<char*>(rip)[i]);
	if (instruction.info.length < 12)
		for (size_t i = 0; i < 12 - instruction.info.length; i++)
			fprintf(stderr, "   ");
	fprintf(stderr, "%s\n", instruction.text);
#endif
	
	// Enumerate reads that will be made by the next instruction.
	MemcorderStatus enumerate_status = memcorder_enumerate_memory_accesses(
		rip, ucontext, MEMCORDER_MEMORY_ACCESS_TYPE_READ, s_accesses, &s_access_count);
	if (enumerate_status != MEMCORDER_SUCCESS)
	{
		fprintf(stderr, "memcorder_enumerate_memory_accesses: %s\n",
			memcorder_status_string(enumerate_status));
		abort();
	}
	
	// Check if the instruction performed the expected read.
	for (size_t i = 0; i < s_access_count; i++)
	{
		const MemcorderMemoryAccess* access = &s_accesses[i];
		long long offset = static_cast<unsigned char*>(access->address) - s_buffer;
		
		fprintf(stderr, "\tread %p %d\t\t\t\t0x%llx\n",
			access->address,
			access->size,
			offset);
		
		if (access->type == MEMCORDER_MEMORY_ACCESS_TYPE_READ
			&& access->address == s_buffer + s_expected_read.offset
			&& access->size == s_expected_read.size
			&& memcmp(access->address, s_buffer + s_expected_read.offset, s_expected_read.size) == 0)
		{
			s_found_expected_read = true;
			break;
		}
	}
}

static void set_eflags_trap_bit(
	bool trap)
{
	if (trap)
	{
		asm volatile(
			"pushf\n"
			"orl $0x100, (%%rsp)\n"
			"popf\n"
			"nop\n"
			"nop\n"
			"nop\n"
			::: "memory");
	}
	else
	{
		asm volatile(
			"pushf\n"
			"andl $0xfffffffffffffeff, (%%rsp)\n"
			"popf\n"
			::: "memory");
	}
}

static void run_test(
	void (*run_test_body)(),
	void (*run_result_reader)(),
	void (*run_verifier)())
{
	// Fill the buffer with a pattern such that reading from two different
	// addresses in it will yield different results.
	for (unsigned char i = 0; i < BUFFER_SIZE; i++)
		s_buffer[i] = i;
	
	// Setup a signal handler to run after each instruction is executed, so that
	// we can detect reads from the buffer.
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
	
	s_found_expected_read = false;
	
	// Enable trapping after each instruction. Our signal handler will start
	// getting called after this.
	set_eflags_trap_bit(true);
	
	// Execute the instructions to use for testing.
	run_test_body();
	
	// Disable trapping after each instruction. Our signal handler will stop
	// getting called after this.
	set_eflags_trap_bit(false);
	
	// Make sure that we successfully predicted that the test instructions was
	// going to perform the expected read.
	ASSERT_TRUE(s_found_expected_read);
	
	if (!run_verifier)
		return;
	
	// Make sure the result of said instruction is the same as the result of
	// running the same instruction with the expected value as input (to make
	// sure it actually read from the memory location we thought it did).
	run_result_reader();
	uint64_t test_output = s_output;
	memset(&s_input, 0, sizeof(s_input));
	memcpy(&s_input, &s_expected_read.value, s_expected_read.size);
	s_output = s_input;
	run_verifier();
	uint64_t verifier_output = s_output;
	switch (s_expected_read.size)
	{
		case 8: test_output &= 0xff; verifier_output &= 0xff; break;
		case 16: test_output &= 0xffff; verifier_output &= 0xffff; break;
		case 32: test_output &= 0xffffffff; verifier_output &= 0xffffffff; break;
	}
	ASSERT_EQ(test_output, verifier_output);
}

#define X86_READ_TEST(name, expected, test_body, result_reader, verifier) \
	TEST(X86Read, name) \
	{ \
		s_expected_read = ExpectedRead expected; \
		void (*run_test_body)() = test_body; \
		void (*run_result_reader)() = result_reader; \
		void (*run_verifier)() = verifier; \
		run_test(run_test_body, run_result_reader, run_verifier); \
	}

#define ASM asm volatile

// *****************************************************************************
// Instructions (A-L)
// ***************************************************************************** }

X86_READ_TEST(ADC_Imm8ToMem8, ({0, 1, 0x00}),
	([]() { ASM("clc\n adcb $123, %0" : "+m" (s_buffer)); }),
	([]() { s_output = s_buffer[0]; }),
	([]() { ASM("clc\n adcb $123, %%al" : "+a" (s_output) :: "memory");  }));

#endif
