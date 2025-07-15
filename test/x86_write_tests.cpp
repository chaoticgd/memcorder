// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memcorder/memory.h"

#define VERBOSE_X86_WRITE_TESTS 1

#ifdef VERBOSE_X86_WRITE_TESTS
#include <Zydis/Decoder.h>
#include <Zydis/Disassembler.h>
#endif

#include <gtest/gtest.h>
#include <signal.h>
#include <sys/user.h>

// Here we test the memcorder_enumerate_memory_accesses function by comparing
// the writes it thinks are going to be performed by a given instruction with
// what actually happens on a real x86-64 processor.

#if defined(__linux__) && defined(__x86_64__)

#define BUFFER_SIZE 64

// The main buffer, which will be written to directly.
static unsigned char s_buffer[BUFFER_SIZE];

// The mirror buffer, which will be written to by our signal handler.
static unsigned char s_mirror[BUFFER_SIZE];

static MemcorderMemoryAccess s_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION];
static size_t s_access_count = 0;

// Whether or not to treat 0xBBs being copied to the mirror buffer a failure.
static bool s_relaxed = false;

static void handle_sigtrap(
	int sig,
	siginfo_t* info,
	void* ucontext)
{
	ucontext_t* context = reinterpret_cast<ucontext_t*>(ucontext);
	void* rip = reinterpret_cast<void*>(context->uc_mcontext.gregs[REG_RIP]);
	
	// Mirror writes made by the last instruction that was executed.
	for (size_t i = 0; i < s_access_count; i++)
	{
		MemcorderMemoryAccess* access = &s_accesses[i];
		
		// We're only interested in writes to the main buffer.
		size_t offset = static_cast<unsigned char*>(access->address) - s_buffer;
		if (offset > BUFFER_SIZE || BUFFER_SIZE - offset < access->size)
			continue;
		
		memcpy(s_mirror + offset, access->address, access->size);
	}
	
#ifdef VERBOSE_X86_WRITE_TESTS
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
	
	// Enumerate writes that will be made by the next instruction.
	MemcorderStatus enumerate_status = memcorder_enumerate_memory_accesses(
		rip, ucontext, MEMCORDER_MEMORY_ACCESS_TYPE_WRITE, s_accesses, &s_access_count);
	if (enumerate_status != MEMCORDER_SUCCESS)
	{
		fprintf(stderr, "memcorder_enumerate_memory_accesses: %s\n",
			memcorder_status_string(enumerate_status));
		abort();
	}

#ifdef VERBOSE_X86_WRITE_TESTS
	for (size_t i = 0; i < s_access_count; i++)
	{
		MemcorderMemoryAccess* access = &s_accesses[i];
		long long offset = static_cast<unsigned char*>(access->address) - s_buffer;
		
		fprintf(stderr, "\t%s %p %d\t\t\t\t0x%llx\n",
			(access->type == MEMCORDER_MEMORY_ACCESS_TYPE_READ) ? "read" : "write",
			access->address,
			access->size,
			offset);
	}
#endif
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

static bool compare_buffers()
{
	bool result = true;
	bool would_have_failed_if_strict = false;
	
	for (unsigned int i = 0; i < BUFFER_SIZE; i++)
	{
		if (s_buffer[i] == s_mirror[i])
		{
			if (s_mirror[i] == 0xbb)
			{
				// This may indicate that the wrong bytes were copied, or it
				// could just be that the instruction being tested couldn't
				// modify all the output bytes to be different to the input.
				
				if (s_relaxed)
				{
					would_have_failed_if_strict = true;
					continue;
				}
				else
				{
					result = false;
				}
			}
		}
		else if (s_buffer[i] != 0xbb || s_mirror[i] != 0xdd)
		{
			result = false;
		}
		else
		{
			// Neither buffers have been modified.
		}
	}
	
	// If the s_relaxed test flag wasn't required for the test to pass, it
	// should've been made a strict test instead. That means there's something
	// going on that should be investigated.
	EXPECT_TRUE(!s_relaxed || would_have_failed_if_strict);
	
	return result;
}

static void print_diff_row(
	unsigned char* buffer,
	unsigned char* other,
	unsigned int offset)
{
	for (unsigned int i = 0; i < 0x10; i++)
	{
		if (offset + i >= BUFFER_SIZE)
			break;
		
		if (i % 4 == 0)
			fprintf(stderr, " ");
		
		const char* colour;
		if (s_buffer[offset + i] == 0xbb && s_mirror[offset + i] == 0xdd)
			colour = "30"; // gray
		else if (buffer[offset + i] == other[offset + i])
			if (s_mirror[offset + i] != 0xbb)
				colour = "32"; // green
			else
				colour = "33"; // yellow
		else
			colour = "31"; // red
		
		fprintf(stderr, " \033[%sm%02x\033[0m", colour, buffer[offset + i]);
	}
}

static void print_diff()
{
	fprintf(stderr, "         "
		"   0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f  |"
		"   0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f\n");
	
	for (unsigned int i = 0; i < BUFFER_SIZE; i += 0x10)
	{
		fprintf(stderr, "%8x:", i);
		print_diff_row(s_buffer, s_mirror, i);
		fprintf(stderr, "  |");
		print_diff_row(s_mirror, s_buffer, i);
		fprintf(stderr, "\n");
	}
}

// Some variables to use as input operands.
static int zero;
static int one;
static int two;

static void run_test(
	void (*run_test_body)())
{
	// Fill the buffers so that we can compare them later. We fill them with
	// different values so that we can detect when bytes are copied between
	// them incorrectly.
	memset(s_buffer, 0xbb, BUFFER_SIZE);
	memset(s_mirror, 0xdd, BUFFER_SIZE);
	
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
	
	// These variables may be clobbered by some of the test case, so they need
	// to be reset here.
	zero = 0;
	one = 1;
	two = 2;
	
	// Enable trapping after each instruction. Our signal handler will start
	// getting called after this.
	set_eflags_trap_bit(true);
	
	// Execute the instructions to use for testing.
	run_test_body();
	
	// Disable trapping after each instruction. Our signal handler will stop
	// getting called after this.
	set_eflags_trap_bit(false);
	
	s_access_count = 0;
	
	// Compare the contents of the buffers, ignoring the special pattern they
	// were filled with initially.
	const bool equal = compare_buffers();
	
	// If the comparison above failed, that means the memory isn't being
	// mirrored correctly, so print out a diff so we can see what went wrong.
#ifdef VERBOSE_X86_WRITE_TESTS
	const bool print = true;
#else
	const bool print = !equal;
#endif
	
	if (print)
	{
		fprintf(stderr, "****\n");
		if (!equal)
			fprintf(stderr, "Difference detected between main buffer (left) and mirror buffer (right):\n");
		print_diff();
		fprintf(stderr, "****\n");
	}
	
	EXPECT_TRUE(equal);
}

// Strict write test. This variant will fail if the mirror buffer contains any
// 0xBBs (which could possibly mean that the wrong bytes were copied).
#define X86_WTS(name) \
	static void run_test_body_##name(); \
	TEST(X86Write, name) \
	{ \
		s_relaxed = false; \
		run_test(run_test_body_##name); \
	} \
	static void run_test_body_##name()

// Relaxed write test. Only use this if it is infeasible to use X86_WTS (e.g.
// because the instruction being tested has operands that aren't large enough to
// affect the most significant byte of the output).
#define X86_WTR(name) \
	static void run_test_body_##name(); \
	TEST(X86Write, name) \
	{ \
		s_relaxed = true; \
		run_test(run_test_body_##name); \
	} \
	static void run_test_body_##name()

#define ASMV asm volatile

// *****************************************************************************
// Instructions (A-L)
// *****************************************************************************

X86_WTS(ADC_Imm8ToMem8) { ASMV("adcb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Imm8ToMem16) { ASMV("adcw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADC_Imm8ToMem32) { ASMV("adcl $123, (%0)" :: "r" (s_buffer) : "memory"); }

X86_WTR(ADC_Imm8ToMem64) { ASMV("adcq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Imm16ToMem16) { ASMV("adcw $12345, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Imm32ToMem32) { ASMV("adcl $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADC_Imm32ToMem64) { ASMV("adcq $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Reg8ToMem8) { ASMV("movb $123, %%al\n adcb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WTS(ADC_Reg16ToMem16) { ASMV("movw $12345, %%ax\n adcw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WTS(ADC_Reg32ToMem32) { ASMV("movl $1234567890, %%eax\n adcl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WTS(ADC_Reg64ToMem64) { ASMV("movq $12345678901234567890, %%rax\n adcq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

X86_WTS(ADD_Imm8ToMem8) { ASMV("addb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Imm8ToMem16) { ASMV("addw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADD_Imm8ToMem32) { ASMV("addl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADD_Imm8ToMem64) { ASMV("addq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Imm16ToMem16) { ASMV("addw $12345, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Imm32ToMem32) { ASMV("addl $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADD_Imm32ToMem64) { ASMV("addq $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Reg8ToMem8) { ASMV("movb $123, %%al\n addb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WTS(ADD_Reg16ToMem16) { ASMV("movw $12345, %%ax\n addw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WTS(ADD_Reg32ToMem32) { ASMV("movl $1234567890, %%eax\n addl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WTS(ADD_Reg64ToMem64) { ASMV("movq $12345678901234567890, %%rax\n addq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

X86_WTS(AND_Imm8ToMem8) { ASMV("andb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm8ToMem16) { ASMV("andw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm8ToMem32) { ASMV("andl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm8ToMem64) { ASMV("andq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm16ToMem16) { ASMV("andw $1234, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm32ToMem32) { ASMV("andl $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm32ToMem64) { ASMV("andq $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Reg8ToMem8) { ASMV("movb $123, %%al\n andb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WTS(AND_Reg16ToMem16) { ASMV("movw $123, %%ax\n andw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WTS(AND_Reg32ToMem32) { ASMV("movl $123, %%eax\n andl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WTS(AND_Reg64ToMem64) { ASMV("movq $123, %%rax\n andq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

#define X86_WTS_BTC_SMALL(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg16ToMem16) \
		{ ASMV("movw $" #bit_offset ", %%ax\n btcw %%ax, (%0)" :: "r" (s_buffer + 32) : "ax", "memory"); } \
	X86_WTS(BTC_##name##_Reg32ToMem32) \
		{ ASMV("movl $" #bit_offset ", %%eax\n btcl %%eax, (%0)" :: "r" (s_buffer + 32) : "eax", "memory"); } \
	X86_WTS(BTC_##name##_Reg64ToMem64) \
		{ ASMV("movq $" #bit_offset ", %%rax\n btcq %%rax, (%0)" :: "r" (s_buffer + 32) : "rax", "memory"); } \
	X86_WTS(BTC_##name##_Imm8ToMem16) \
		{ ASMV("btcw $" #bit_offset ", (%0)" :: "r" (s_buffer + 32) : "memory"); } \
	X86_WTS(BTC_##name##_Imm8ToMem32) \
		{ ASMV("btcl $" #bit_offset ", (%0)" :: "r" (s_buffer + 32) : "memory"); } \
	X86_WTS(BTC_##name##_Imm8ToMem64) \
		{ ASMV("btcq $" #bit_offset ", (%0)" :: "r" (s_buffer + 32) : "memory"); }
X86_WTS_BTC_SMALL(Zero, 0)
X86_WTS_BTC_SMALL(Positive4, 4)
X86_WTS_BTC_SMALL(Positive64, 64)
X86_WTS_BTC_SMALL(Positive123, 123)
X86_WTS_BTC_SMALL(Positive127, 127)
X86_WTS_BTC_SMALL(Negative4, -4)
X86_WTS_BTC_SMALL(Negative64, -64)
X86_WTS_BTC_SMALL(Negative123, -123)
X86_WTS_BTC_SMALL(Negative128, -128)
#define X86_WTS_BTC_LARGE64(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg64ToMem64) \
		{ ASMV("movq $" #bit_offset ", %%rax\n btcq %%rax, (%0)" \
			:: "r" ((s_buffer + 32) - (bit_offset / 8)) : "rax", "memory"); }
#define X86_WTS_BTC_LARGE32(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg32ToMem32) \
		{ ASMV("movl $" #bit_offset ", %%eax\n btcl %%eax, (%0)" \
			:: "r" ((s_buffer + 32) - (bit_offset / 8)) : "eax", "memory"); } \
		X86_WTS_BTC_LARGE64(name, bit_offset)
#define X86_WTS_BTC_LARGE16(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg16ToMem16) \
		{ ASMV("movw $" #bit_offset ", %%ax\n btcw %%ax, (%0)" \
			:: "r" ((s_buffer + 32) - (bit_offset / 8)) : "ax", "memory"); } \
		X86_WTS_BTC_LARGE32(name, bit_offset)
X86_WTS_BTC_LARGE16(MaxSigned16, 32767);
X86_WTS_BTC_LARGE32(MaxSigned32, 2147483647);
// TODO: Test some more out of range values here. Minimums don't work right.

// NOTE: Assume BTR and BTS behave similarly.

#endif
