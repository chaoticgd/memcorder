// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memcorder/memory.h"

#define VERBOSE_WRITE_TESTS 1

#if VERBOSE_WRITE_TESTS
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

static unsigned char s_buffer[BUFFER_SIZE];
static unsigned char s_mirror[BUFFER_SIZE];

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
		if (offset > BUFFER_SIZE || BUFFER_SIZE - offset < s_accesses[i].size)
			continue;
		
		memcpy(s_mirror + offset, s_accesses[i].address, s_accesses[i].size);
	}
	
#ifdef VERBOSE_WRITE_TESTS
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	
	ZydisDisassembledInstruction instruction;
	ZyanStatus disassemble_status = ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64, context->uc_mcontext.gregs[REG_RIP], rip, 15, &instruction);
	if (!ZYAN_SUCCESS(disassemble_status))
		abort();
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
		abort();

#ifdef VERBOSE_WRITE_TESTS
	for (size_t i = 0; i < s_access_count; i++)
	{
		MemcorderMemoryAccess* access = &s_accesses[i];
		fprintf(stderr, "\t%s %p %d\n",
			(access->type == MEMCORDER_MEMORY_ACCESS_TYPE_READ) ? "read" : "write",
			access->address,
			access->size);
	}
#endif
}

static void set_eflags_trap_bit(bool trap)
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
	for (unsigned int i = 0; i < BUFFER_SIZE; i++)
		if (s_buffer[i] != s_mirror[i] && (s_buffer[i] != 0xbb || s_mirror[i] != 0xdd))
			return false;
	
	return true;
}

static void print_diff_row(unsigned char* buffer, unsigned char* other, unsigned int offset)
{
	for (unsigned int i = 0; i < 0x10; i++)
	{
		if (offset + i >= BUFFER_SIZE)
			break;
		
		if (i % 4 == 0)
			fprintf(stderr, " ");
		
		const char* colour;
		if (buffer[offset + i] == other[offset + i])
			colour = "32"; // green
		else if (s_buffer[offset + i] == 0xbb && s_mirror[offset + i] == 0xdd)
			colour = "38"; // gray
		else
			colour = "31"; // red
		
		fprintf(stderr, " \033[%sm%02x\033[0m", colour, buffer[offset + i]);
	}
}

static void print_diff()
{
	fprintf(stderr, "****\n");
	fprintf(stderr, "Difference detected between mirror (left) and expected buffer (right):\n");
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
	
	fprintf(stderr, "****\n");
}

// Some variables to use as input operands.
static int zero;
static int one;
static int two;

static void run_test(void (*run_test_body)())
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
	bool equal = compare_buffers();
	
	// If the comparison above failed, that means the memory isn't being
	// mirrored correctly, so print out a diff so we can see what went wrong.
#ifdef VERBOSE_WRITE_TESTS
	print_diff();
#else
	if (!equal)
		print_diff();
#endif
	
	ASSERT_TRUE(equal);
}

#define X86_WT(name) \
	static void run_test_body_##name(); \
	TEST(X86Write, name) \
	{ \
		run_test(run_test_body_##name); \
	} \
	static void run_test_body_##name()

// *****************************************************************************
// Instructions (A-L)
// *****************************************************************************

X86_WT(ADC_Imm8ToMem8) { asm volatile("adcb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Imm8ToMem16) { asm volatile("adcw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Imm8ToMem32) { asm volatile("adcl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Imm8ToMem64) { asm volatile("adcq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Imm16ToMem16) { asm volatile("adcw $1234, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Imm32ToMem32) { asm volatile("adcl $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Imm32ToMem64) { asm volatile("adcq $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADC_Reg8ToMem8) { asm volatile("movb $123, %%al\n adcb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WT(ADC_Reg16ToMem16) { asm volatile("movw $123, %%ax\n adcw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WT(ADC_Reg32ToMem32) { asm volatile("movl $123, %%eax\n adcl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WT(ADC_Reg64ToMem64) { asm volatile("movq $123, %%rax\n adcq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

X86_WT(ADD_Imm8ToMem8) { asm volatile("addb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Imm8ToMem16) { asm volatile("addw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Imm8ToMem32) { asm volatile("addl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Imm8ToMem64) { asm volatile("addq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Imm16ToMem16) { asm volatile("addw $1234, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Imm32ToMem32) { asm volatile("addl $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Imm32ToMem64) { asm volatile("addq $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WT(ADD_Reg8ToMem8) { asm volatile("movb $123, %%al\n addb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WT(ADD_Reg16ToMem16) { asm volatile("movw $123, %%ax\n addw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WT(ADD_Reg32ToMem32) { asm volatile("movl $123, %%eax\n addl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WT(ADD_Reg64ToMem64) { asm volatile("movq $123, %%rax\n addq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }


#endif
