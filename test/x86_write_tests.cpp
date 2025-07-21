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

#include <immintrin.h>

#define BUFFER_SIZE 512

// The main buffer, which will be written to directly.
static unsigned char s_buffer[BUFFER_SIZE];

// The mirror buffer, which will be written to by our signal handler.
static unsigned char s_mirror[BUFFER_SIZE];

static MemcorderMemoryAccess s_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION];
static size_t s_access_count = 0;

// Whether or not to treat 0xBBs being copied to the mirror buffer a failure.
static bool s_strict = true;

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
		
		fprintf(stderr, "\twrite %p %d\t\t\t\t0x%llx\n",
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

static bool compare_buffers()
{
	for (int i = 0; i < BUFFER_SIZE; i++)
	{
		if (s_buffer[i] == s_mirror[i])
		{
			if (s_mirror[i] == 0xbb)
			{
				// This may indicate that the wrong bytes were copied, or it
				// could just be that the instruction being tested couldn't
				// modify all the output bytes to be different to the input.
				
				if (s_strict)
					return false;
			}
		}
		else if (s_buffer[i] != 0xbb || s_mirror[i] != 0xdd)
		{
			return false;
		}
		else
		{
			// Neither buffers have been modified.
		}
	}
	
	return true;
}

static int last_byte_written()
{
	for (int i = BUFFER_SIZE - 1; i >= 0; i--)
		if (s_buffer[i] != 0xbb || s_mirror[i] != 0xdd)
			return i;
	
	return -1;
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
	int size;
	int last_byte = last_byte_written();
	if (last_byte != -1)
		size = MEMCORDER_ALIGN(last_byte + 1, 0x10);
	else
		size = 0x10;
	
	fprintf(stderr, "         "
		"   0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f  |"
		"   0  1  2  3   4  5  6  7   8  9  a  b   c  d  e  f\n");
	
	for (int i = 0; i < size; i += 0x10)
	{
		fprintf(stderr, "%8x:", i);
		print_diff_row(s_buffer, s_mirror, i);
		fprintf(stderr, "  |");
		print_diff_row(s_mirror, s_buffer, i);
		fprintf(stderr, "\n");
	}
}

// Some variables to use as input operands.
static int s_zero;
static int s_one;
static int s_two;
static __m128 s_one_two_three_four;

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
	s_zero = 0;
	s_one = 1;
	s_two = 2;
	s_one_two_three_four = _mm_set_ps(4.f, 3.f, 2.f, 1.f);
	
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
		s_strict = true; \
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
		s_strict = false; \
		run_test(run_test_body_##name); \
	} \
	static void run_test_body_##name()

// Instruction set extension tests. These behave similarly to the macros above
// except that they will only be run if the compiler is configured to support
// the given extension.

#ifdef __MMX__
#define X86_WTS_MMX(name) X86_WTS(name)
#define X86_WTR_MMX(name) X86_WTR(name)
#else
#define X86_WTS_MMX(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_MMX(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __SSE__
#define X86_WTS_SSE(name) X86_WTS(name)
#define X86_WTR_SSE(name) X86_WTR(name)
#else
#define X86_WTS_SSE(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_SSE(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __SSE2__
#define X86_WTS_SSE2(name) X86_WTS(name)
#define X86_WTR_SSE2(name) X86_WTR(name)
#else
#define X86_WTS_SSE2(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_SSE2(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __SSE3__
#define X86_WTS_SSE3(name) X86_WTS(name)
#define X86_WTR_SSE3(name) X86_WTR(name)
#else
#define X86_WTS_SSE3(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_SSE3(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __SSSE3__
#define X86_WTS_SSSE3(name) X86_WTS(name)
#define X86_WTR_SSSE3(name) X86_WTR(name)
#else
#define X86_WTS_SSSE3(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_SSSE3(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __SSE4_1__
#define X86_WTS_SSE41(name) X86_WTS(name)
#define X86_WTR_SSE41(name) X86_WTR(name)
#else
#define X86_WTS_SSE41(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_SSE41(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __SSE4_2__
#define X86_WTS_SSE42(name) X86_WTS(name)
#define X86_WTR_SSE42(name) X86_WTR(name)
#else
#define X86_WTS_SSE42(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_SSE42(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX__
#define X86_WTS_AVX(name) X86_WTS(name)
#define X86_WTR_AVX(name) X86_WTR(name)
#else
#define X86_WTS_AVX(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX2__
#define X86_WTS_AVX2(name) X86_WTS(name)
#define X86_WTR_AVX2(name) X86_WTR(name)
#else
#define X86_WTS_AVX2(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX2(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX512CD__
#define X86_WTS_AVX512CD(name) X86_WTS(name)
#define X86_WTR_AVX512CD(name) X86_WTR(name)
#else
#define X86_WTS_AVX512CD(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX512CD(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX512ER__
#define X86_WTS_AVX512ER(name) X86_WTS(name)
#define X86_WTR_AVX512ER(name) X86_WTR(name)
#else
#define X86_WTS_AVX512ER(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX512ER(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX512F__
#define X86_WTS_AVX512F(name) X86_WTS(name)
#define X86_WTR_AVX512F(name) X86_WTR(name)
#else
#define X86_WTS_AVX512F(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX512F(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX512PF__
#define X86_WTS_AVX512PF(name) X86_WTS(name)
#define X86_WTR_AVX512PF(name) X86_WTR(name)
#else
#define X86_WTS_AVX512PF(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX512PF(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#ifdef __AVX512VL__
#define X86_WTS_AVX512VL(name) X86_WTS(name)
#define X86_WTR_AVX512VL(name) X86_WTR(name)
#else
#define X86_WTS_AVX512VL(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#define X86_WTR_AVX512VL(name) template <typename T> [[maybe_unused]] static void stub_test_body_##name()
#endif

#define A asm volatile

// *****************************************************************************
// Instructions (A-L)
// *****************************************************************************

X86_WTS(ADC_Imm8ToMem8) { A("adcb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Imm8ToMem16) { A("adcw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADC_Imm8ToMem32) { A("adcl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADC_Imm8ToMem64) { A("adcq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Imm16ToMem16) { A("adcw $12345, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Imm32ToMem32) { A("adcl $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADC_Imm32ToMem64) { A("adcq $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADC_Reg8ToMem8) { A("movb $123, %%al\n adcb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WTS(ADC_Reg16ToMem16) { A("movw $12345, %%ax\n adcw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WTS(ADC_Reg32ToMem32) { A("movl $1234567890, %%eax\n adcl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WTS(ADC_Reg64ToMem64) { A("movq $12345678901234567890, %%rax\n adcq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

X86_WTS(ADD_Imm8ToMem8) { A("addb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Imm8ToMem16) { A("addw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADD_Imm8ToMem32) { A("addl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADD_Imm8ToMem64) { A("addq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Imm16ToMem16) { A("addw $12345, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Imm32ToMem32) { A("addl $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTR(ADD_Imm32ToMem64) { A("addq $1234567890, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(ADD_Reg8ToMem8) { A("movb $123, %%al\n addb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WTS(ADD_Reg16ToMem16) { A("movw $12345, %%ax\n addw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WTS(ADD_Reg32ToMem32) { A("movl $1234567890, %%eax\n addl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WTS(ADD_Reg64ToMem64) { A("movq $12345678901234567890, %%rax\n addq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

X86_WTS(AND_Imm8ToMem8) { A("andb $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm8ToMem16) { A("andw $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm8ToMem32) { A("andl $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm8ToMem64) { A("andq $123, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm16ToMem16) { A("andw $1234, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm32ToMem32) { A("andl $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Imm32ToMem64) { A("andq $123456, (%0)" :: "r" (s_buffer) : "memory"); }
X86_WTS(AND_Reg8ToMem8) { A("movb $123, %%al\n andb %%al, (%0)" :: "r" (s_buffer) : "al", "memory"); }
X86_WTS(AND_Reg16ToMem16) { A("movw $123, %%ax\n andw %%ax, (%0)" :: "r" (s_buffer) : "ax", "memory"); }
X86_WTS(AND_Reg32ToMem32) { A("movl $123, %%eax\n andl %%eax, (%0)" :: "r" (s_buffer) : "eax", "memory"); }
X86_WTS(AND_Reg64ToMem64) { A("movq $123, %%rax\n andq %%rax, (%0)" :: "r" (s_buffer) : "rax", "memory"); }

#define X86_WTS_BTC_SMALL(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg16ToMem16) \
		{ A("movw $" #bit_offset ", %%ax\n btcw %%ax, (%0)" :: "r" (s_buffer + 32) : "ax", "memory"); } \
	X86_WTS(BTC_##name##_Reg32ToMem32) \
		{ A("movl $" #bit_offset ", %%eax\n btcl %%eax, (%0)" :: "r" (s_buffer + 32) : "eax", "memory"); } \
	X86_WTS(BTC_##name##_Reg64ToMem64) \
		{ A("movq $" #bit_offset ", %%rax\n btcq %%rax, (%0)" :: "r" (s_buffer + 32) : "rax", "memory"); } \
	X86_WTS(BTC_##name##_Imm8ToMem16) \
		{ A("btcw $" #bit_offset ", (%0)" :: "r" (s_buffer + 32) : "memory"); } \
	X86_WTS(BTC_##name##_Imm8ToMem32) \
		{ A("btcl $" #bit_offset ", (%0)" :: "r" (s_buffer + 32) : "memory"); } \
	X86_WTS(BTC_##name##_Imm8ToMem64) \
		{ A("btcq $" #bit_offset ", (%0)" :: "r" (s_buffer + 32) : "memory"); }
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
		{ A("movq $" #bit_offset ", %%rax\n btcq %%rax, (%0)" \
			:: "r" ((s_buffer + 32) - (bit_offset / 8)) : "rax", "memory"); }
#define X86_WTS_BTC_LARGE32(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg32ToMem32) \
		{ A("movl $" #bit_offset ", %%eax\n btcl %%eax, (%0)" \
			:: "r" ((s_buffer + 32) - (bit_offset / 8)) : "eax", "memory"); } \
		X86_WTS_BTC_LARGE64(name, bit_offset)
#define X86_WTS_BTC_LARGE16(name, bit_offset) \
	X86_WTS(BTC_##name##_Reg16ToMem16) \
		{ A("movw $" #bit_offset ", %%ax\n btcw %%ax, (%0)" \
			:: "r" ((s_buffer + 32) - (bit_offset / 8)) : "ax", "memory"); } \
		X86_WTS_BTC_LARGE32(name, bit_offset)
X86_WTS_BTC_LARGE16(MaxSigned16, 32767);
X86_WTS_BTC_LARGE32(MaxSigned32, 2147483647);
// TODO: Test some more out of range values here. Minimums don't work right.

// NOTE: Assume BTR and BTS behave similarly.

X86_WTS(CMPXCHG_Exchange8)
	{ A("movb $0xbb, %%al\n movb $123, %%bl\n cmpxchgb %%bl, %0"
		: "+m" (s_buffer) :: "al", "bl", "memory"); }
X86_WTS(CMPXCHG_Exchange16)
	{ A("movw $0xbbbb, %%ax\n movw $123, %%bx\n cmpxchgw %%bx, %0"
		: "+m" (s_buffer) :: "ax", "bx", "memory"); }
X86_WTS(CMPXCHG_Exchange32)
	{ A("movl $0xbbbbbbbb, %%eax\n movl $123, %%ebx\n cmpxchgl %%ebx, %0"
		: "+m" (s_buffer) :: "eax", "ebx", "memory"); }
X86_WTS(CMPXCHG_Exchange64)
	{ A("movq $0xbbbbbbbbbbbbbbbb, %%rax\n movq $123, %%rbx\n cmpxchgq %%rbx, %0"
		: "+m" (s_buffer) :: "rax", "rbx", "memory"); }
X86_WTS(CMPXCHG_DontExchange8)
	{ A("movb $123, %%al\n movb $123, %%bl\n cmpxchgb %%bl, %0"
		: "+m" (s_buffer) :: "al", "bl", "memory"); }
X86_WTS(CMPXCHG_DontExchange16)
	{ A("movw $123, %%ax\n movw $123, %%bx\n cmpxchgw %%bx, %0"
		: "+m" (s_buffer) :: "ax", "bx", "memory"); }
X86_WTS(CMPXCHG_DontExchange32)
	{ A("movl $123, %%eax\n movl $123, %%ebx\n cmpxchgl %%ebx, %0"
		: "+m" (s_buffer) :: "eax", "ebx", "memory"); }
X86_WTS(CMPXCHG_DontExchange64)
	{ A("movq $123, %%rax\n movq $123, %%rbx\n cmpxchgq %%rbx, %0"
		: "+m" (s_buffer) :: "rax", "rbx", "memory"); }

X86_WTS(CMPXCHG8B_Exchange)
	{ A("movl $0xbbbbbbbb, %%edx\n movl $0xbbbbbbbb, %%eax\n\n"
		"movl $123, %%ecx\n movl $123, %%ebx\n"
		"cmpxchg8b %0" : "+m" (s_buffer) :: "eax", "ebx", "ecx", "edx", "memory"); }
X86_WTS(CMPXCHG8B_DontExchange)
	{ A("movl $123, %%edx\n movl $123, %%eax\n\n"
		"movl $123, %%ecx\n movl $123, %%ebx\n"
		"cmpxchg8b %0" : "+m" (s_buffer) :: "eax", "ebx", "ecx", "edx", "memory"); }

X86_WTS(CMPXCHG16B_Exchange)
	{ A("movq $0xbbbbbbbbbbbbbbbb, %%rdx\n movq $0xbbbbbbbbbbbbbbbb, %%rax\n"
		"movq $123, %%rcx\n movq $123, %%rbx\n"
		"cmpxchg16b %0" : "+m" (s_buffer) :: "rax", "rbx", "rcx", "rdx", "memory"); }
X86_WTS(CMPXCHG16B_DontExchange)
	{ A("movq $123, %%rdx\n movq $123, %%rax\n"
		"movq $123, %%rcx\n movq $123, %%rbx\n"
		"cmpxchg16b %0" : "+m" (s_buffer) :: "rax", "rbx", "rcx", "rdx", "memory"); }

X86_WTS(DEC_Mem8) { A("decb %0" : "+m" (s_buffer)); }
X86_WTR(DEC_Mem16) { A("decw %0" : "+m" (s_buffer)); }
X86_WTR(DEC_Mem32) { A("decl %0" : "+m" (s_buffer)); }
X86_WTR(DEC_Mem64) { A("decq %0" : "+m" (s_buffer)); }

X86_WTS_SSE41(EXTRACTPS) { A("extractps $1, %1, %0" : "+m" (s_buffer) : "x" (s_one_two_three_four)); }
X86_WTS_AVX(VEXTRACTPS) { A("vextractps $1, %1, %0" : "+m" (s_buffer) : "x" (s_one_two_three_four)); }

X86_WTS(FBSTP) { A("fldpi\n fbstp %0" : "+m" (s_buffer)); }

X86_WTS(FIST_Short) { A("fldpi\n fists %0" : "+m" (s_buffer)); }
X86_WTS(FIST_Long) { A("fldpi\n fistl %0" : "+m" (s_buffer)); }

X86_WTS(FIST_RegToMem16) { A("fldpi\n fists %0" : "+m" (s_buffer)); }
X86_WTS(FIST_RegToMem32) { A("fldpi\n fistl %0" : "+m" (s_buffer)); }
X86_WTS(FISTP_RegToMem16) { A("fldpi\n fistps %0" : "+m" (s_buffer)); }
X86_WTS(FISTP_RegToMem32) { A("fldpi\n fistpl %0" : "+m" (s_buffer)); }
X86_WTS(FISTP_RegToMem64) { A("fldpi\n fistpq %0" : "+m" (s_buffer)); }

X86_WTS_SSE3(FISTTP_RegToMem16) { A("fldpi\n fisttps %0" : "+m" (s_buffer)); }
X86_WTS_SSE3(FISTTP_RegToMem32) { A("fldpi\n fisttpl %0" : "+m" (s_buffer)); }
X86_WTS_SSE3(FISTTP_RegToMem64) { A("fldpi\n fisttpq %0" : "+m" (s_buffer)); }

X86_WTR(FSAVE) { A("fsave %0" : "=m" (s_buffer)); }
X86_WTR(FNSAVE) { A("fnsave %0" : "=m" (s_buffer)); }

X86_WTS(FST_RegToMem32) { A("fldpi\n fsts %0" : "=m" (s_buffer)); }
X86_WTS(FST_RegToMem64) { A("fldpi\n fstl %0" : "=m" (s_buffer)); }
X86_WTS(FSTP_RegToMem32) { A("fldpi\n fstps %0" : "=m" (s_buffer)); }
X86_WTS(FSTP_RegToMem64) { A("fldpi\n fstpl %0" : "=m" (s_buffer)); }
X86_WTS(FSTP_RegToMem80) { A("fldpi\n fstpt %0" : "=m" (s_buffer)); }

X86_WTR(FSTCW) { A("fstcw %0" : "=m" (s_buffer)); }
X86_WTR(FNSTCW) { A("fnstcw %0" : "=m" (s_buffer)); }

X86_WTR(FSTENV) { A("fstenv %0" : "=m" (s_buffer)); }
X86_WTR(FNSTENV) { A("fnstenv %0" : "=m" (s_buffer)); }

X86_WTR(FSTSW) { A("fstsw %0" : "=m" (s_buffer)); }
X86_WTR(FNSTSW) { A("fnstsw %0" : "=m" (s_buffer)); }

X86_WTR(FXSAVE) { A("fxsave %0" : "=m" (s_buffer)); }
X86_WTR(FXSAVE64) { A("fxsave64 %0" : "=m" (s_buffer)); }

#endif
