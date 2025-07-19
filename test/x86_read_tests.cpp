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

#include <inttypes.h>

// Here we test the memcorder_enumerate_memory_accesses function by comparing
// what reads it thinks are going to happen with an expected read that's
// manually defined for each test, and then we do an additional check to make
// sure that the expected read is correct.

#if defined(__linux__) && defined(__x86_64__)

#define BUFFER_SIZE 64

static unsigned char s_buffer[BUFFER_SIZE];

static MemcorderMemoryAccess s_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION];
static size_t s_access_count = 0;

static uint32_t s_expected_offset;
static uint32_t s_expected_size;
static uint64_t s_expected_value;
static uint8_t s_expected_value_8;
static uint16_t s_expected_value_16;
static uint32_t s_expected_value_32;
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

#ifdef VERBOSE_X86_READ_TESTS
		fprintf(stderr, "\tread %p %d\t\t\t\t0x%llx",
			access->address,
			access->size,
			offset);
#endif
		
		if (access->type == MEMCORDER_MEMORY_ACCESS_TYPE_READ
			&& access->address == s_buffer + s_expected_offset
			&& access->size == s_expected_size
			&& memcmp(access->address, &s_expected_value, s_expected_size) == 0)
		{
			s_found_expected_read = true;
			
#ifdef VERBOSE_X86_READ_TESTS
			fprintf(stderr, " <---\n");
			continue;
#else
			break;
#endif
		}
		
#ifdef VERBOSE_X86_READ_TESTS
		fprintf(stderr, "\n");
#endif
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
		s_buffer[i] = i + 1;
	
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
	
	// Copy the expected value into some smaller variables, useful for declaring
	// the input operands for inline assembly blocks.
	s_expected_value_8 = static_cast<uint8_t>(s_expected_value);
	s_expected_value_16 = static_cast<uint16_t>(s_expected_value);
	s_expected_value_32 = static_cast<uint32_t>(s_expected_value);
	
	// Enable trapping after each instruction. Our signal handler will start
	// getting called after this.
	set_eflags_trap_bit(true);
	
	// Execute the instructions to use for testing.
	run_test_body();
	
	// Disable trapping after each instruction. Our signal handler will stop
	// getting called after this.
	set_eflags_trap_bit(false);
	
	if (run_result_reader)
		run_result_reader();
	uint64_t test_output = s_output;
	switch (s_expected_size)
	{
		case 1: test_output &= 0xff; break;
		case 2: test_output &= 0xffff; break;
		case 4: test_output &= 0xffffffff; break;
	}
	fprintf(stderr, "Test output: 0x%" PRIx64 "\n", test_output);
	
	// Make sure that we successfully predicted that the test instructions was
	// going to perform the expected read.
	ASSERT_TRUE(s_found_expected_read);
	
	if (!run_verifier)
		return;
	
	// Run the same instruction again, but this time pass the expected input via
	// registers so that we can compare the output below.
	memset(&s_input, 0, sizeof(s_input));
	memcpy(&s_input, &s_expected_value, s_expected_size);
	s_output = s_input;
	run_verifier();
	uint64_t verifier_output = s_output;
	switch (s_expected_size)
	{
		case 1: verifier_output &= 0xff; break;
		case 2: verifier_output &= 0xffff; break;
		case 4: verifier_output &= 0xffffffff; break;
	}
	fprintf(stderr, "Expected output: 0x%" PRIx64 "\n", verifier_output);
	
	// Make sure the result of said instruction is the same as the result of
	// running the same instruction with the expected value as input (to make
	// sure it actually read from the memory location we thought it did).
	ASSERT_EQ(test_output, verifier_output);
}

#define X86_READ_TEST(name, offset, size, value, run_test_body, run_result_reader, run_verifier) \
	TEST(X86Read, name) \
	{ \
		s_expected_offset = offset; \
		s_expected_size = size; \
		s_expected_value = value; \
		run_test(run_test_body, run_result_reader, run_verifier); \
	}

#define ASM asm volatile

// *****************************************************************************
// Instructions (A-L)
// *****************************************************************************

X86_READ_TEST(ADC_Imm8ToMem8, 0, 1, 0x01,
	([]() { ASM("clc\n adcb $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint8_t*) s_buffer; }),
	([]() { ASM("movb $0x01, %%al\n clc\n adcb $0x12, %%al" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Imm16ToMem16, 0, 2, 0x0201,
	([]() { ASM("clc\n adcw $0x1234, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint16_t*) s_buffer; }),
	([]() { ASM("movw $0x0201, %%ax\n clc\n adcw $0x1234, %%ax" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Imm32ToMem32, 0, 4, 0x04030201,
	([]() { ASM("clc\n adcl $0x12345678, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint32_t*) s_buffer; }),
	([]() { ASM("movl $0x04030201, %%eax\n clc\n adcl $0x12345678, %%eax" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Imm32ToMem64, 0, 8, 0x0807060504030201,
	([]() { ASM("clc\n adcq $0x12345678, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint64_t*) s_buffer; }),
	([]() { ASM("movq $0x0807060504030201, %%rax\n clc\n adcq $0x12345678, %%rax" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Imm8ToMem16, 0, 2, 0x0201,
	([]() { ASM("clc\n adcw $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint16_t*) s_buffer; }),
	([]() { ASM("movw $0x0201, %%ax\n clc\n adcw $0x12, %%ax" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Imm8ToMem32, 0, 4, 0x04030201,
	([]() { ASM("clc\n adcl $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint32_t*) s_buffer; }),
	([]() { ASM("movl $0x04030201, %%eax\n clc\n adcl $0x12, %%eax" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Imm8ToMem64, 0, 8, 0x0807060504030201,
	([]() { ASM("clc\n adcq $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint64_t*) s_buffer; }),
	([]() { ASM("movq $0x0807060504030201, %%rax\n clc\n adcq $0x12, %%rax" : "+a" (s_output)); }));
X86_READ_TEST(ADC_Reg8ToMem8, 0, 1, 0x01,
	([]() { ASM("movb $0x12, %%bl\n clc\n adcb %%bl, %0" : "+m" (s_buffer) :: "bl"); }),
	([]() { s_output = *(uint8_t*) s_buffer; }),
	([]() { ASM("movb $0x12, %%bl\n movb $0x01, %%al\n clc\n adcb %%bl, %%al" : "+a" (s_output) :: "bl"); }));
X86_READ_TEST(ADC_Reg16ToMem16, 0, 2, 0x0201,
	([]() { ASM("movw $0x1234, %%bx\n clc\n adcw %%bx, %0" : "+m" (s_buffer) :: "bx"); }),
	([]() { s_output = *(uint16_t*) s_buffer; }),
	([]() { ASM("movw $0x1234, %%bx\n movw $0x0201, %%ax\n clc\n adcw %%bx, %%ax" : "+a" (s_output) :: "bx"); }));
X86_READ_TEST(ADC_Reg32ToMem32, 0, 4, 0x04030201,
	([]() { ASM("movl $0x12345678, %%ebx\n clc\n adcl %%ebx, %0" : "+m" (s_buffer) :: "ebx"); }),
	([]() { s_output = *(uint32_t*) s_buffer; }),
	([]() { ASM("movl $0x12345678, %%ebx\n movl $0x04030201, %%eax\n clc\n adcl %%ebx, %%eax" : "+a" (s_output) :: "ebx"); }));
X86_READ_TEST(ADC_Reg64ToMem64, 0, 8, 0x0807060504030201,
	([]() { ASM("movq $0x1234567890123456, %%rbx\n clc\n adcq %%rbx, %0" : "+m" (s_buffer) :: "rbx"); }),
	([]() { s_output = *(uint64_t*) s_buffer; }),
	([]() { ASM("movq $0x1234567890123456, %%rbx\n movq $0x0807060504030201, %%rax\n clc\n adcq %%rbx, %%rax" : "+a" (s_output) :: "rbx"); }));
X86_READ_TEST(ADC_Mem8ToReg8, 0, 1, 0x01,
	([]() { ASM("movb $0x12, %%al\n clc\n adcb %1, %%al" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movb $0x12, %%al\n clc\n adcb %1, %%al" : "+a" (s_output) : "r" (s_expected_value_8)); }));
X86_READ_TEST(ADC_Mem16ToReg16, 0, 2, 0x0201,
	([]() { ASM("movw $0x1234, %%ax\n clc\n adcw %1, %%ax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movw $0x1234, %%ax\n clc\n adcw %1, %%ax" : "+a" (s_output) : "r" (s_expected_value_16)); }));
X86_READ_TEST(ADC_Mem32ToReg32, 0, 4, 0x04030201,
	([]() { ASM("movl $0x12345678, %%eax\n clc\n adcl %1, %%eax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movl $0x12345678, %%eax\n clc\n adcl %1, %%eax" : "+a" (s_output) : "r" (s_expected_value_32)); }));
X86_READ_TEST(ADC_Mem64ToReg64, 0, 8, 0x0807060504030201,
	([]() { ASM("movq $0x1234567890123456, %%rax\n clc\n adcq %1, %%rax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movq $0x1234567890123456, %%rax\n clc\n adcq %1, %%rax" : "+a" (s_output) : "r" (s_expected_value)); }));

#ifdef __broadwell__
X86_READ_TEST(ADCX_Mem32ToReg32, 0, 4, 0x04030201,
	([]() { ASM("movl $0x12345678, %%eax\n clc\n adcxl %1, %%eax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movl $0x12345678, %%eax\n clc\n adcxl %1, %%eax" : "+a" (s_output) : "r" (s_expected_value_32)); }));
X86_READ_TEST(ADCX_Mem64ToReg64, 0, 8, 0x0807060504030201,
	([]() { ASM("movq $0x1234567890123456, %%rax\n clc\n adcxq %1, %%rax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movq $0x1234567890123456, %%rax\n clc\n adcxq %1, %%rax" : "+a" (s_output) : "r" (s_expected_value)); }));
#endif

X86_READ_TEST(ADD_Imm8ToMem8, 0, 1, 0x01,
	([]() { ASM("addb $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint8_t*) s_buffer; }),
	([]() { ASM("movb $0x01, %%al\n addb $0x12, %%al" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Imm16ToMem16, 0, 2, 0x0201,
	([]() { ASM("addw $0x1234, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint16_t*) s_buffer; }),
	([]() { ASM("movw $0x0201, %%ax\n addw $0x1234, %%ax" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Imm32ToMem32, 0, 4, 0x04030201,
	([]() { ASM("addl $0x12345678, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint32_t*) s_buffer; }),
	([]() { ASM("movl $0x04030201, %%eax\n addl $0x12345678, %%eax" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Imm32ToMem64, 0, 8, 0x0807060504030201,
	([]() { ASM("addq $0x12345678, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint64_t*) s_buffer; }),
	([]() { ASM("movq $0x0807060504030201, %%rax\n addq $0x12345678, %%rax" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Imm8ToMem16, 0, 2, 0x0201,
	([]() { ASM("addw $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint16_t*) s_buffer; }),
	([]() { ASM("movw $0x0201, %%ax\n addw $0x12, %%ax" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Imm8ToMem32, 0, 4, 0x04030201,
	([]() { ASM("addl $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint32_t*) s_buffer; }),
	([]() { ASM("movl $0x04030201, %%eax\n addl $0x12, %%eax" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Imm8ToMem64, 0, 8, 0x0807060504030201,
	([]() { ASM("addq $0x12, %0" : "+m" (s_buffer)); }),
	([]() { s_output = *(uint64_t*) s_buffer; }),
	([]() { ASM("movq $0x0807060504030201, %%rax\n addq $0x12, %%rax" : "+a" (s_output)); }));
X86_READ_TEST(ADD_Reg8ToMem8, 0, 1, 0x01,
	([]() { ASM("movb $0x12, %%bl\n addb %%bl, %0" : "+m" (s_buffer) :: "bl"); }),
	([]() { s_output = *(uint8_t*) s_buffer; }),
	([]() { ASM("movb $0x12, %%bl\n movb $0x01, %%al\n addb %%bl, %%al" : "+a" (s_output) :: "bl"); }));
X86_READ_TEST(ADD_Reg16ToMem16, 0, 2, 0x0201,
	([]() { ASM("movw $0x1234, %%bx\n addw %%bx, %0" : "+m" (s_buffer) :: "bx"); }),
	([]() { s_output = *(uint16_t*) s_buffer; }),
	([]() { ASM("movw $0x1234, %%bx\n movw $0x0201, %%ax\n addw %%bx, %%ax" : "+a" (s_output) :: "bx"); }));
X86_READ_TEST(ADD_Reg32ToMem32, 0, 4, 0x04030201,
	([]() { ASM("movl $0x12345678, %%ebx\n addl %%ebx, %0" : "+m" (s_buffer) :: "ebx"); }),
	([]() { s_output = *(uint32_t*) s_buffer; }),
	([]() { ASM("movl $0x12345678, %%ebx\n movl $0x04030201, %%eax\n addl %%ebx, %%eax" : "+a" (s_output) :: "ebx"); }));
X86_READ_TEST(ADD_Reg64ToMem64, 0, 8, 0x0807060504030201,
	([]() { ASM("movq $0x1234567890123456, %%rbx\n addq %%rbx, %0" : "+m" (s_buffer) :: "rbx"); }),
	([]() { s_output = *(uint64_t*) s_buffer; }),
	([]() { ASM("movq $0x1234567890123456, %%rbx\n movq $0x0807060504030201, %%rax\n addq %%rbx, %%rax" : "+a" (s_output) :: "rbx"); }));
X86_READ_TEST(ADD_Mem8ToReg8, 0, 1, 0x01,
	([]() { ASM("movb $0x12, %%al\n addb %1, %%al" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movb $0x12, %%al\n addb %1, %%al" : "+a" (s_output) : "r" (s_expected_value_8)); }));
X86_READ_TEST(ADD_Mem16ToReg16, 0, 2, 0x0201,
	([]() { ASM("movw $0x1234, %%ax\n addw %1, %%ax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movw $0x1234, %%ax\n addw %1, %%ax" : "+a" (s_output) : "r" (s_expected_value_16)); }));
X86_READ_TEST(ADD_Mem32ToReg32, 0, 4, 0x04030201,
	([]() { ASM("movl $0x12345678, %%eax\n addl %1, %%eax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movl $0x12345678, %%eax\n addl %1, %%eax" : "+a" (s_output) : "r" (s_expected_value_32)); }));
X86_READ_TEST(ADD_Mem64ToReg64, 0, 8, 0x0807060504030201,
	([]() { ASM("movq $0x1234567890123456, %%rax\n addq %1, %%rax" : "+a" (s_output) : "m" (s_buffer)); }),
	nullptr,
	([]() { ASM("movq $0x1234567890123456, %%rax\n addq %1, %%rax" : "+a" (s_output) : "r" (s_expected_value)); }));

#endif
