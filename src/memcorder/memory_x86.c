// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memory.h"

#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>

#include <sys/user.h>
#define __USE_GNU
#include <sys/ucontext.h>
#include <immintrin.h>

#include <stdio.h>

static void linux_context_to_zydis_context(ucontext_t* source, ZydisRegisterContext* destination);

MemcorderStatus memcorder_enumerate_memory_accesses(
	void* instruction,
	void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count)
{
	*output_access_count = 0;
	
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	
	ZydisDecodedInstruction decoded_instruction;
	ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];
	ZydisDecoderDecodeFull(&decoder,
		instruction, 15, &decoded_instruction, decoded_operands);
	
	for (ZyanU8 i = 0; i < decoded_instruction.operand_count; i++)
	{
		ZydisDecodedOperand* operand = &decoded_operands[i];
		if (operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
			continue;
		
		if (types & MEMCORDER_MEMORY_ACCESS_TYPE_READ
			&& (operand->actions & ZYDIS_OPERAND_ACTION_READ
				|| operand->actions & ZYDIS_OPERAND_ACTION_CONDREAD))
		{
			MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
			access->address = 0;
			ZydisRegisterContext context = {};
			linux_context_to_zydis_context((ucontext_t*) platform_context, &context);
			ZydisCalcAbsoluteAddressEx(
				&decoded_instruction, operand, (ZyanU64) instruction, &context, (ZyanU64*) &access->address);
			access->size = operand->size / 8;
			access->type = MEMCORDER_MEMORY_ACCESS_TYPE_READ;
		}
		
		if (types & MEMCORDER_MEMORY_ACCESS_TYPE_WRITE
			&& (operand->actions & ZYDIS_OPERAND_ACTION_WRITE
				|| operand->actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
		{
			MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
			access->address = 0;
			ZydisRegisterContext context = {};
			linux_context_to_zydis_context((ucontext_t*) platform_context, &context);
			ZydisCalcAbsoluteAddressEx(
				&decoded_instruction, operand, (ZyanU64) instruction, &context, (ZyanU64*) &access->address);
			access->size = operand->size / 8;
			access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
		}
	}
	
	return MEMCORDER_SUCCESS;
}

static void linux_context_to_zydis_context(ucontext_t* source, ZydisRegisterContext* destination)
{
	destination->values[ZYDIS_REGISTER_RAX] = source->uc_mcontext.gregs[REG_RAX];
	destination->values[ZYDIS_REGISTER_RCX] = source->uc_mcontext.gregs[REG_RCX];
	destination->values[ZYDIS_REGISTER_RDX] = source->uc_mcontext.gregs[REG_RDX];
	destination->values[ZYDIS_REGISTER_RBX] = source->uc_mcontext.gregs[REG_RBX];
	destination->values[ZYDIS_REGISTER_RSP] = source->uc_mcontext.gregs[REG_RSP];
	destination->values[ZYDIS_REGISTER_RBP] = source->uc_mcontext.gregs[REG_RBP];
	destination->values[ZYDIS_REGISTER_RSI] = source->uc_mcontext.gregs[REG_RSI];
	destination->values[ZYDIS_REGISTER_RDI] = source->uc_mcontext.gregs[REG_RDI];
	destination->values[ZYDIS_REGISTER_R8] = source->uc_mcontext.gregs[REG_R8];
	destination->values[ZYDIS_REGISTER_R9] = source->uc_mcontext.gregs[REG_R9];
	destination->values[ZYDIS_REGISTER_R10] = source->uc_mcontext.gregs[REG_R10];
	destination->values[ZYDIS_REGISTER_R11] = source->uc_mcontext.gregs[REG_R11];
	destination->values[ZYDIS_REGISTER_R12] = source->uc_mcontext.gregs[REG_R12];
	destination->values[ZYDIS_REGISTER_R13] = source->uc_mcontext.gregs[REG_R13];
	destination->values[ZYDIS_REGISTER_R14] = source->uc_mcontext.gregs[REG_R14];
	destination->values[ZYDIS_REGISTER_R15] = source->uc_mcontext.gregs[REG_R15];
	destination->values[ZYDIS_REGISTER_RIP] = source->uc_mcontext.gregs[REG_RIP];
}
