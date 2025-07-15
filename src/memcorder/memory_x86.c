// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memory.h"

#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>

#include <sys/user.h>
#define __USE_GNU
#include <sys/ucontext.h>
#include <immintrin.h>

static MemcorderStatus handle_special_cases(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
	ZyanU64 runtime_address,
	const void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count);

static MemcorderStatus calculate_operand_value(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	ZyanU64 runtime_address,
	const void* platform_context,
	ZyanU64* result);

static int64_t to_signed(uint64_t value, int size);

static ZyanBool get_integer_register(ZydisRegister reg, ucontext_t* context, ZyanU64* result);

static void linux_context_to_zydis_context(
	const ucontext_t* source,
	ZydisRegisterContext* destination);

MemcorderStatus memcorder_enumerate_memory_accesses(
	void* instruction,
	const void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count)
{
	*output_access_count = 0;
	
	ZydisDecoder decoder;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
		return MEMCORDER_DECODER_FAILURE;
	
	ZydisDecodedInstruction decoded_instruction;
	ZydisDecodedOperand decoded_operands[ZYDIS_MAX_OPERAND_COUNT];
	if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
		instruction, 15, &decoded_instruction, decoded_operands)))
		return MEMCORDER_DECODER_FAILURE;
	
	MemcorderStatus special_cases_status = handle_special_cases(
		&decoded_instruction,
		decoded_operands,
		(ZyanU64) instruction,
		platform_context,
		types,
		output_accesses,
		output_access_count);
	if (special_cases_status != -1)
		return special_cases_status;
	
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
			if (calculate_operand_value(
				&decoded_instruction, operand, (ZyanU64) instruction, platform_context, (ZyanU64*) &access->address)
				!= MEMCORDER_SUCCESS)
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			access->size = operand->size / 8;
			access->type = MEMCORDER_MEMORY_ACCESS_TYPE_READ;
		}
		
		if (types & MEMCORDER_MEMORY_ACCESS_TYPE_WRITE
			&& (operand->actions & ZYDIS_OPERAND_ACTION_WRITE
				|| operand->actions & ZYDIS_OPERAND_ACTION_CONDWRITE))
		{
			MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
			access->address = 0;
			if (calculate_operand_value(
				&decoded_instruction, operand, (ZyanU64) instruction, platform_context, (ZyanU64*) &access->address)
				!= MEMCORDER_SUCCESS)
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			access->size = operand->size / 8;
			access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
		}
	}
	
	return MEMCORDER_SUCCESS;
}

static MemcorderStatus handle_special_cases(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
	ZyanU64 runtime_address,
	const void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count)
{
	switch (instruction->mnemonic)
	{
		case ZYDIS_MNEMONIC_BTC:
		case ZYDIS_MNEMONIC_BTR:
		case ZYDIS_MNEMONIC_BTS:
		{
			assert(instruction->operand_count >= 2);
			const ZydisDecodedOperand* bit_base_operand = &operands[0];
			const ZydisDecodedOperand* bit_offset_operand = &operands[1];
			
			// We only care about the variants that access memory.
			if (bit_base_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
				break;
			
			ZyanU64 bit_base;
			if (calculate_operand_value(
				instruction, bit_base_operand, runtime_address, platform_context, &bit_base)
				!= MEMCORDER_SUCCESS)
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			ZyanU64 bit_offset_unsigned;
			if (calculate_operand_value(
				instruction, bit_offset_operand, runtime_address, platform_context, &bit_offset_unsigned)
				!= MEMCORDER_SUCCESS)
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			int64_t bit_offset = to_signed(bit_offset_unsigned, bit_offset_operand->size);
			
			switch (bit_offset_operand->type)
			{
				case ZYDIS_OPERAND_TYPE_REGISTER:
				{
					// TODO: Fix this.
					switch (bit_base_operand->size)
					{
						case 16: bit_offset = bit_offset % 32768; break;
						case 32: bit_offset = bit_offset % 2147483648; break;
						case 64: break;
						default:
							return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
					}
					
					break;
				}
				case ZYDIS_OPERAND_TYPE_IMMEDIATE:
				{
					switch (bit_base_operand->size)
					{
						case 16: bit_offset = ((bit_offset % 16) + 16) % 16; break;
						case 32: bit_offset = ((bit_offset % 32) + 32) % 32; break;
						case 64: bit_offset = ((bit_offset % 64) + 64) % 64; break;
						default:
							return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
					}
					
					break;
				}
				default:
					return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			}
			
			if (types & MEMCORDER_MEMORY_ACCESS_TYPE_READ)
			{
				MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
				if (bit_offset < 0 && (bit_offset % 8) != 0)
					access->address = (void*) (bit_base + bit_offset / 8 - 1);
				else
					access->address = (void*) (bit_base + bit_offset / 8);
				access->size = 1;
				access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
			}
			
			if (types & MEMCORDER_MEMORY_ACCESS_TYPE_WRITE)
			{
				MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
				if (bit_offset < 0 && (bit_offset % 8) != 0)
					access->address = (void*) (bit_base + bit_offset / 8 - 1);
				else
					access->address = (void*) (bit_base + bit_offset / 8);
				access->size = 1;
				access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
			}
			
			return MEMCORDER_SUCCESS;
		}
		default:
		{
		}
	}
	
	return -1;
}

static MemcorderStatus calculate_operand_value(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	ZyanU64 runtime_address,
	const void* platform_context,
	ZyanU64* result)
{
	switch (operand->type)
	{
		case ZYDIS_OPERAND_TYPE_REGISTER:
		{
			if (!get_integer_register(operand->reg.value, (ucontext_t*) platform_context, result))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			break;
		}
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		{
			*result = operand->imm.value.u;
			break;
		}
		default:
		{
			ZydisRegisterContext context = {};
			linux_context_to_zydis_context((const ucontext_t*) platform_context, &context);
			if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(
				instruction, operand, runtime_address, &context, result)))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
		}
	}
	
	return MEMCORDER_SUCCESS;
}

static ZyanBool get_integer_register(ZydisRegister reg, ucontext_t* context, ZyanU64* result)
{
	switch (reg)
	{
		case ZYDIS_REGISTER_AL: *result = context->uc_mcontext.gregs[REG_RAX] & 0xff; break;
		case ZYDIS_REGISTER_CL: *result = context->uc_mcontext.gregs[REG_RCX] & 0xff; break;
		case ZYDIS_REGISTER_DL: *result = context->uc_mcontext.gregs[REG_RDX] & 0xff; break;
		case ZYDIS_REGISTER_BL: *result = context->uc_mcontext.gregs[REG_RBX] & 0xff; break;
		case ZYDIS_REGISTER_AH: *result = (context->uc_mcontext.gregs[REG_RAX] >> 8) & 0xff; break;
		case ZYDIS_REGISTER_CH: *result = (context->uc_mcontext.gregs[REG_RCX] >> 8) & 0xff; break;
		case ZYDIS_REGISTER_DH: *result = (context->uc_mcontext.gregs[REG_RDX] >> 8) & 0xff; break;
		case ZYDIS_REGISTER_BH: *result = (context->uc_mcontext.gregs[REG_RBX] >> 8) & 0xff; break;
		case ZYDIS_REGISTER_R8B: *result = context->uc_mcontext.gregs[REG_R8] & 0xff; break;
		case ZYDIS_REGISTER_R9B: *result = context->uc_mcontext.gregs[REG_R9] & 0xff; break;
		case ZYDIS_REGISTER_R10B: *result = context->uc_mcontext.gregs[REG_R10] & 0xff; break;
		case ZYDIS_REGISTER_R11B: *result = context->uc_mcontext.gregs[REG_R11] & 0xff; break;
		case ZYDIS_REGISTER_R12B: *result = context->uc_mcontext.gregs[REG_R12] & 0xff; break;
		case ZYDIS_REGISTER_R13B: *result = context->uc_mcontext.gregs[REG_R13] & 0xff; break;
		case ZYDIS_REGISTER_R14B: *result = context->uc_mcontext.gregs[REG_R14] & 0xff; break;
		case ZYDIS_REGISTER_R15B: *result = context->uc_mcontext.gregs[REG_R15] & 0xff; break;
		case ZYDIS_REGISTER_AX: *result = context->uc_mcontext.gregs[REG_RAX] & 0xffff; break;
		case ZYDIS_REGISTER_CX: *result = context->uc_mcontext.gregs[REG_RCX] & 0xffff; break;
		case ZYDIS_REGISTER_DX: *result = context->uc_mcontext.gregs[REG_RDX] & 0xffff; break;
		case ZYDIS_REGISTER_BX: *result = context->uc_mcontext.gregs[REG_RBX] & 0xffff; break;
		case ZYDIS_REGISTER_SP: *result = context->uc_mcontext.gregs[REG_RSP] & 0xffff; break;
		case ZYDIS_REGISTER_BP: *result = context->uc_mcontext.gregs[REG_RBP] & 0xffff; break;
		case ZYDIS_REGISTER_SI: *result = context->uc_mcontext.gregs[REG_RSI] & 0xffff; break;
		case ZYDIS_REGISTER_DI: *result = context->uc_mcontext.gregs[REG_RDI] & 0xffff; break;
		case ZYDIS_REGISTER_R8W: *result = context->uc_mcontext.gregs[REG_R8] & 0xffff; break;
		case ZYDIS_REGISTER_R9W: *result = context->uc_mcontext.gregs[REG_R9] & 0xffff; break;
		case ZYDIS_REGISTER_R10W: *result = context->uc_mcontext.gregs[REG_R10] & 0xffff; break;
		case ZYDIS_REGISTER_R11W: *result = context->uc_mcontext.gregs[REG_R11] & 0xffff; break;
		case ZYDIS_REGISTER_R12W: *result = context->uc_mcontext.gregs[REG_R12] & 0xffff; break;
		case ZYDIS_REGISTER_R13W: *result = context->uc_mcontext.gregs[REG_R13] & 0xffff; break;
		case ZYDIS_REGISTER_R14W: *result = context->uc_mcontext.gregs[REG_R14] & 0xffff; break;
		case ZYDIS_REGISTER_R15W: *result = context->uc_mcontext.gregs[REG_R15] & 0xffff; break;
		case ZYDIS_REGISTER_EAX: *result = context->uc_mcontext.gregs[REG_RAX] & 0xffffffff; break;
		case ZYDIS_REGISTER_ECX: *result = context->uc_mcontext.gregs[REG_RCX] & 0xffffffff; break;
		case ZYDIS_REGISTER_EDX: *result = context->uc_mcontext.gregs[REG_RDX] & 0xffffffff; break;
		case ZYDIS_REGISTER_EBX: *result = context->uc_mcontext.gregs[REG_RBX] & 0xffffffff; break;
		case ZYDIS_REGISTER_ESP: *result = context->uc_mcontext.gregs[REG_RSP] & 0xffffffff; break;
		case ZYDIS_REGISTER_EBP: *result = context->uc_mcontext.gregs[REG_RBP] & 0xffffffff; break;
		case ZYDIS_REGISTER_ESI: *result = context->uc_mcontext.gregs[REG_RSI] & 0xffffffff; break;
		case ZYDIS_REGISTER_EDI: *result = context->uc_mcontext.gregs[REG_RDI] & 0xffffffff; break;
		case ZYDIS_REGISTER_R8D: *result = context->uc_mcontext.gregs[REG_R8] & 0xffffffff; break;
		case ZYDIS_REGISTER_R9D: *result = context->uc_mcontext.gregs[REG_R9] & 0xffffffff; break;
		case ZYDIS_REGISTER_R10D: *result = context->uc_mcontext.gregs[REG_R10] & 0xffffffff; break;
		case ZYDIS_REGISTER_R11D: *result = context->uc_mcontext.gregs[REG_R11] & 0xffffffff; break;
		case ZYDIS_REGISTER_R12D: *result = context->uc_mcontext.gregs[REG_R12] & 0xffffffff; break;
		case ZYDIS_REGISTER_R13D: *result = context->uc_mcontext.gregs[REG_R13] & 0xffffffff; break;
		case ZYDIS_REGISTER_R14D: *result = context->uc_mcontext.gregs[REG_R14] & 0xffffffff; break;
		case ZYDIS_REGISTER_R15D: *result = context->uc_mcontext.gregs[REG_R15] & 0xffffffff; break;
		case ZYDIS_REGISTER_RAX: *result = context->uc_mcontext.gregs[REG_RAX]; break;
		case ZYDIS_REGISTER_RCX: *result = context->uc_mcontext.gregs[REG_RCX]; break;
		case ZYDIS_REGISTER_RDX: *result = context->uc_mcontext.gregs[REG_RDX]; break;
		case ZYDIS_REGISTER_RBX: *result = context->uc_mcontext.gregs[REG_RBX]; break;
		case ZYDIS_REGISTER_RSP: *result = context->uc_mcontext.gregs[REG_RSP]; break;
		case ZYDIS_REGISTER_RBP: *result = context->uc_mcontext.gregs[REG_RBP]; break;
		case ZYDIS_REGISTER_RSI: *result = context->uc_mcontext.gregs[REG_RSI]; break;
		case ZYDIS_REGISTER_RDI: *result = context->uc_mcontext.gregs[REG_RDI]; break;
		case ZYDIS_REGISTER_R8: *result = context->uc_mcontext.gregs[REG_R8]; break;
		case ZYDIS_REGISTER_R9: *result = context->uc_mcontext.gregs[REG_R9]; break;
		case ZYDIS_REGISTER_R10: *result = context->uc_mcontext.gregs[REG_R10]; break;
		case ZYDIS_REGISTER_R11: *result = context->uc_mcontext.gregs[REG_R11]; break;
		case ZYDIS_REGISTER_R12: *result = context->uc_mcontext.gregs[REG_R12]; break;
		case ZYDIS_REGISTER_R13: *result = context->uc_mcontext.gregs[REG_R13]; break;
		case ZYDIS_REGISTER_R14: *result = context->uc_mcontext.gregs[REG_R14]; break;
		case ZYDIS_REGISTER_R15: *result = context->uc_mcontext.gregs[REG_R15]; break;
		case ZYDIS_REGISTER_FLAGS: *result = 0; break;
		case ZYDIS_REGISTER_EFLAGS: *result = 0; break;
		case ZYDIS_REGISTER_RFLAGS: *result = 0; break;
		case ZYDIS_REGISTER_IP: *result = context->uc_mcontext.gregs[REG_RIP] & 0xffff; break;
		case ZYDIS_REGISTER_EIP: *result = context->uc_mcontext.gregs[REG_RIP] & 0xffffffff; break;
		case ZYDIS_REGISTER_RIP: *result = context->uc_mcontext.gregs[REG_RIP]; break;
		case ZYDIS_REGISTER_FS: *result = _readfsbase_u64(); break; // Assume fs is the same in the signal handler.
		case ZYDIS_REGISTER_GS: *result = _readgsbase_u64(); break; // Assume gs is the same in the signal handler.
		default:
		{
			return ZYAN_FALSE;
		}
	}
	
	return ZYAN_TRUE;
}

static int64_t to_signed(uint64_t value, int size)
{
	int64_t result;
	switch (size)
	{
		case 8: result = (int8_t) (uint8_t) value; break;
		case 16: result = (int16_t) (uint16_t) value; break;
		case 32: result = (int32_t) (uint32_t) value; break;
		default: result = (int64_t) value; break;
	}
	
	return result;
}

static void linux_context_to_zydis_context(
	const ucontext_t* source,
	ZydisRegisterContext* destination)
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
