// This file is part of Memcorder.
// SPDX-License-Identifier: MIT

#include "memory.h"

#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>

#include <sys/user.h>
#define __USE_GNU
#include <sys/ucontext.h>
#include <immintrin.h>

static MemcorderStatus handle_special_instructions(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
	uint64_t runtime_address,
	const void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count);
static MemcorderStatus calculate_operand_value(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	uint64_t runtime_address,
	const void* platform_context,
	uint64_t* result);
static MemcorderStatus calculate_memory_operand_value(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	uint64_t runtime_address,
	const void* platform_context,
	size_t element_count,
	uint64_t* result);
static MemcorderStatus calculate_memory_operand_address(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	uint64_t runtime_address,
	const void* platform_context,
	uint64_t* result);
static int64_t to_signed(uint64_t value, int size);
static uint64_t truncate_to_size(
	uint64_t value,
	int size);
static ZyanBool get_integer_register(ZydisRegister reg, const void* platform_context, uint64_t* result);
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
	
	MemcorderStatus special_cases_status = handle_special_instructions(
		&decoded_instruction,
		decoded_operands,
		(uint64_t) instruction,
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
			if (calculate_memory_operand_address(
				&decoded_instruction, operand, (uint64_t) instruction, platform_context, (uint64_t*) &access->address)
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
			if (calculate_memory_operand_address(
				&decoded_instruction, operand, (uint64_t) instruction, platform_context, (uint64_t*) &access->address)
				!= MEMCORDER_SUCCESS)
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			access->size = operand->size / 8;
			access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
		}
	}
	
	return MEMCORDER_SUCCESS;
}

static MemcorderStatus handle_special_instructions(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT],
	uint64_t runtime_address,
	const void* platform_context,
	MemcorderMemoryAccessType types,
	MemcorderMemoryAccess output_accesses[MEMCORDER_MAX_MEMORY_ACCESSES_PER_INSTRUCTION],
	size_t* output_access_count)
{
	switch (instruction->mnemonic)
	{
		case ZYDIS_MNEMONIC_BT:
		case ZYDIS_MNEMONIC_BTC:
		case ZYDIS_MNEMONIC_BTR:
		case ZYDIS_MNEMONIC_BTS:
		{
			assert(instruction->operand_count >= 2);
			const ZydisDecodedOperand* bit_base_operand = &operands[0];
			const ZydisDecodedOperand* bit_offset_operand = &operands[1];
			
			if (bit_base_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
				break;
			
			uint64_t bit_base;
			if (calculate_memory_operand_address(
				instruction, bit_base_operand, runtime_address, platform_context, &bit_base)
				!= MEMCORDER_SUCCESS)
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			uint64_t bit_offset_unsigned;
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
			
			if ((types & MEMCORDER_MEMORY_ACCESS_TYPE_WRITE) && instruction->mnemonic != ZYDIS_MNEMONIC_BT)
			{
				MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
				if (bit_offset < 0 && (bit_offset % 8) != 0)
					access->address = (void*) (bit_base + bit_offset / 8 - 1);
				else
					access->address = (void*) (bit_base + bit_offset / 8);
				access->size = 1;
				access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
			}
			
			break;
		}
		case ZYDIS_MNEMONIC_CMPXCHG:
		{
			assert(instruction->operand_count >= 2);
			const ZydisDecodedOperand* source_dest_operand = &operands[0];
			
			if (source_dest_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
				break;
			
			uint64_t rax;
			if (!get_integer_register(ZYDIS_REGISTER_RAX, platform_context, &rax))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			rax = truncate_to_size(rax, source_dest_operand->size);
			
			uint64_t value;
			MemcorderStatus status = calculate_memory_operand_value(
				instruction, source_dest_operand, runtime_address, platform_context, 1, &value);
			if (status != MEMCORDER_SUCCESS)
				return status;
			
			if (value == rax)
				return -1;
			
			break;
		}
		case ZYDIS_MNEMONIC_CMPXCHG8B:
		{
			assert(instruction->operand_count >= 1);
			const ZydisDecodedOperand* source_dest_operand = &operands[0];
			
			if (source_dest_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
				break;
			
			uint64_t edx;
			if (!get_integer_register(ZYDIS_REGISTER_EDX, platform_context, &edx))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			uint64_t eax;
			if (!get_integer_register(ZYDIS_REGISTER_EAX, platform_context, &eax))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			uint64_t value;
			MemcorderStatus status = calculate_memory_operand_value(
				instruction, source_dest_operand, runtime_address, platform_context, 1, &value);
			if (status != MEMCORDER_SUCCESS)
				return status;
			
			if ((value & 0xffffffff) == edx && (value >> 32) == eax)
				return -1;
			
			break;
		}
		case ZYDIS_MNEMONIC_CMPXCHG16B:
		{
			assert(instruction->operand_count >= 1);
			const ZydisDecodedOperand* source_dest_operand = &operands[0];
			
			if (source_dest_operand->type != ZYDIS_OPERAND_TYPE_MEMORY)
				break;
			
			uint64_t rdx;
			if (!get_integer_register(ZYDIS_REGISTER_RDX, platform_context, &rdx))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			uint64_t rax;
			if (!get_integer_register(ZYDIS_REGISTER_RAX, platform_context, &rax))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			
			uint64_t value[2];
			MemcorderStatus status = calculate_memory_operand_value(
				instruction, source_dest_operand, runtime_address, platform_context, 2, value);
			if (status != MEMCORDER_SUCCESS)
				return status;
			
			if (value[0] == rdx && value[1] == rax)
				return -1;
			
			break;
		}
		case ZYDIS_MNEMONIC_FXRSTOR:
		case ZYDIS_MNEMONIC_FXRSTOR64:
		{
			// Zydis reports this as a 512 bit read, but the manual says it only
			// uses 464 bytes at most, so report that instead.
			
			assert(instruction->operand_count >= 1);
			const ZydisDecodedOperand* source_operand = &operands[0];
			
			if (types & MEMCORDER_MEMORY_ACCESS_TYPE_READ)
			{
				MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
				access->address = 0;
				if (calculate_memory_operand_address(
					instruction, source_operand, runtime_address, platform_context, (uint64_t*) &access->address)
					!= MEMCORDER_SUCCESS)
					return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
				access->size = 464;
				access->type = MEMCORDER_MEMORY_ACCESS_TYPE_READ;
			}
			
			break;
		}
		case ZYDIS_MNEMONIC_FXSAVE:
		case ZYDIS_MNEMONIC_FXSAVE64:
		{
			// Zydis reports this as a 512 bit write, but the manual says it's
			// actually a 464 byte write at most, so report that instead.
			
			assert(instruction->operand_count >= 1);
			const ZydisDecodedOperand* dest_operand = &operands[0];
			
			if (types & MEMCORDER_MEMORY_ACCESS_TYPE_WRITE)
			{
				MemcorderMemoryAccess* access = &output_accesses[(*output_access_count)++];
				access->address = 0;
				if (calculate_memory_operand_address(
					instruction, dest_operand, runtime_address, platform_context, (uint64_t*) &access->address)
					!= MEMCORDER_SUCCESS)
					return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
				access->size = 464;
				access->type = MEMCORDER_MEMORY_ACCESS_TYPE_WRITE;
			}
			
			break;
		}
		default:
		{
			return -1;
		}
	}
	
	return MEMCORDER_SUCCESS;
}

static MemcorderStatus calculate_operand_value(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	uint64_t runtime_address,
	const void* platform_context,
	uint64_t* result)
{
	switch (operand->type)
	{
		case ZYDIS_OPERAND_TYPE_REGISTER:
		{
			if (!get_integer_register(operand->reg.value, platform_context, result))
				return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
			break;
		}
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		{
			*result = operand->imm.value.u;
			break;
		}
		case ZYDIS_OPERAND_TYPE_MEMORY:
		{
			MemcorderStatus status = calculate_memory_operand_value(
				instruction,
				operand,
				runtime_address,
				platform_context,
				1,
				result);
			if (status != MEMCORDER_SUCCESS)
				return status;
			
			break;
		}
		default:
		{
			return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
		}
	}
	
	return MEMCORDER_SUCCESS;
}

static MemcorderStatus calculate_memory_operand_value(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	uint64_t runtime_address,
	const void* platform_context,
	size_t element_count,
	uint64_t* result)
{
	uint64_t address;
	MemcorderStatus status = calculate_memory_operand_address(
		instruction, operand, runtime_address, platform_context, &address);
	if (status != MEMCORDER_SUCCESS)
		return status;
	
	switch (operand->size)
	{
		case 8:
			for (size_t i = 0; i < element_count; i++)
				((uint64_t*) result)[i] = ((uint8_t*) address)[i];
			break;
		case 16:
			for (size_t i = 0; i < element_count; i++)
				((uint64_t*) result)[i] = ((uint16_t*) address)[i];
			break;
		case 32:
			for (size_t i = 0; i < element_count; i++)
				((uint64_t*) result)[i] = ((uint32_t*) address)[i];
			break;
		case 64:
		case 128:
			for (size_t i = 0; i < element_count; i++)
				((uint64_t*) result)[i] = ((uint64_t*) address)[i];
			break;
		default: return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
	}
	
	return MEMCORDER_SUCCESS;
}

static MemcorderStatus calculate_memory_operand_address(
	const ZydisDecodedInstruction* instruction,
	const ZydisDecodedOperand* operand,
	uint64_t runtime_address,
	const void* platform_context,
	uint64_t* result)
{
	assert(operand->type == ZYDIS_OPERAND_TYPE_MEMORY);
	
	ZydisRegisterContext context = {};
	linux_context_to_zydis_context((const ucontext_t*) platform_context, &context);
	
	if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(
		instruction, operand, (ZyanU64) runtime_address, &context, (ZyanU64*) result)))
		return MEMCORDER_ADDRESS_CALCULATION_FAILURE;
	
	return MEMCORDER_SUCCESS;
}

static ZyanBool get_integer_register(ZydisRegister reg, const void* platform_context, uint64_t* result)
{
	const ucontext_t* context = (const ucontext_t*) platform_context;
	
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

static int64_t to_signed(
	uint64_t value,
	int size)
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

static uint64_t truncate_to_size(
	uint64_t value,
	int size)
{
	uint64_t result;
	switch (size)
	{
		case 8: result = value & 0xff; break;
		case 16: result = value & 0xffff; break;
		case 32: result = value & 0xffffffff; break;
		default: result = value; break;
	}
	
	return result;
}

static void linux_context_to_zydis_context(
	const ucontext_t* source,
	ZydisRegisterContext* destination)
{
	destination->values[ZYDIS_REGISTER_AL] = source->uc_mcontext.gregs[REG_RAX] & 0xff;
	destination->values[ZYDIS_REGISTER_CL] = source->uc_mcontext.gregs[REG_RCX] & 0xff;
	destination->values[ZYDIS_REGISTER_DL] = source->uc_mcontext.gregs[REG_RDX] & 0xff;
	destination->values[ZYDIS_REGISTER_BL] = source->uc_mcontext.gregs[REG_RBX] & 0xff;
	destination->values[ZYDIS_REGISTER_BL] = source->uc_mcontext.gregs[REG_RBP] & 0xff;
	destination->values[ZYDIS_REGISTER_DL] = source->uc_mcontext.gregs[REG_RDI] & 0xff;
	destination->values[ZYDIS_REGISTER_AH] = (source->uc_mcontext.gregs[REG_RAX] >> 8) & 0xff;
	destination->values[ZYDIS_REGISTER_CH] = (source->uc_mcontext.gregs[REG_RCX] >> 8) & 0xff;
	destination->values[ZYDIS_REGISTER_DH] = (source->uc_mcontext.gregs[REG_RDX] >> 8) & 0xff;
	destination->values[ZYDIS_REGISTER_BH] = (source->uc_mcontext.gregs[REG_RBX] >> 8) & 0xff;
	destination->values[ZYDIS_REGISTER_BH] = (source->uc_mcontext.gregs[REG_RBP] >> 8) & 0xff;
	destination->values[ZYDIS_REGISTER_DH] = (source->uc_mcontext.gregs[REG_RDI] >> 8) & 0xff;
	destination->values[ZYDIS_REGISTER_R8B] = source->uc_mcontext.gregs[REG_R8] & 0xff;
	destination->values[ZYDIS_REGISTER_R9B] = source->uc_mcontext.gregs[REG_R9] & 0xff;
	destination->values[ZYDIS_REGISTER_R10B] = source->uc_mcontext.gregs[REG_R10] & 0xff;
	destination->values[ZYDIS_REGISTER_R11B] = source->uc_mcontext.gregs[REG_R11] & 0xff;
	destination->values[ZYDIS_REGISTER_R12B] = source->uc_mcontext.gregs[REG_R12] & 0xff;
	destination->values[ZYDIS_REGISTER_R13B] = source->uc_mcontext.gregs[REG_R13] & 0xff;
	destination->values[ZYDIS_REGISTER_R14B] = source->uc_mcontext.gregs[REG_R14] & 0xff;
	destination->values[ZYDIS_REGISTER_R15B] = source->uc_mcontext.gregs[REG_R15] & 0xff;
	
	destination->values[ZYDIS_REGISTER_AX] = source->uc_mcontext.gregs[REG_RAX] & 0xffff;
	destination->values[ZYDIS_REGISTER_CX] = source->uc_mcontext.gregs[REG_RCX] & 0xffff;
	destination->values[ZYDIS_REGISTER_DX] = source->uc_mcontext.gregs[REG_RDX] & 0xffff;
	destination->values[ZYDIS_REGISTER_BX] = source->uc_mcontext.gregs[REG_RBX] & 0xffff;
	destination->values[ZYDIS_REGISTER_SP] = source->uc_mcontext.gregs[REG_RSP] & 0xffff;
	destination->values[ZYDIS_REGISTER_BP] = source->uc_mcontext.gregs[REG_RBP] & 0xffff;
	destination->values[ZYDIS_REGISTER_SI] = source->uc_mcontext.gregs[REG_RSI] & 0xffff;
	destination->values[ZYDIS_REGISTER_DI] = source->uc_mcontext.gregs[REG_RDI] & 0xffff;
	destination->values[ZYDIS_REGISTER_R8W] = source->uc_mcontext.gregs[REG_R8] & 0xffff;
	destination->values[ZYDIS_REGISTER_R9W] = source->uc_mcontext.gregs[REG_R9] & 0xffff;
	destination->values[ZYDIS_REGISTER_R10W] = source->uc_mcontext.gregs[REG_R10] & 0xffff;
	destination->values[ZYDIS_REGISTER_R11W] = source->uc_mcontext.gregs[REG_R11] & 0xffff;
	destination->values[ZYDIS_REGISTER_R12W] = source->uc_mcontext.gregs[REG_R12] & 0xffff;
	destination->values[ZYDIS_REGISTER_R13W] = source->uc_mcontext.gregs[REG_R13] & 0xffff;
	destination->values[ZYDIS_REGISTER_R14W] = source->uc_mcontext.gregs[REG_R14] & 0xffff;
	destination->values[ZYDIS_REGISTER_R15W] = source->uc_mcontext.gregs[REG_R15] & 0xffff;
	
	destination->values[ZYDIS_REGISTER_EAX] = source->uc_mcontext.gregs[REG_RAX] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_ECX] = source->uc_mcontext.gregs[REG_RCX] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_EDX] = source->uc_mcontext.gregs[REG_RDX] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_EBX] = source->uc_mcontext.gregs[REG_RBX] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_ESP] = source->uc_mcontext.gregs[REG_RSP] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_EBP] = source->uc_mcontext.gregs[REG_RBP] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_ESI] = source->uc_mcontext.gregs[REG_RSI] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_EDI] = source->uc_mcontext.gregs[REG_RDI] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R8D] = source->uc_mcontext.gregs[REG_R8] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R9D] = source->uc_mcontext.gregs[REG_R9] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R10D] = source->uc_mcontext.gregs[REG_R10] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R11D] = source->uc_mcontext.gregs[REG_R11] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R12D] = source->uc_mcontext.gregs[REG_R12] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R13D] = source->uc_mcontext.gregs[REG_R13] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R14D] = source->uc_mcontext.gregs[REG_R14] & 0xffffffff;
	destination->values[ZYDIS_REGISTER_R15D] = source->uc_mcontext.gregs[REG_R15] & 0xffffffff;
	
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
