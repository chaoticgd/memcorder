#!/usr/bin/env python3

import json

# Parse Zydis's instruction table file and print out all the instructions that
# touch memory, so that we can make a more comprehensive test suite. See:
# https://raw.githubusercontent.com/zyantific/zydis-db/refs/heads/master/Data/instructions.json

instructions = []
with open("instructions.json") as file:
	instructions = json.loads(file.read())

operand_type_accesses_memory = {
	'abs': False, # absolute value
	'agen': False, # address generation
	'agen_norel': False, # address generation
	'bnd': False, # bounds register
	'cr': False, # control register
	'dr': False, # debug register
	'fpr': False, # floating point register
	'gpr16': False, # general purpose register
	'gpr16_32_32': False, # general purpose register
	'gpr16_32_64': False, # general purpose register
	'gpr32': False, # general purpose register
	'gpr32_32_64': False, # general purpose register
	'gpr64': False, # general purpose register
	'gpr8': False, # general purpose register
	'gpr_asz': False, # general purpose register
	'imm': False, # immediate
	'implicit_imm1': False, # implicit immediate
	'implicit_mem': True, # implicit memory
	'implicit_reg': False, # implicit register
	'mask': False, # mask
	'mem': True, # memory
	'mem_vsibx': True, # vector array of memory operands
	'mem_vsiby': True, # vector array of memory operands
	'mem_vsibz': True, # vector array of memory operands
	'mib': True, # memory SIB
	'mmx': False, # mmx register
	'moffs': True, # memory offset relative to segment base
	'ptr': True, # pointer
	'rel': False, # rip relative value
	'sreg': False, # segment register
	'tmm': False, # simd amx
	'xmm': False, # simd
	'ymm': False, # simd avx2
	'zmm': False # simd avx512
}

instructions_that_read = []
instructions_that_write = []

for instruction in instructions:
	if 'operands' in instruction:
		for operand in instruction['operands']:
			if (
				'action' in operand and
				'read' in operand['action'] and
				operand_type_accesses_memory[operand['operand_type']]
			):
				instructions_that_read.append(
					instruction['mnemonic'] + ' ' + instruction['opcode'] + ' ' + instruction['meta_info']['extension'])
				break
		for operand in instruction['operands']:
			if (
				'action' in operand and
				'write' in operand['action'] and
				operand_type_accesses_memory[operand['operand_type']]
			):
				instructions_that_write.append(
					instruction['mnemonic'] + ' ' + instruction['opcode'] + ' ' + instruction['meta_info']['extension'])
				break

instructions_that_read = sorted(set(instructions_that_read))
instructions_that_write = sorted(set(instructions_that_write))

for instruction in instructions_that_read:
	print('READ: ' + instruction)

for instruction in instructions_that_write:
	print('WRITE: ' + instruction)
