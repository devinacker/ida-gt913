# ----------------------------------------------------------------------
# Casio GT913F / NEC uPD913GF processor module for IDA 7.x
# by Devin Acker, (c)2022
# released under the MIT license

import sys
import idaapi
from idaapi import *

def op_itype(op_name):
	return "itype_%s" % op_name.replace('.', '_')

# ----------------------------------------------------------------------
class gt913_processor_t(idaapi.processor_t):

	# IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
	id = 0x8000 + 913

	# Processor features
	flag = PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_BINMEM | PR_WORD_INS

	# Number of bits in a byte for code segments (usually 8)
	# IDA supports values up to 32 bits
	cnbits = 8

	# Number of bits in a byte for non-code segments (usually 8)
	# IDA supports values up to 32 bits
	dnbits = 8

	# short processor names
	# Each name should be shorter than 9 characters
	psnames = ['gt913', 'upd913']

	# long processor names
	# No restriction on name lengthes.
	plnames = ['Casio GT913F', 'NEC uPD913GF']

	# register names
	reg_names_8 = [
		"r0h", "r1h", "r2h", "r3h", "r4h", "r5h", "r6h", "r7h",
		"r0l", "r1l", "r2l", "r3l", "r4l", "r5l", "r6l", "r7l"
	]

	reg_names_16 = [
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "sp"
	]
	
	reg_names = reg_names_8 + reg_names_16 + [
		# General purpose registers
		"pc", "ccr", "bankh", "bankl",
		# Fake segment registers
		"cs", "ds"
	]

	# Segment register information (use virtual CS and DS registers if your
	# processor doesn't have segment registers):
	reg_first_sreg = reg_names.index("cs") # index of CS
	reg_last_sreg  = reg_names.index("ds") # index of DS
	
	reg_pc     = reg_names.index("pc")
	reg_ccr    = reg_names.index("ccr")
	reg_bankh  = reg_names.index("bankh")
	reg_bankl  = reg_names.index("bankl")
	reg_num_8  = reg_names.index("r0h")
	reg_num_16 = reg_names.index("r0")
	reg_sp     = reg_num_16 + 7

	# size of a segment register in bytes
	segreg_size = 0

	# You should define 2 virtual segment registers for CS and DS.

	# number of CS/DS registers
	reg_code_sreg = reg_first_sreg
	reg_data_sreg = reg_last_sreg

	# ----------------------------------------------------------------------
	# Instruction decoding

	def OP_bankl(self, op, data, moredata): # bank number, low bits
		op.type = o_reg
		op.reg  = self.reg_bankl
	
	def OP_bankh(self, op, data, moredata): # bank number, high bits
		op.type = o_reg
		op.reg  = self.reg_bankh
	
	def OP_ccr(self, op, data, moredata): # ccr/flags reg
		op.type = o_reg
		op.reg  = self.reg_ccr
	
	def OP_r8l(self, op, data, moredata): # 8-bit register in low bits
		op.type = o_reg
		op.reg  = self.reg_num_8 + (data & 0xf)
	
	def OP_r8h(self, op, data, moredata): # 8-bit register in higher bits
		op.type = o_reg
		op.reg  = self.reg_num_8 + ((data >> 4) & 0xf)
	
	def OP_r8u(self, op, data, moredata): # 8-bit register in upper bits
		op.type = o_reg
		op.reg  = self.reg_num_8 + ((data >> 8) & 0xf)
		
	def OP_r16l(self, op, data, moredata): # 16-bit register in low bits
		op.type = o_reg
		op.reg  = self.reg_num_16 + (data & 0x7)
	
	def OP_r16h(self, op, data, moredata): # 16-bit register in higher bits
		op.type = o_reg
		op.reg  = self.reg_num_16 + ((data >> 4) & 0x7)
	
	def OP_r16ih(self, op, data, moredata): # 16-bit register indirect in higher bits
		op.type   = o_phrase
		op.phrase = self.reg_num_16 + ((data >> 4) & 0x7)
	
	def OP_r16ph(self, op, data, moredata): # 16-bit register indirect (post-increment) in higher bits
		op.type    = o_phrase
		op.phrase  = self.reg_num_16 + ((data >> 4) & 0x7)
		op.specval = 1
	
	def OP_pr16h(self, op, data, moredata): # 16-bit register indirect (pre-decrement) in higher bits
		op.type    = o_phrase
		op.phrase  = self.reg_num_16 + ((data >> 4) & 0x7)
		op.specval = -1
	
	def OP_r16d16h(self, op, data, moredata): # 16-bit register indirect (with displacement) in higher bits
		op.type    = o_displ
		op.phrase  = self.reg_num_16 + ((data >> 4) & 0x7)
		op.addr    = moredata
		op.dtype   = dt_word
	
	def OP_abs8(self, op, data, moredata): # 8-bit absolute data address (relative to 0xff00)
		op.type = o_mem
		op.addr = 0xff00 | (data & 0xff)
	
	def OP_abs8c(self, op, data, moredata): # 8-bit absolute code address
		op.type = o_near
		op.addr = data & 0xff
	
	def OP_abs16(self, op, data, moredata): # 16-bit absolute data address
		op.type = o_mem
		op.addr = moredata
	
	def OP_abs16c(self, op, data, moredata): # 16-bit absolute code address
		op.type = o_near
		op.addr = moredata
	
	def OP_rel8(self, op, data, moredata): # 8-bit PC-relative
		op.type  = o_idpspec0
		op.addr = data & 0xff
		if (data & 0x80):
			op.addr -= 256
	
	def OP_imm2l(self, op, data, moredata): # 2-bit immediate (for bankl)
		op.type  = o_imm
		op.value = data & 0x03
	
	def OP_imm3(self, op, data, moredata): # 3-bit immediate
		op.type  = o_imm
		op.value = (data >> 4) & 0x7
	
	def OP_imm3x(self, op, data, moredata): # 3-bit immediate (in next word)
		op.type  = o_imm
		op.value = (moredata >> 4) & 0x7
	
	def OP_imm4l(self, op, data, moredata): # 4-bit immediate (for bankl)
		op.type  = o_imm
		op.value = data & 0x0f
	
	def OP_imm8(self, op, data, moredata): # 8-bit immediate
		op.type  = o_imm
		op.value = data & 0xff
	
	def OP_imm16(self, op, data, moredata): # 16-bit immediate
		op.type  = o_imm
		op.value = moredata
		op.dtype = dt_word
	
	def OP_one(self, op, data, moredata):
		op.type  = o_imm
		op.value = 1

	def OP_two(self, op, data, moredata):
		op.type  = o_imm
		op.value = 2
	
	opcodes = [
		{'opcode': 0x0000, 'mask': 0xffff, 'name': "nop",     'op1': None,       'op2': None},
		{'opcode': 0x0100, 'mask': 0xffff, 'name': "sleep",   'op1': None,       'op2': None},
		{'opcode': 0x0240, 'mask': 0xfff0, 'name': "stc",     'op1': OP_ccr,     'op2': OP_r8l},
		{'opcode': 0x0340, 'mask': 0xfff0, 'name': "ldc",     'op1': OP_r8l,     'op2': OP_ccr},
		{'opcode': 0x0380, 'mask': 0xfff0, 'name': "ldbank",  'op1': OP_r8l,     'op2': OP_bankh},
		{'opcode': 0x03c0, 'mask': 0xfff0, 'name': "ldbank",  'op1': OP_r8l,     'op2': OP_bankl},
		{'opcode': 0x0400, 'mask': 0xff00, 'name': "orc",     'op1': OP_imm8,    'op2': OP_ccr},
		{'opcode': 0x0500, 'mask': 0xff00, 'name': "xorc",    'op1': OP_imm8,    'op2': OP_ccr},
		{'opcode': 0x0600, 'mask': 0xff00, 'name': "andc",    'op1': OP_imm8,    'op2': OP_ccr},
		{'opcode': 0x0780, 'mask': 0xfff0, 'name': "ldbank",  'op1': OP_imm4l,   'op2': OP_bankh},
		{'opcode': 0x07c0, 'mask': 0xfff0, 'name': "ldbank",  'op1': OP_imm2l,   'op2': OP_bankl},
		{'opcode': 0x0800, 'mask': 0xff00, 'name': "add.b",   'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x0900, 'mask': 0xff00, 'name': "add.w",   'op1': OP_r16h,    'op2': OP_r16l},
		{'opcode': 0x0a00, 'mask': 0xfff0, 'name': "inc.b",   'op1': OP_r8l,     'op2': None},
		{'opcode': 0x0b00, 'mask': 0xfff8, 'name': "adds.l",  'op1': OP_one,     'op2': OP_r16l},
		{'opcode': 0x0b80, 'mask': 0xfff8, 'name': "adds.l",  'op1': OP_two,     'op2': OP_r16l},
		{'opcode': 0x0c00, 'mask': 0xff00, 'name': "mov.b",   'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x0d00, 'mask': 0xff00, 'name': "mov.w",   'op1': OP_r16h,    'op2': OP_r16l},
		{'opcode': 0x0e00, 'mask': 0xff00, 'name': "addx.b",  'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x0f00, 'mask': 0xff00, 'name': "mulxu.b", 'op1': OP_r8h,     'op2': OP_r16l},
		{'opcode': 0x1000, 'mask': 0xfff0, 'name': "shll.b",  'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1080, 'mask': 0xfff0, 'name': "shal.b",  'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1100, 'mask': 0xfff0, 'name': "shlr.b",  'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1180, 'mask': 0xfff0, 'name': "shar.b",  'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1200, 'mask': 0xfff0, 'name': "rotxl.b", 'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1280, 'mask': 0xfff0, 'name': "rotl.b",  'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1300, 'mask': 0xfff0, 'name': "rotxr.b", 'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1380, 'mask': 0xfff0, 'name': "rotr.b",  'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1400, 'mask': 0xff00, 'name': "or.b",    'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x1500, 'mask': 0xff00, 'name': "xor.b",   'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x1600, 'mask': 0xff00, 'name': "and.b",   'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x1700, 'mask': 0xfff0, 'name': "not.b",   'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1780, 'mask': 0xfff0, 'name': "neg.b",   'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1800, 'mask': 0xff00, 'name': "sub.b",   'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x1900, 'mask': 0xff00, 'name': "sub.w",   'op1': OP_r16h,    'op2': OP_r16l},
		{'opcode': 0x1a00, 'mask': 0xfff0, 'name': "dec.b",   'op1': OP_r8l,     'op2': None},
		{'opcode': 0x1b00, 'mask': 0xfff8, 'name': "subs.l",  'op1': OP_two,     'op2': OP_r16l},
		{'opcode': 0x1b80, 'mask': 0xfff8, 'name': "subs.l",  'op1': OP_one,     'op2': OP_r16l},
		{'opcode': 0x1c00, 'mask': 0xff00, 'name': "cmp.b",   'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x1d00, 'mask': 0xff00, 'name': "cmp.w",   'op1': OP_r16h,    'op2': OP_r16l},
		{'opcode': 0x1e00, 'mask': 0xff00, 'name': "subx.b",  'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x1f00, 'mask': 0xff00, 'name': "divxu.b", 'op1': OP_r8h,     'op2': OP_r16l},
		{'opcode': 0x2000, 'mask': 0xf000, 'name': "mov.b",   'op1': OP_abs8,    'op2': OP_r8u},
		{'opcode': 0x3000, 'mask': 0xf000, 'name': "mov.b",   'op1': OP_r8u,     'op2': OP_abs8},
		{'opcode': 0x4000, 'mask': 0xff00, 'name': "bt",      'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4100, 'mask': 0xff00, 'name': "bf",      'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4200, 'mask': 0xff00, 'name': "bhi",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4300, 'mask': 0xff00, 'name': "bls",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4400, 'mask': 0xff00, 'name': "bcc",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4500, 'mask': 0xff00, 'name': "bcs",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4600, 'mask': 0xff00, 'name': "bne",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4700, 'mask': 0xff00, 'name': "beq",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4800, 'mask': 0xff00, 'name': "bvc",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4900, 'mask': 0xff00, 'name': "bvs",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4a00, 'mask': 0xff00, 'name': "bpl",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4b00, 'mask': 0xff00, 'name': "bmi",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4c00, 'mask': 0xff00, 'name': "bge",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4d00, 'mask': 0xff00, 'name': "blt",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4e00, 'mask': 0xff00, 'name': "bgt",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x4f00, 'mask': 0xff00, 'name': "ble",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x5000, 'mask': 0xff80, 'name': "bset",    'op1': OP_imm3,    'op2': OP_r8l},
		{'opcode': 0x5100, 'mask': 0xff00, 'name': "bset",    'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x5200, 'mask': 0xff80, 'name': "bclr",    'op1': OP_imm3,    'op2': OP_r8l},
		{'opcode': 0x5300, 'mask': 0xff00, 'name': "bclr",    'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x5400, 'mask': 0xff80, 'name': "bnot",    'op1': OP_imm3,    'op2': OP_r8l},
		{'opcode': 0x5500, 'mask': 0xff00, 'name': "bnot",    'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x5600, 'mask': 0xff80, 'name': "btst",    'op1': OP_imm3,    'op2': OP_r8l},
		{'opcode': 0x5700, 'mask': 0xff00, 'name': "btst",    'op1': OP_r8h,     'op2': OP_r8l},
		{'opcode': 0x5800, 'mask': 0xffff, 'name': "rts",     'op1': None,       'op2': None},
		{'opcode': 0x5980, 'mask': 0xffff, 'name': "rte",     'op1': None,       'op2': None},
		{'opcode': 0x5a00, 'mask': 0xff8f, 'name': "jmp",     'op1': OP_r16h,    'op2': None},
		{'opcode': 0x5a80, 'mask': 0xffff, 'name': "jmp",     'op1': OP_abs16c,  'op2': None},
		{'opcode': 0x5b00, 'mask': 0xff00, 'name': "jmp",     'op1': OP_abs8c,   'op2': None},
		{'opcode': 0x5c00, 'mask': 0xff8f, 'name': "jsr",     'op1': OP_r16h,    'op2': None},
		{'opcode': 0x5c80, 'mask': 0xffff, 'name': "jsr",     'op1': OP_abs16c,  'op2': None},
		{'opcode': 0x5e00, 'mask': 0xff00, 'name': "bsr",     'op1': OP_rel8,    'op2': None},
		{'opcode': 0x5f00, 'mask': 0xfff0, 'name': "mov.w",   'op1': OP_imm16,   'op2': OP_r16l},
		{'opcode': 0x6600, 'mask': 0xff00, 'name': "btst",    'op1': OP_imm3x,   'op2': OP_r16ih},
		{'opcode': 0x6800, 'mask': 0xff80, 'name': "mov.b",   'op1': OP_r16ih,   'op2': OP_r8l},
		{'opcode': 0x6900, 'mask': 0xff88, 'name': "mov.w",   'op1': OP_r16ih,   'op2': OP_r16l},
		{'opcode': 0x6a00, 'mask': 0xff80, 'name': "mov.b",   'op1': OP_r16ph,   'op2': OP_r8l},
		{'opcode': 0x6b70, 'mask': 0xfff8, 'name': "pop",     'op1': OP_r16l,    'op2': None},
		{'opcode': 0x6b00, 'mask': 0xff88, 'name': "mov.w",   'op1': OP_r16ph,   'op2': OP_r16l},
		{'opcode': 0x6c00, 'mask': 0xfff0, 'name': "mov.b",   'op1': OP_abs16,   'op2': OP_r8l},
		{'opcode': 0x6d00, 'mask': 0xfff0, 'name': "mov.w",   'op1': OP_abs16,   'op2': OP_r16l},
		{'opcode': 0x6e00, 'mask': 0xff80, 'name': "mov.b",   'op1': OP_r16d16h, 'op2': OP_r8l},
		{'opcode': 0x6f00, 'mask': 0xff80, 'name': "mov.w",   'op1': OP_r16d16h, 'op2': OP_r16l},
		{'opcode': 0x7000, 'mask': 0xff00, 'name': "bset",    'op1': OP_imm3x,   'op2': OP_abs8},
		{'opcode': 0x7200, 'mask': 0xff00, 'name': "bclr",    'op1': OP_imm3x,   'op2': OP_abs8},
		{'opcode': 0x7800, 'mask': 0xff80, 'name': "mov.b",   'op1': OP_r8l,     'op2': OP_r16ih},
		{'opcode': 0x7900, 'mask': 0xff88, 'name': "mov.w",   'op1': OP_r16l,    'op2': OP_r16ih},
		{'opcode': 0x7a00, 'mask': 0xff80, 'name': "mov.b",   'op1': OP_r8l,     'op2': OP_pr16h},
		{'opcode': 0x7b70, 'mask': 0xfff8, 'name': "push",    'op1': OP_r16l,    'op2': None},
		{'opcode': 0x7b00, 'mask': 0xff88, 'name': "mov.w",   'op1': OP_r16l,    'op2': OP_pr16h},
		{'opcode': 0x7c00, 'mask': 0xfff0, 'name': "mov.b",   'op1': OP_r8l,     'op2': OP_abs16},
		{'opcode': 0x7d00, 'mask': 0xfff0, 'name': "mov.w",   'op1': OP_r16l,    'op2': OP_abs16},
		{'opcode': 0x7e00, 'mask': 0xff80, 'name': "mov.b",   'op1': OP_r8l,     'op2': OP_r16d16h},
		{'opcode': 0x7f00, 'mask': 0xff80, 'name': "mov.w",   'op1': OP_r16l,    'op2': OP_r16d16h},
		{'opcode': 0x8000, 'mask': 0xf000, 'name': "add.b",   'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0x9000, 'mask': 0xf000, 'name': "addx.b",  'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0xa000, 'mask': 0xf000, 'name': "cmp.b",   'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0xb000, 'mask': 0xf000, 'name': "subx.b",  'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0xc000, 'mask': 0xf000, 'name': "or.b",    'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0xd000, 'mask': 0xf000, 'name': "xor.b",   'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0xe000, 'mask': 0xf000, 'name': "and.b",   'op1': OP_imm8,    'op2': OP_r8u},
		{'opcode': 0xf000, 'mask': 0xf000, 'name': "mov.b",   'op1': OP_imm8,    'op2': OP_r8u}
	]
	
	# operand types that indicate a 32-bit instruction
	ops_long = (OP_abs16, OP_abs16c, OP_imm3x, OP_imm16, OP_r16d16h)

	# Array of instructions
	instruc = [
		{'name': "nop",     'feature': 0},
		{'name': "sleep",   'feature': 0},
		{'name': "ldbank",  'feature': CF_USE1 | CF_CHG2},
		{'name': "stc",     'feature': CF_USE1 | CF_CHG2},
		{'name': "ldc",     'feature': CF_USE1 | CF_CHG2},
		{'name': "orc",     'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "xorc",    'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "andc",    'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "add.b",   'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "add.w",   'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "adds.l",  'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "inc.b",   'feature': CF_USE1 | CF_CHG1},
		{'name': "mov.b",   'feature': CF_USE1 | CF_CHG2},
		{'name': "mov.w",   'feature': CF_USE1 | CF_CHG2},
		{'name': "push",    'feature': CF_USE1},
		{'name': "pop",     'feature': CF_CHG1},
		{'name': "addx.b",  'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "mulxu.b", 'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "shll.b",  'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "shal.b",  'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "shlr.b",  'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "shar.b",  'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "rotxl.b", 'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "rotl.b",  'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "rotxr.b", 'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "rotr.b",  'feature': CF_USE1 | CF_CHG1 | CF_SHFT},
		{'name': "or.b",    'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "xor.b",   'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "and.b",   'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "not.b",   'feature': CF_USE1 | CF_CHG1},
		{'name': "neg.b",   'feature': CF_USE1 | CF_CHG1},
		{'name': "sub.b",   'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "sub.w",   'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "subs.l",  'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "dec.b",   'feature': CF_USE1 | CF_CHG1},
		{'name': "cmp.b",   'feature': CF_USE1 | CF_USE2},
		{'name': "cmp.w",   'feature': CF_USE1 | CF_USE2},
		{'name': "subx.b",  'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "divxu.b", 'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "bt",      'feature': CF_USE1 | CF_JUMP | CF_STOP},
		{'name': "bf",      'feature': CF_USE1 | CF_JUMP},
		{'name': "bhi",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bls",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bcc",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bcs",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bne",     'feature': CF_USE1 | CF_JUMP},
		{'name': "beq",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bvc",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bvs",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bpl",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bmi",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bge",     'feature': CF_USE1 | CF_JUMP},
		{'name': "blt",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bgt",     'feature': CF_USE1 | CF_JUMP},
		{'name': "ble",     'feature': CF_USE1 | CF_JUMP},
		{'name': "bset",    'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "bclr",    'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "bnot",    'feature': CF_USE1 | CF_USE2 | CF_CHG2},
		{'name': "btst",    'feature': CF_USE1 | CF_USE2},
		{'name': "jmp",     'feature': CF_USE1 | CF_JUMP | CF_STOP},
		{'name': "jsr",     'feature': CF_USE1 | CF_CALL},
		{'name': "bsr",     'feature': CF_USE1 | CF_CALL},
		{'name': "rte",     'feature': CF_STOP},
		{'name': "rts",     'feature': CF_STOP},
	]

	# icode of the first instruction
	instruc_start = 0

	# icode of the last instruction + 1
	instruc_end = len(instruc)
	
	# ----------------------------------------------------------------------
	# Assembler
	
	assembler = {
		# flag
		'flag' : AS_UNEQU | AS_COLON | ASH_HEXF1 | ASB_BINF4 | ASO_OCTF4,

		'flag2': 0,
		
		# Assembler name (displayed in menus)
		'name': "",

		# org directive
		'origin': ".org",

		# end directive
		'end': "end",

		# comment string (see also cmnt2)
		'cmnt': ";",

		# ASCII string delimiter
		'ascsep': "\"",

		# ASCII char constant delimiter
		'accsep': "'",

		# ASCII special chars (they can't appear in character and ascii constants)
		'esccodes': "\"'",

		#
		#      Data representation (db,dw,...):
		#
		# ASCII string directive
		'a_ascii': ".ascii",

		# byte directive
		'a_byte': ".byte",

		# word directive
		'a_word': ".word",

		# remove if not allowed
		'a_dword': ".long",

		# uninitialized data directive (should include '%s' for the size of data)
		'a_bss': ".space %s",

		# 'equ' Used if AS_UNEQU is set (optional)
		'a_equ': "=",
		
		# 'seg ' prefix (example: push seg seg001)
		'a_seg': "seg",
		
		# current IP (instruction pointer) symbol in assembler
		'a_curip': "$",

		# "public" name keyword. NULL-gen default, ""-do not generate
		'a_public': ".globl",

		# "weak"   name keyword. NULL-gen default, ""-do not generate
		'a_weak': "",

		# "extrn"  name keyword
		'a_extrn': ".extern",

		# "comm" (communal variable)
		'a_comdef': ".comm",

		# "align" keyword
		'a_align': ".align",

		# Left and right braces used in complex expressions
		'lbrace': "(",
		'rbrace': ")",

		# %  mod     assembler time operation
		'a_mod': "%",

		# &  bit and assembler time operation
		'a_band': "&",

		# |  bit or  assembler time operation
		'a_bor': "|",

		# ^  bit xor assembler time operation
		'a_xor': "^",

		# ~  bit not assembler time operation
		'a_bnot': "~",

		# << shift left assembler time operation
		'a_shl': "<<",

		# >> shift right assembler time operation
		'a_shr': ">>",

		# size of type (format string) (optional)
		'a_sizeof_fmt': "size %s",
	} # Assembler


	# ----------------------------------------------------------------------
	# The following callbacks are optional.
	# *** Please remove the callbacks that you don't plan to implement ***

	mem_regs = [
		(0xffc0, 2, "reg_SoundData1"),
		(0xffc2, 2, "reg_SoundData2"),
		(0xffc4, 2, "reg_SoundData3"),
		(0xffc6, 2, "reg_SoundCmd"),
		(0xffca, 2, "reg_SoundStatus"),
		
		(0xffd0, 2, "reg_KeyInput"),
		(0xffd2, 2, "reg_KeyStatus"),
		
		(0xffd8, 1, "reg_Timer0En"),
		(0xffd9, 1, "reg_Timer1En"),
		(0xffdc, 2, "reg_Timer0Rate"),
		(0xffdf, 1, "reg_Timer1Rate"),
		
		(0xffe0, 1, "reg_SerialRate"),
		(0xffe1, 1, "reg_SerialTx"),
		(0xffe2, 1, "reg_SerialStatus"),
		(0xffe3, 1, "reg_SerialRx"),

		(0xffe9, 1, "reg_ADCStatus"),
		(0xffea, 1, "reg_ADCData"),
		
		(0xfff0, 1, "reg_Port1DDR"),
		(0xfff1, 1, "reg_Port2DDR"),
		(0xfff2, 1, "reg_Port1"),
		(0xfff3, 1, "reg_Port2"),
		(0xfff5, 1, "reg_Port3")
	]
	
	mem_vector = [
		(0x0000, "Reset"),
		(0x0002, None),
		(0x0004, None),
		(0x0006, None),
		(0x0008, "IRQ_0"),
		(0x000a, "IRQ_1_KeyInput"),
		(0x000c, "IRQ_2_Timer0"),
		(0x000e, "IRQ_3_Timer1"),
		(0x0010, "IRQ_4_SerialError"),
		(0x0012, "IRQ_5_SerialRx"),
		(0x0014, "IRQ_6_SerialTx"),
		(0x0016, "IRQ_7"),
		(0x0018, "IRQ_8"),
		(0x001a, "IRQ_9"),
		(0x001c, "IRQ_10"),
	]

	def notify_newfile(self, filename):
		"""A new file is loaded (already)"""
		# TODO: generate other ROM segments
		
		add_segm(0, 0xfac0, 0xffc0,  "RAM", "DATA")
		add_segm(0, 0xffc0, 0x10000, "REG", "DATA")
		
		for addr, size, name in self.mem_regs:
			set_name(addr, name, SN_NOCHECK)
			if size == 1:
				create_byte(addr, 1)
			else:
				create_word(addr, 2)

		for addr, name in self.mem_vector:
			create_word(addr, 2)
			vector = get_word(addr)
			if vector > 0:
				if addr >= 0x0008:
					auto_make_proc(vector)
				else:
					auto_make_code(vector)
				
				op_plain_offset(addr, 0, 0)
				if not has_user_name(get_flags(vector)):
					set_name(vector, name, SN_NOCHECK)

	def notify_may_be_func(self, insn, state):
		if insn.itype == self.itype_push:
			return 100
		return 0

	def notify_is_ret_insn(self, insn, strict):
		feature = insn.get_canon_feature()
		if feature & (CF_STOP | CF_JUMP) == CF_STOP:
			return 1
		return 0
	
	def notify_init(self, idp_file):
		# init returns >=0 on success
		idainfo.set_be(True)
		return 0
	
	# ----------------------------------------------------------------------
	# helpers for notify_emu
	
	def notify_emu_operand(self, insn, op, read, write):
		flags = get_flags(insn.ea)
		create_data = False
	
		if op.type == o_mem:
			if read:
				add_dref(insn.ea, op.addr, dr_R)
			if write:
				add_dref(insn.ea, op.addr, dr_W)
			
			create_data = read or write
			
		elif op.type in (o_near, o_idpspec0):
			if op.type == o_idpspec0:
				addr = (op.addr + insn.ip + insn.size) & 0xffff
			else:
				addr = op.addr
			
			if insn.get_canon_feature() & CF_CALL:
				add_cref(insn.ea, addr, fl_CN)
			else:
				add_cref(insn.ea, addr, fl_JN)
		
		if op.type == o_imm:
			if op_adds_xrefs(flags, op.n) and insn.add_off_drefs(op, dr_O, OOFW_IMM | OOFS_IFSIGN) != BADADDR:
				create_data = True
					
		elif op.type == o_displ:
			if op_adds_xrefs(flags, op.n) and insn.add_off_drefs(op, dr_O, OOFW_IMM | OOFS_IFSIGN) != BADADDR:
				create_data = True
			# handle stack vars
			if op.reg == self.reg_sp and may_create_stkvars() and insn.create_stkvar(op, op.addr, 0):
				op_stkvar(insn.ea, op.n);
		
		if create_data:
			if insn.itype == self.itype_mov_w:
				create_word(op.addr, 2)
			else:
				create_byte(op.addr, 1)

	# ----------------------------------------------------------------------
	# The following callbacks are mandatory
	#

	def notify_emu(self, insn):
		feature = insn.get_canon_feature()
		
		self.notify_emu_operand(insn, insn[0], feature & CF_USE1, feature & CF_CHG1)
		self.notify_emu_operand(insn, insn[1], feature & CF_USE2, feature & CF_CHG2)
		
		if (feature & CF_STOP) == 0:
			add_cref(insn.ea, insn.ea + insn.size, fl_F)
		
		# stack pointer analysis
		if may_trace_sp():
			func = get_func(insn.ea)
			if func:
				sp_point = insn.ea + insn.size
				if insn.itype == self.itype_push:
					add_auto_stkpnt(func, sp_point, -2)
				elif insn.itype == self.itype_pop:
					add_auto_stkpnt(func, sp_point, 2)
				elif insn[0].type == o_imm and insn[1].type == o_reg and insn[1].reg == self.reg_sp:
					if insn.itype in (self.itype_add_b, self.itype_adds_l):
						add_auto_stkpnt(func, sp_point, insn[0].value)
					elif insn.itype in (self.itype_sub_b, self.itype_subs_l):
						add_auto_stkpnt(func, sp_point, -insn[0].value)
				
		return 1

	def notify_out_operand(self, ctx, op):
		if op.type == o_reg:
			ctx.out_register(self.reg_names[op.reg])
		elif op.type in (o_mem, o_near, o_idpspec0):
			if op.type == o_mem:
				ctx.out_symbol('@')
			
			if op.type == o_idpspec0:
				addr = (op.addr + ctx.insn.ip + ctx.insn.size) & 0xffff
			else:
				addr = op.addr
			
			r = ctx.out_name_expr(op, addr, BADADDR)
			if not r:
				ctx.out_tagon(COLOR_ERROR)
				ctx.out_btoa(addr, 16)
				ctx.out_tagoff(COLOR_ERROR)
				remember_problem(PR_NONAME, ctx.insn.ea)
		elif op.type == o_phrase:
			ctx.out_symbol('@')
			if op.specval < 0:
				ctx.out_symbol('-')
			ctx.out_register(self.reg_names[op.phrase])
			if op.specval > 0:
				ctx.out_symbol('+')
		elif op.type == o_displ:
			ctx.out_symbol('@')
			ctx.out_symbol('(')
			ctx.out_value(op, OOF_ADDR)
			ctx.out_symbol(',')
			ctx.out_register(self.reg_names[op.phrase])
			ctx.out_symbol(')')
		elif op.type == o_imm:
			ctx.out_symbol('#')
			ctx.out_value(op)
		else:
			return False
		
		return True

	def notify_out_insn(self, ctx):
		ctx.out_mnemonic()
		
		if ctx.insn[0].type != o_void:
			ctx.out_one_operand(0)
			if ctx.insn[1].type != o_void:
				ctx.out_symbol(',')
				ctx.out_char(' ')
				ctx.out_one_operand(1)
				
		ctx.set_gen_cmt()
		ctx.flush_outbuf()

	def notify_ana(self, insn):
		if insn.ea & 1:
			return 0
		
		data = insn.get_next_word()
		moredata = 0
		
		for o in self.opcodes:
			if data & o['mask'] != o['opcode']:
				continue
			
			insn.itype = getattr(self, op_itype(o['name']))
			
			if o['op1'] in self.ops_long or o['op2'] in self.ops_long:
				moredata = insn.get_next_word()
			
			if o['op1']:
				o['op1'](self, insn[0], data, moredata)
			if o['op2']:
				o['op2'](self, insn[1], data, moredata)
			
			return insn.size
		
		return 0

	def __init__(self):
		idaapi.processor_t.__init__(self)
		
		for num, i in enumerate(self.instruc):
			setattr(self, op_itype(i['name']), num)
		
		self.icode_return = self.itype_rts

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
	return gt913_processor_t()
