
from collections import namedtuple
import io
import os

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from capstone import *
from capstone import _cs
from capstone.x86 import *

registerEqualtity = (
    (X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AL, X86_REG_AH),
    (X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CL, X86_REG_CH),
    (X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DL, X86_REG_DH),
    (X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BL, X86_REG_BH),
    (X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL),
    (X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL),
    (X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL),
    (X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL),
    (X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_R8B),
    (X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_R9B),
    (X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B),
    (X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B),
    (X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B),
    (X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B),
    (X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B),
    (X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B),
)
def registerEqual(reg1, reg2):
    if reg1 == reg2: return True
    return any([True for eq in registerEqualtity if reg1 in eq and reg2 in eq])


class OperandKind(object):
    UNKNOWN = 0
    REG = 1
    IMM_SDEC = 2
    IMM_UDEC = 3
    IMM_HEX = 4
    ADDR = 5
    ADDR_CSTR = 6
    @staticmethod
    def isAddress(kind):
        return kind in (OperandKind.ADDR, OperandKind.ADDR_CSTR)

class Region(namedtuple("Region", "text,kind,meta")):
    KIND_NONE = 0
    KIND_REG = 1
    KIND_DATA = 2
    KIND_CODE_ADDR = 3
    KIND_CODE_INDIRECT = 4
    def __new__(self, text, kind=KIND_NONE, meta=None):
        return super(Region, self).__new__(self, text, kind, meta)
    def isImmediate(self):
        return self.kind == Region.KIND_DATA
    def isStatic(self):
        return self.kind == Region.KIND_NONE


MemOperand = namedtuple("Operand", ["base", "index", "scale", "disp", "segment"])
Operand = namedtuple("Operand", ["kind", "type", "size", "reg", "imm", "mem"])

class Instruction(object):
    def __init__(self, cs):
        # self.cs = cs
        self.id = cs.id
        self.address = cs.address
        self.size = cs.size
        self.isBranch = X86_GRP_JUMP in cs.groups or X86_GRP_CALL in cs.groups
        self.operands = []
        for op in cs.operands:
            if op.type == X86_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    memOp = MemOperand(0, 0, 0, cs.address + cs.size + op.mem.disp, op.mem.segment)
                    kinds = [OperandKind.ADDR]
                else:
                    memOp = MemOperand(op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.mem.segment)
                    kinds = [OperandKind.IMM_HEX if op.mem.base else OperandKind.ADDR]
                self.operands.append(Operand(kinds, op.type, op.size, None, None, memOp))
            elif op.type == X86_OP_REG:
                self.operands.append(Operand([OperandKind.REG], op.type, op.size, op.reg, None, None))
            elif op.type == X86_OP_IMM:
                kind = OperandKind.IMM_HEX
                if self.isBranch: kind = OperandKind.ADDR
                self.operands.append(Operand([kind], op.type, op.size, None, op.imm, None))
        self.mnemonic = cs.mnemonic
        self.op_str = []
        self.csStr = cs.op_str
        self.userComment = ""
        self.autoComment = ""

class ELFReader(object):
    def __init__(self, binary):
        self.fd = io.BytesIO(binary)
        self.elf = ELFFile(self.fd)
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.vaddr = 0
    def vseek(self, addr):
        fileoff = list(self.elf.address_offsets(addr))[0]
        self.fd.seek(fileoff, os.SEEK_SET)
        self.vaddr = addr
    def vread(self, length):
        data = self.fd.read(length)
        self.vaddr += len(data)
        return data
    def vreadInstr(self):
        stream = self.fd.read(32)
        try:
            disas = list(self.cs.disasm(stream, self.vaddr, 1))[0]
        except Exception:
            print("Cannot decode:", stream, hex(self.vaddr))
        self.vseek(self.vaddr + disas.size)
        return Instruction(disas)
    def get_symbol(self, symbolName):
        symtab = self.elf.get_section_by_name(".symtab")
        if not symtab or not isinstance(symtab, SymbolTableSection):
            return
        for i in range(symtab.num_symbols()):
            symbol = symtab.get_symbol(i)
            if symbol.name != symbolName: continue
            return symbol["st_value"]
    def get_section(self, name):
        # for i in range(self.elf.num_sections()): print(self.elf.get_section(i).name)
        return self.elf.get_section_by_name(name)

class BasicBlock(object):
    def __init__(self, addr):
        self.address = addr
        self.instructions = []
        self.branchTrue = None
        self.branchFalse = None
        self.view = None
        self.name = "bb_" + hex(addr)[2:]

    def dump(self):
        print("Basic Block at", hex(self.address))
        if self.branchFalse: print("  B/default:", hex(self.branchFalse.address))
        if self.branchTrue: print("  B/condtaken:", hex(self.branchTrue.address))
        for instr in self.instructions:
            print("  {:016x}:  {} \t{}".format(instr.address, instr.mnemonic, instr.op_str))

class Function(object):
    CF_INSTR_COND = (
        X86_INS_JAE,
        X86_INS_JA,
        X86_INS_JBE,
        X86_INS_JB,
        X86_INS_JCXZ,
        X86_INS_JECXZ,
        X86_INS_JE,
        X86_INS_JGE,
        X86_INS_JG,
        X86_INS_JLE,
        X86_INS_JL,
        X86_INS_JNE,
        X86_INS_JNO,
        X86_INS_JNP,
        X86_INS_JNS,
        X86_INS_JO,
        X86_INS_JP,
        X86_INS_JRCXZ,
        X86_INS_JS,
    )
    CF_INSTR_UNCOND = (
        X86_INS_JMP,
        X86_INS_RET,
        X86_INS_IRET,
        X86_INS_INT,
        X86_INS_INT1,
        X86_INS_INT3,
        X86_INS_INTO,
        X86_INS_UD2,
    )
    CF_INSTR = CF_INSTR_COND + CF_INSTR_UNCOND
    def __init__(self, elf, addr, name=None, isPLT=False):
        self.basicBlocks = []
        self.addrMap = {}
        self.address = addr
        self.name = name if name else "fn_" + hex(addr)[2:]
        self.isPLT = isPLT
        # self.args = []

        self.entry = self.recoverCFG(elf, addr)
        self.entry.name = self.name
        self.basicBlocks.sort(key=lambda bb: bb.address)

    def dump(self):
        for bb in self.basicBlocks:
            bb.dump()

    def recoverCFG(self, elf, addr):
        # print("Decoding", hex(addr))
        if addr in self.addrMap:
            bb = self.addrMap[addr]
            if bb.address == addr: return bb
            splitIdx = [i for i, instr in enumerate(bb.instructions) if instr.address == addr]
            if len(splitIdx) != 1:
                raise Exception("jump in middle of instruction, len(splitIdx) != 1")
            splitIdx = splitIdx[0]

            newbb = BasicBlock(addr)
            newbb.branchFalse = bb.branchFalse
            newbb.branchTrue = bb.branchTrue
            newbb.instructions = bb.instructions[splitIdx:]
            self.basicBlocks.append(newbb)

            bb.instructions = bb.instructions[:splitIdx]
            bb.branchTrue = None
            bb.branchFalse = newbb
            for instr in newbb.instructions:
                self.addrMap[instr.address] = newbb

            return newbb

        elf.vseek(addr)
        bb = BasicBlock(addr)
        self.basicBlocks.append(bb)

        while True:
            if elf.vaddr in self.addrMap:
                bb.branchFalse = self.addrMap[elf.vaddr]
                break

            instr = elf.vreadInstr()
            bb.instructions.append(instr)
            self.addrMap[instr.address] = bb

            if instr.id in Function.CF_INSTR:
                break

        lastInstr = bb.instructions[-1]
        if lastInstr.id in Function.CF_INSTR_COND:
            bfalse = self.recoverCFG(elf, lastInstr.address + lastInstr.size)
            self.addrMap[lastInstr.address].branchFalse = bfalse
        if lastInstr.id in Function.CF_INSTR_COND or lastInstr.id == X86_INS_JMP:
            operand = lastInstr.operands[0]
            if operand.type == X86_OP_IMM:
                btrue = self.recoverCFG(elf, operand.imm)
                if lastInstr.id == X86_INS_JMP:
                    self.addrMap[lastInstr.address].branchFalse = btrue
                else:
                    self.addrMap[lastInstr.address].branchTrue = btrue
            elif not self.isPLT:
                print("unhandled jump operand " + instr.csStr)

        return bb

class Model(object):
    def __init__(self, binaryFile, **kwargs):
        self.binaryFile = binaryFile
        self.elf = ELFReader(binaryFile)
        self.functions = []
        self.funcMap = {}
        self.parse_plt(".plt", ".rela.plt", 0x10, 0x10)
        self.parse_plt(".plt.got", ".rela.dyn", 0, 0x8)
        self.update_instructions()

    def parse_plt(self, pltName, relaName, skip, offset):
        plt = self.elf.get_section(pltName)
        relaDyn = self.elf.get_section(relaName)
        symtab = self.elf.get_section(".dynsym")
        if plt and relaDyn and isinstance(relaDyn, RelocationSection):
            addr = plt["sh_addr"]
            for i in range(skip, plt["sh_size"], offset): # ignore first 10 bytes
                self.elf.vseek(plt["sh_addr"] + i)
                instr = self.elf.vreadInstr()
                if instr.id == X86_INS_JMP and instr.operands[0].type == X86_OP_MEM and \
                    not instr.operands[0].mem.base and not instr.operands[0].mem.index:
                    gotEntryAddr = instr.operands[0].mem.disp

                    relocation = None
                    for rela in relaDyn.iter_relocations():
                        if rela["r_offset"] == gotEntryAddr:
                            relocation = rela
                            break
                    if not relocation:
                        print("No relocation found for", hex(gotEntryAddr))
                        continue

                    symName = symtab.get_symbol(relocation["r_info_sym"]).name
                    func = Function(self.elf, instr.address, symName + "@plt", isPLT=True)
                    self.functions.append(func)
                    self.funcMap[instr.address] = func
                else:
                    print("Could not parse PLT entry @", hex(plt["sh_addr"] + i))

    def parse_function(self, tgt):
        if isinstance(tgt, str):
            address = self.elf.get_symbol(tgt)
            if not address:
                address = int(tgt, 16)
            if not address:
                print("Could not find address for", tgt)
                return
        else: address = tgt

        for fn in self.functions:
            if fn.address == address: return fn

        symtab = self.elf.get_section(".symtab")
        name = None
        if symtab and isinstance(symtab, SymbolTableSection):
            for symbol in symtab.iter_symbols():
                if symbol["st_value"] == address:
                    name = symbol.name
                    break
        func = Function(self.elf, address, name)
        self.functions.append(func)
        self.funcMap[address] = func
        self.update_instructions()
        return self.functions[-1]

    def update_instructions(self):
        for func in self.functions:
            for bb in func.basicBlocks:
                for instr in bb.instructions:
                    self.update_instruction(instr)

    def reg_name(self, reg):
        return _cs.cs_reg_name(self.elf.cs.csh, reg).decode()

    def regionize_address(self, operand, address, regionKind):
        if address in self.funcMap:
            return Region(self.funcMap[address].name, regionKind, operand)
        for func in self.functions:
            if address in func.addrMap:
                bb = func.addrMap[address]
                if bb.address == address:
                    return Region(bb.name, regionKind, operand)
        return Region(hex(address), regionKind, operand)

    def regionize_immediate(self, operand, imm, regionKind):
        if OperandKind.isAddress(operand.kind[0]):
            return self.regionize_address(operand, imm, regionKind)
        elif operand.kind[0] == OperandKind.IMM_HEX:
            return Region(hex(imm), regionKind, meta=operand)
        elif operand.kind[0] == OperandKind.IMM_SDEC:
            return Region(str(imm), regionKind, meta=operand)
        else: raise Exception("not reached")

    def regionize_operand(self, op, isBranch=False):
        regions = []
        immediate = None
        if op.type == X86_OP_REG:
            regionKind = Region.KIND_CODE_INDIRECT if isBranch else Region.KIND_REG
            meta = op if isBranch else op.reg
            regions.append(Region(self.reg_name(op.reg), regionKind, meta))
        elif op.type == X86_OP_IMM:
            regionKind = Region.KIND_CODE_ADDR if isBranch else Region.KIND_DATA
            regions.append(self.regionize_immediate(op, op.imm, regionKind))
            immediate = op.imm
        elif op.type == X86_OP_MEM:
            sizeName = { 1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "xmmword" }
            if op.size in sizeName: sizeName = sizeName[op.size]
            else: sizeName = "SZ" + op.size
            regions.append(Region(sizeName + " "))
            if op.mem.segment:
                regions.append(Region(self.reg_name(op.mem.segment), kind=Region.KIND_REG, meta=op.mem.segment))
                regions.append(Region(":"))
            regions.append(Region("["))
            hasComp = False
            if op.mem.base:
                regions.append(Region(self.reg_name(op.mem.base), kind=Region.KIND_REG, meta=op.mem.base))
                hasComp = True
            if op.mem.index:
                if hasComp: regions.append(Region(" + "))
                if op.mem.scale != 1: regions.append(Region(str(op.mem.scale) + "*"))
                regions.append(Region(self.reg_name(op.mem.index), kind=Region.KIND_REG, meta=op.mem.index))
                hasComp = True
            if op.mem.disp or not hasComp:
                if hasComp:
                    regions.append(Region(" + " if op.mem.disp >= 0 else " - "))
                    regions.append(self.regionize_immediate(op, abs(op.mem.disp), Region.KIND_DATA))
                    if op.mem.disp > 0: immediate = op.mem.disp
                else:
                    regions.append(self.regionize_immediate(op, op.mem.disp, Region.KIND_DATA))
                    immediate = op.mem.disp
            regions.append(Region("]"))
        else: regions.append(Region("UNKNOWN"))
        return regions, immediate

    def update_instruction(self, instr):
        regions = []
        for i, op in enumerate(instr.operands):
            if i != 0: regions.append(Region(", "))
            newRegions, immediate = self.regionize_operand(op, instr.isBranch)
            regions += newRegions
            if op.kind[0] == OperandKind.ADDR_CSTR:
                try:
                    self.elf.vseek(immediate)
                    data = self.elf.vread(20)
                    if data.find(b"\0") >= 0:
                        data = repr(data[:data.find(b"\x00")].decode())
                    else:
                        data = repr(data.decode()) + "..."
                    instr.autoComment = data
                except Exception:
                    instr.autoComment = "addr not readable"
            else: instr.autoComment = ""
        instr.op_str = regions
