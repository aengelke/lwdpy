
import io
import os

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from capstone import *
from capstone.x86 import *

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
        return disas
    def get_symbol(self, symbolName):
        symtab = self.elf.get_section_by_name(".symtab")
        if not symtab or not isinstance(symtab, SymbolTableSection):
            print("No symtab found.")
            return

        print("Found symtab with %d symbols" % symtab.num_symbols())
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
        self.entry = self.recoverCFG(elf, addr)
        self.entry.name = self.name
        self.basicBlocks.sort(key=lambda bb: bb.address)
        self.isPLT = isPLT
        self.isLib = False
        # self.dump()

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
            else:
                print("unhandled jump operand " + instr.op_str)

        return bb
        # print(instr.mnemonic, instr.op_str)

class Model(object):
    def __init__(self, binaryFile, **kwargs):
        self.binaryFile = binaryFile
        self.elf = ELFReader(binaryFile)
        self.functions = []
        self.parse_plt(".plt", ".rela.plt", 0x10, 0x10)
        self.parse_plt(".plt.got", ".rela.dyn", 0, 0x8)

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
                    instr.operands[0].mem.base == X86_REG_RIP:
                    gotEntryAddr = instr.address + instr.size + instr.operands[0].mem.disp

                    relocation = None
                    for rela in relaDyn.iter_relocations():
                        if rela["r_offset"] == gotEntryAddr:
                            relocation = rela
                            break
                    if not relocation:
                        print("No relocation found for", hex(gotEntryAddr))
                        continue

                    symName = symtab.get_symbol(relocation["r_info_sym"]).name
                    print("Relocation entry @", hex(instr.address), "for", symName)
                    self.functions.append(Function(self.elf, instr.address, "plt@" + symName, isPLT=True))
                else:
                    print("Could not parse PLT entry @", hex(plt["sh_addr"] + i))

    def parse_function(self, tgt):
        address = self.elf.get_symbol(tgt)
        if not address:
            address = int(tgt, 16)
        if not address:
            print("Could not find address for", tgt)
            return
        for fn in self.functions:
            if fn.address == address: return fn

        symtab = self.elf.get_section(".symtab")
        name = None
        if symtab and isinstance(symtab, SymbolTableSection):
            for symbol in symtab.iter_symbols():
                if symbol["st_value"] == address:
                    name = symbol.name
                    break
        self.functions.append(Function(self.elf, address, name))
        return self.functions[-1]


