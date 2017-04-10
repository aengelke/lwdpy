
from collections import namedtuple
import io
import os
import struct

from capstone import _cs
from capstone.x86 import *
from gi.repository import GObject

from elfreader import ELFReader


class OperandKind(object):
    UNKNOWN = 0
    REG = 1
    IMM_SDEC = 2
    IMM_HEX = 4
    ADDR = 5
    ADDR_CSTR = 6
    IMM_CHAR = 7
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


MemOperand_ = MemOperand = namedtuple("MemOperand_", ["base", "index", "scale", "disp", "segment"])
Operand_ = Operand = namedtuple("Operand_", ["kind", "type", "size", "reg", "imm", "mem"])
Label_ = Label = namedtuple("Label_", ["name", "data"])
StoredModel_ = StoredModel = namedtuple("StoredModel_", ["binaryFile", "labels", "instructions"])


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

class Instruction(object):
    def __init__(self, cs):
        self.id = cs.id
        self.address = cs.address
        self.size = cs.size
        self.isBranch = X86_GRP_JUMP in cs.groups or X86_GRP_CALL in cs.groups
        self.operands = []
        for op in cs.operands:
            if op.type == X86_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    memOp = MemOperand(0, 0, 0, cs.address + cs.size + op.mem.disp, op.mem.segment)
                    kinds = OperandKind.ADDR
                else:
                    memOp = MemOperand(op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.mem.segment)
                    kinds = OperandKind.IMM_HEX if op.mem.base else OperandKind.ADDR
                self.operands.append(Operand(kinds, op.type, op.size, None, None, memOp))
            elif op.type == X86_OP_REG:
                self.operands.append(Operand([OperandKind.REG], op.type, op.size, op.reg, None, None))
            elif op.type == X86_OP_IMM:
                kind = OperandKind.IMM_HEX
                if self.isBranch: kind = OperandKind.ADDR
                self.operands.append(Operand(kind, op.type, op.size, None, op.imm, None))
        self.mnemonic = cs.mnemonic
        self.csStr = cs.op_str
        self.userComment = ""
        self.autoComment = ""
        self.jumpTable = None

    def getJumpTargets(self, includeFallthrough=False):
        targets = {}
        if self.id in CF_INSTR_COND or self.id == X86_INS_JMP:
            operand = self.operands[0]
            if operand.type == X86_OP_IMM:
                targets["jump"] = operand.imm
            else:
                print("unhandled jump operand " + self.csStr)

        if includeFallthrough and self.id not in CF_INSTR_UNCOND:
            targets["fallthrough"] = self.address + self.size

        return targets


Function = namedtuple("Function", ["address", "basicBlocks", "data"])
BasicBlock = namedtuple("BasicBlock", ["address", "instructions", "successors", "data"])

class Model(GObject.GObject):
    __gsignals__ = {
        "name-changed": (GObject.SIGNAL_RUN_FIRST, None, (int,)),
        "cfg-changed": (GObject.SIGNAL_RUN_FIRST, None, ()),
        "instruction-changed": (GObject.SIGNAL_RUN_FIRST, None, (int,)),
    }

    def __init__(self, binaryFile, **kwargs):
        super(Model, self).__init__()

        self.smodel = StoredModel(binaryFile, {}, {})
        self.elf = ELFReader(self.smodel.binaryFile)

        # This is an internal cache.
        self._functions = {}

        if self.elf.arch == "x64":
            self.parse_plt(".plt", ".rela.plt", 0x10, 0x10)
            self.parse_plt(".plt.got", ".rela.dyn", 0, 0x8)
        elif self.elf.arch == "x86":
            self.parse_plt(".plt", ".rel.plt", 0x10, 0x10)
            self.parse_plt(".plt.got", ".rel.dyn", 0, 0x8)

        for value, name, kind in self.elf.iter_symbols():
            if kind in ("function", "object",):
                self.get_label(value, name, kind)

    def _clear_function_cache(self):
        self._functions = {}
        self.emit("cfg-changed")

    def __getstate__(self):
        return self.smodel

    def __setstate__(self, state):
        self.smodel = state
        self.elf = ELFReader(self.smodel.binaryFile)
        self._functions = {}

    def get_functions(self):
        functions = []
        for labelAddr in self.smodel.labels:
            label = self.smodel.labels[labelAddr]
            if label.data["kind"] == "function":
                functions.append((labelAddr, label.name))
        return functions

    def parse_plt(self, pltName, relaName, skip, offset):
        plt = self.elf.get_section(pltName)
        relaDyn = self.elf.get_section(relaName)
        symtab = self.elf.get_section(".dynsym")
        if plt and relaDyn:
            addr = plt["sh_addr"]
            for i in range(skip, plt["sh_size"], offset): # ignore first 10 bytes
                instr = self.get_instruction(plt["sh_addr"] + i)
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

                    symName = symtab.get_symbol(relocation["r_info_sym"]).name + "@plt"
                    data = {"plt": True}
                    if symName in ("__stack_chk_fail@plt", "__libc_start_main@plt", "exit@plt", "_exit@plt"):
                        data["noreturn"] = True
                    self.get_label(instr.address, symName, "function", data)
                else:
                    print("Could not parse PLT entry @", hex(plt["sh_addr"] + i))

    def rename(self, address, name):
        label = self.get_label(address, name, "unknown")
        if label.name != name:
            self.smodel.labels[address] = Label(name, label.data)
            self.emit("name-changed", address)

    def get_name(self, address):
        if address in self.smodel.labels:
            return self.smodel.labels[address].name
        return hex(address)

    def set_attribute(self, address, attribute, value=True):
        if address not in self.smodel.labels:
            return
        data = self.smodel.labels[address].data
        if not value:
            data.pop(attribute, None)
        else:
            data[attribute] = value

        if attribute == "noreturn":
            self._clear_function_cache()

    def set_operand_kind(self, instrAddress, operandIndex, kind):
        instr = self.get_instruction(instrAddress)
        operand = instr.operands[operandIndex]
        instr.operands[operandIndex] = Operand(kind, operand.type, operand.size, operand.reg, operand.imm, operand.mem)
        self.emit("instruction-changed", instrAddress)

    def get_function(self, address):
        if isinstance(address, str):
            addrString = address
            address = self.elf.get_symbol(addrString)
            if not address:
                address = int(addrString, 16)
            if not address:
                print("Could not find address for", addrString)
                return

        if address in self._functions:
            return self._functions[address]

        label = self.get_label(address, "fn_" + hex(address)[2:], "function")
        name, data = label.name, label.data
        if data["kind"] != "function":
            print("Label at", hex(address), "with name", name, label, "is not a function")
            return

        addrQueue = [address]
        addrMap = {} # Mapping from address to basic block
        while len(addrQueue) > 0:
            currentAddr = addrQueue.pop(0)
            if currentAddr in addrMap:
                bb = addrMap[currentAddr]
                if bb.address == currentAddr:
                    continue

                splitIdx = [i for i, instr in enumerate(bb.instructions) if instr.address == currentAddr]
                if len(splitIdx) != 1:
                    raise Exception("instruction exists twice, len(splitIdx) != 1")
                splitIdx = splitIdx[0]

                bb1 = BasicBlock(bb.address, bb.instructions[:splitIdx], {"fallthrough": currentAddr}, None)
                bb2 = BasicBlock(currentAddr, bb.instructions[splitIdx:], bb.successors, None)
                for i, instr in enumerate(bb.instructions):
                    addrMap[instr.address] = bb1 if i < splitIdx else bb2
                continue

            instructions = []
            startAddr = currentAddr
            successors = {"fallthrough": currentAddr}
            while len(successors) == 1 and "fallthrough" in successors:
                if currentAddr in addrMap:
                    successors = {"fallthrough": currentAddr}
                    break
                instr = self.get_instruction(currentAddr)
                currentAddr += instr.size
                instructions.append(instr)
                if instr.id == X86_INS_CALL:
                    operand = instr.operands[0]
                    if operand.type == X86_OP_IMM:
                        callee = self.get_label(operand.imm, "fn_" + hex(address)[2:], "function")
                        if "noreturn" in callee.data:
                            successors = {}
                            break
                successors = instr.getJumpTargets(True)

            bb = BasicBlock(startAddr, instructions, successors, None)
            for instr in instructions:
                addrMap[instr.address] = bb

            for nextAddr in successors.values():
                if nextAddr not in addrMap or addrMap[nextAddr].address != nextAddr:
                    addrQueue.append(nextAddr)

        basicBlocks = list({bb.address: bb for bb in addrMap.values()}.values())
        basicBlocks.sort(key=lambda bb: bb.address)
        for index, bb in enumerate(basicBlocks):
            label = self.get_label(bb.address, "bb_" + hex(bb.address)[2:], "basicBlock")
            basicBlocks[index] = BasicBlock(bb.address, bb.instructions, bb.successors, label.data)

        function = Function(address, basicBlocks, data)
        self._functions[address] = function
        return function

    def get_instruction(self, address):
        if address in self.smodel.instructions:
            return self.smodel.instructions[address]

        self.elf.vseek(address)
        instr = self.elf.vreadCSInstr()
        instr = Instruction(instr)

        self.smodel.instructions[address] = instr
        return instr

    def get_label(self, address, name, kind, data=None):
        if address not in self.smodel.labels:
            if not data:
                data = {"kind": kind}
            else:
                data["kind"] = kind
            self.smodel.labels[address] = Label(name, data)
            return self.smodel.labels[address]
        else:
            label = self.smodel.labels[address]
            return label

    def reg_name(self, reg):
        return _cs.cs_reg_name(self.elf.cs.csh, reg).decode()

    def regionize_immediate(self, operand, imm, regionKind):
        if OperandKind.isAddress(operand.kind):
            return Region(self.get_name(imm), regionKind, meta=operand)
        elif operand.kind == OperandKind.IMM_HEX:
            return Region(hex(imm), regionKind, meta=operand)
        elif operand.kind == OperandKind.IMM_SDEC:
            return Region(str(imm), regionKind, meta=operand)
        elif operand.kind == OperandKind.IMM_CHAR:
            return Region(repr(struct.pack("<Q", imm)[:operand.size])[1:], regionKind, meta=operand)
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

    def regionize_instruction(self, instr):
        regions = []
        for i, op in enumerate(instr.operands):
            if i != 0: regions.append(Region(", "))
            newRegions, immediate = self.regionize_operand(op, instr.isBranch)
            regions += newRegions
            if op.kind == OperandKind.ADDR_CSTR:
                try:
                    self.elf.vseek(immediate)
                    data = self.elf.vread(20)
                    if data.find(b"\0") >= 0:
                        data = repr(data[:data.find(b"\x00")].decode())
                    else:
                        data = repr(data.decode()[:-3]) + "..."
                    instr.autoComment = data
                except Exception:
                    print(instr, op)
                    instr.autoComment = "addr not readable"
            else: instr.autoComment = ""
        return regions
