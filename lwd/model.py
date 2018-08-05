
from collections import namedtuple
from enum import Enum
import io
import os
import struct

from capstone import _cs
from capstone.x86 import *
from gi.repository import GObject

from lwd import profile
from lwd.elfreader import ELFReader

class OperandKind(Enum):
    UNKNOWN = 0
    REG = 1
    IMM_SDEC = 2
    IMM_HEX = 4
    ADDR = 5
    ADDR_CSTR = 6
    IMM_CHAR = 7
    STACKFRAME = 8

    @property
    def isaddress(self):
        return self in (OperandKind.ADDR, OperandKind.ADDR_CSTR)

class OperandType(Enum):
    REG = 0
    IMM = 1
    MEM = 2

class RegionKind(Enum):
    STATIC = 0
    REG = 1
    IMM = 2
    CODE_IMM = 3
    CODE_REG = 4

class Region(namedtuple("Region", "text,kind,meta")):
    __slots__ = ()

    @classmethod
    def static(cls, text):
        return cls(text, RegionKind.STATIC, None)
    @classmethod
    def register(cls, text, register, branch=False):
        kind = RegionKind.CODE_REG if branch else RegionKind.REG
        return cls(text, kind, register)
    @classmethod
    def immediate(cls, text, operand, branch=False):
        kind = RegionKind.CODE_IMM if branch else RegionKind.IMM
        return cls(text, kind, operand)

LabelKind = Enum("LabelKind", "UNKNOWN OBJECT BASIC_BLOCK FUNCTION")

MemOperand = namedtuple("MemOperand", ["base", "index", "scale", "disp", "segment"])

class Operand(namedtuple("Operand", ["kind", "type", "size", "reg", "imm", "mem"])):
    """
    If type is MEM, the operand kind denotes the kind of the immediate only.
    """

    @classmethod
    def register(cls, size, reg):
        return cls(OperandKind.REG, OperandType.REG, size, reg, None, None)
    @classmethod
    def immediate(cls, size, imm):
        return cls(OperandKind.IMM_HEX, OperandType.IMM, size, None, imm, None)
    @classmethod
    def memory(cls, size, base=0, index=0, scale=1, disp=0, segment=0):
        memOp = MemOperand(base, index, scale, disp, segment)
        return cls(OperandKind.IMM_HEX, OperandType.MEM, size, None, None, memOp)

    @property
    def is_stack_relative(self):
        if self.mem is None:
            return False
        return self.mem.base in (X86_REG_RSP, X86_REG_RBP) and not self.mem.index

Label = namedtuple("Label", ["kind", "name", "data"])
StoredModel = namedtuple("StoredModel", ["binaryFile", "labels", "instructions"])

class FunctionData(GObject.GObject):
    _noreturn = False
    _plt = False
    _stackframe = None

    def __getstate__(self):
        # TODO: Iterate over properties
        return {"noreturn": self.noreturn, "plt": self.plt, "stackframe": self.stackframe}
    def __setstate__(self, state):
        super(FunctionData, self).__init__(**state)

    @GObject.Property(type=bool, default=False)
    def noreturn(self):
        return self._noreturn
    @noreturn.setter
    def noreturn(self, value):
        self._noreturn = value

    @GObject.Property()
    def stackframe(self):
        return self._stackframe if self._stackframe is not None else {}
    def set_stackframe_name(self, offset, name):
        if self._stackframe is None:
            self._stackframe = {}
        self._stackframe[abs(offset)] = name
        self.set_property("stackframe", self._stackframe) # Trigger update
    def stackframe_name(self, offset):
        stackframe = self.stackframe
        if offset not in stackframe:
            stackframe[abs(offset)] = "var_" + hex(offset)
        return stackframe[abs(offset)]

    @GObject.Property(type=bool, default=False)
    def plt(self):
        return self._plt

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

PLT_NORETURN = (
    "__stack_chk_fail@plt",
    "__libc_start_main@plt",
    "exit@plt",
    "_exit@plt",
)

class Instruction(object):
    def __init__(self, cs):
        self.id = cs.id
        self.address = cs.address
        self.size = cs.size
        self.isBranch = X86_GRP_JUMP in cs.groups or X86_GRP_CALL in cs.groups
        self.operands = []
        for op in cs.operands:
            operand = None
            if op.type == X86_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    address = cs.address + cs.size + op.mem.disp
                    operand = Operand.memory(op.size, disp=address, segment=op.mem.segment)
                else:
                    operand = Operand.memory(op.size, op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.mem.segment)
                # print(op.mem.base, op.mem.index, op.mem.scale, X86_REG_RSP, X86_REG_RBP, op.mem.base in (X86_REG_RSP, X86_REG_RBP) and not op.mem.index)
                #     memOp = MemOperand(0, 0, 0, cs.address + cs.size + op.mem.disp, op.mem.segment)
                #     kinds = OperandKind.ADDR
                # else:
                #     memOp = MemOperand(op.mem.base, op.mem.index, op.mem.scale, op.mem.disp, op.mem.segment)
                #     kinds = OperandKind.IMM_HEX if op.mem.base else OperandKind.ADDR
                # operand = Operand(kinds, op.type, op.size, None, None, memOp)
                if operand.is_stack_relative:
                    operand = operand._replace(kind=OperandKind.STACKFRAME)
                elif not operand.mem.base or op.mem.base == X86_REG_RIP:
                    operand = operand._replace(kind=OperandKind.ADDR)
            elif op.type == X86_OP_REG:
                operand = Operand.register(op.size, op.reg)
            elif op.type == X86_OP_IMM:
                operand = Operand.immediate(op.size, op.imm)
                if self.isBranch:
                    operand = operand._replace(kind=OperandKind.ADDR)

            self.operands.append(operand)
        self.mnemonic = cs.mnemonic
        self.csStr = cs.op_str
        self.userComment = ""
        self.autoComment = ""
        self.jumpTable = None

    def getJumpTargets(self, includeFallthrough=False):
        targets = {}
        if self.id in CF_INSTR_COND or self.id == X86_INS_JMP:
            operand = self.operands[0]
            if operand.type == OperandType.IMM:
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
        "name-changed": (GObject.SignalFlags.RUN_FIRST, None, (int,)),
        "cfg-changed": (GObject.SignalFlags.RUN_FIRST, None, ()),
        "instruction-changed": (GObject.SignalFlags.RUN_FIRST, None, (int,)),
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
            if kind == "function":
                self.get_label(value, name, LabelKind.FUNCTION, FunctionData())
            elif kind == "object":
                self.get_label(value, name, LabelKind.OBJECT)

    def _clear_function_cache(self):
        self._functions = {}
        self.emit("cfg-changed")

    def __getstate__(self):
        return self.smodel

    def __setstate__(self, state):
        super(Model, self).__init__()
        self.smodel = state
        self.elf = ELFReader(self.smodel.binaryFile)
        self._functions = {}
        for labelAddr in self.smodel.labels:
            label = self.smodel.labels[labelAddr]
            if label.kind == LabelKind.FUNCTION:
                if label.data is None or not isinstance(label.data, FunctionData):
                    raise Exception("function has wrong data type")
                label.data.connect("notify", self._on_function_data_update)

    def get_functions(self):
        functions = []
        for labelAddr in self.smodel.labels:
            label = self.smodel.labels[labelAddr]
            if label.kind == LabelKind.FUNCTION:
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
                if instr.id == X86_INS_JMP and instr.operands[0].type == OperandType.MEM and \
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
                    data = FunctionData(plt=True, noreturn=symName in PLT_NORETURN)
                    self.get_label(instr.address, symName, LabelKind.FUNCTION, data)
                else:
                    print("Could not parse PLT entry @", hex(plt["sh_addr"] + i))

    def rename(self, address, name):
        label = self.get_label(address, name, LabelKind.UNKNOWN)
        if label.name != name:
            self.smodel.labels[address] = label._replace(name=name)
        self.emit("name-changed", address)

    def get_name(self, address):
        if address in self.smodel.labels:
            return self.smodel.labels[address].name
        return hex(address)

    def set_operand_kind(self, instrAddress, operandIndex, kind):
        instr = self.get_instruction(instrAddress)
        operand = instr.operands[operandIndex]
        instr.operands[operandIndex] = operand._replace(kind=kind)
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

        label = self.get_label(address, "fn_" + hex(address)[2:], LabelKind.FUNCTION)
        name, data = label.name, label.data
        if label.kind != LabelKind.FUNCTION:
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
                    if operand.type == OperandType.IMM:
                        callee = self.get_label(operand.imm, "fn_" + hex(address)[2:], LabelKind.FUNCTION)
                        if callee.data.noreturn:
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
            label = self.get_label(bb.address, "bb_" + hex(bb.address)[2:], LabelKind.BASIC_BLOCK)
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

    def _on_function_data_update(self, functionData, param):
        if param.name == "noreturn":
            self._clear_function_cache()
        elif param.name == "stackframe":
            self.emit("instruction-changed", -1)
        else:
            print("function data", param.name, "changed; ignoring")

    def get_label(self, address, name, kind, data=None):
        if address not in self.smodel.labels:
            if kind == LabelKind.FUNCTION:
                if data is None:
                    data = FunctionData()
                if not isinstance(data, FunctionData):
                    raise Exception("function has wrong data type")
                data.connect("notify", self._on_function_data_update)
            label = self.smodel.labels[address] = Label(kind, name, data)
        else:
            label = self.smodel.labels[address]
        if label.kind == LabelKind.FUNCTION and (not label.data or not isinstance(label.data, FunctionData)):
            raise Exception("function has wrong data type")
        return label

    def reg_name(self, reg):
        return _cs.cs_reg_name(self.elf.cs.csh, reg).decode()

    def regionize_immediate(self, function, immediate, operand, branch=False):
        text = "?" + hex(immediate)
        if operand.kind.isaddress:
            text = self.get_name(immediate)
        elif operand.kind == OperandKind.IMM_HEX:
            text = hex(immediate)
        elif operand.kind == OperandKind.IMM_SDEC:
            text = str(immediate)
        elif operand.kind == OperandKind.IMM_CHAR:
            text = repr(struct.pack("<Q", immediate)[:operand.size])[1:]
        elif operand.kind == OperandKind.STACKFRAME:
            text = function.data.stackframe_name(immediate)
        return Region.immediate(text, operand, branch)

    def regionize_operand(self, function, op, branch=False):
        regions = []
        immediate = None

        if op.type == OperandType.REG:
            regions.append(Region.register(self.reg_name(op.reg), op.reg, branch))

        elif op.type == OperandType.IMM:
            regions.append(self.regionize_immediate(function, op.imm, op, branch))
            immediate = op.imm

        elif op.type == OperandType.MEM:
            sizeName = { 1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "xmmword" }
            sizeName = sizeName.get(op.size, "?sz%d" % op.size)
            regions.append(Region.static(sizeName + " "))

            if op.mem.segment:
                regions.append(Region.register(self.reg_name(op.mem.segment), op.mem.segment))
                regions.append(Region.static(":"))

            regions.append(Region.static("["))
            hasComp = False
            if op.mem.base:
                regions.append(Region.register(self.reg_name(op.mem.base), op.mem.base))
                hasComp = True
            if op.mem.index:
                if hasComp:
                    regions.append(Region.static(" + "))
                if op.mem.scale != 1:
                    regions.append(Region.static(str(op.mem.scale) + "*"))
                regions.append(Region.register(self.reg_name(op.mem.index), op.mem.index))
                hasComp = True
            if op.mem.disp or not hasComp:
                if hasComp:
                    regions.append(Region.static(" + " if op.mem.disp >= 0 else " - "))
                    regions.append(self.regionize_immediate(function, abs(op.mem.disp), op))
                    if op.mem.disp > 0: immediate = op.mem.disp
                else:
                    regions.append(self.regionize_immediate(function, op.mem.disp, op))
                    immediate = op.mem.disp
            regions.append(Region.static("]"))

        else:
            regions.append(Region.static("?"))
        return regions, immediate

    def regionize_instruction(self, function, instr):
        regions = []
        for i, op in enumerate(instr.operands):
            if i != 0: regions.append(Region.static(", "))
            newRegions, immediate = self.regionize_operand(function, op, instr.isBranch)
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
