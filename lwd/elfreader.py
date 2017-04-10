
import io
import os

from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

class ELFReader(object):
    def __init__(self, binary):
        self.fd = io.BytesIO(binary)
        self.elf = ELFFile(self.fd)
        self.arch = self.elf.get_machine_arch()
        if self.arch == "x64":
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        elif self.arch == "x86":
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            raise Exception("unknown arch")
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
    def vreadCSInstr(self):
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
            return
        for i in range(symtab.num_symbols()):
            symbol = symtab.get_symbol(i)
            if symbol.name != symbolName: continue
            return symbol["st_value"]
    def get_section(self, name):
        # for i in range(self.elf.num_sections()): print(self.elf.get_section(i).name)
        return self.elf.get_section_by_name(name)

    def iter_symbols(self):
        for tableName in (".symtab", ".dynsym"):
            symtab = self.elf.get_section_by_name(tableName)
            if symtab and isinstance(symtab, SymbolTableSection):
                for symbol in symtab.iter_symbols():
                    # print(symbol.name, symbol["st_info"], symbol["st_value"])
                    if symbol["st_value"] == 0:
                        continue
                    if symbol["st_info"]["type"] == "STT_FUNC":
                        yield symbol["st_value"], symbol.name, "function"
                    if symbol["st_info"]["type"] == "STT_OBJECT":
                        yield symbol["st_value"], symbol.name, "object"
