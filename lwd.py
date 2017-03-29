#!/usr/bin/env python3

import argparse
import io
import math
import os
import operator
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from capstone.x86 import *
import graphviz

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GLib, Gtk, Gdk
import cairo

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
            print("Cannot decode:", stream, self.vaddr)
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

class BasicBlock(object):
    def __init__(self, addr):
        self.address = addr
        self.instructions = []
        self.branchTrue = None
        self.branchFalse = None
        self.view = None

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
    def __init__(self, elf, addr):
        self.basicBlocks = []
        self.addrMap = {}
        self.entry = self.recoverCFG(elf, addr)
        self.basicBlocks.sort(key=operator.attrgetter("address"))
        self.dump()

    def dump(self):
        for bb in self.basicBlocks:
            bb.dump()

    def recoverCFG(self, elf, addr):
        print("Decoding", hex(addr))
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
            print(operand.type, X86_OP_IMM, hex(operand.imm))
            if operand.type == X86_OP_IMM:
                btrue = self.recoverCFG(elf, operand.imm)
                if lastInstr.id == X86_INS_JMP:
                    self.addrMap[lastInstr.address].branchFalse = btrue
                else:
                    self.addrMap[lastInstr.address].branchTrue = btrue
            else:
                raise Exception("unhandled jump operand " + instr.op_str)

        return bb
        # print(instr.mnemonic, instr.op_str)

class Model(object):
    def __init__(self, binaryFile, **kwargs):
        self.binaryFile = binaryFile
        self.elf = ELFReader(binaryFile)
        self.functions = []

    def parse_function(self, **kwargs):
        address = None
        if "address" in kwargs:
            address = kwargs["address"]
        elif "symbol" in kwargs:
            address = self.elf.get_symbol(kwargs["symbol"])
        if not address:
            print("Could not find address for", kwargs)

        self.functions.append(Function(self.elf, address))
        return self.functions[-1]



class LWBasicBlock(Gtk.Box):
    def __init__(self, basicBlock):
        super(LWBasicBlock, self).__init__(Gtk.Orientation.VERTICAL, 0)

        mnemonics = [instr.mnemonic for instr in basicBlock.instructions]
        op_strs = [instr.op_str for instr in basicBlock.instructions]
        mnemonicLen = max(5, len(max(mnemonics, key=len)))

        displayText = "\n".join([a + ((mnemonicLen - len(a) + 1) * " " + b if b else "") for a, b in zip(mnemonics, op_strs)])

        self.model = basicBlock
        self.bbHdr = Gtk.Box(Gtk.Orientation.HORIZONTAL, 0)
        self.bbHdr.pack_start(Gtk.Label("bb_" + hex(basicBlock.address)), False, False, 5)
        self.bbHdr.pack_start(Gtk.Label(), True, True, 0)
        self.bbHdrBox = Gtk.EventBox()
        self.bbHdrBox.add(self.bbHdr)
        self.content = Gtk.TextView()
        self.content.set_editable(False)
        self.content.set_can_focus(False)
        self.buffer = self.content.get_buffer()
        self.buffer.set_text(displayText)
        self.set_homogeneous(False)
        self.set_orientation(Gtk.Orientation.VERTICAL)
        self.pack_start(self.bbHdrBox, False, False, 0)
        self.pack_start(self.content, False, True, 0)
        self.bbHdrBox.get_style_context().add_class("header")

        movement = { "sx": 0, "sy": 0 }
        self.bbHdrBox.connect("button-press-event", self._widget_button_press, movement)
        self.bbHdrBox.connect("button-release-event", self._widget_button_release, movement)
        self.bbHdrBox.connect("motion-notify-event", self._widget_motion, movement)
        self.bbHdrBox.add_events(Gdk.EventMask.EXPOSURE_MASK | Gdk.EventMask.BUTTON_PRESS_MASK | Gdk.EventMask.POINTER_MOTION_MASK)

    def _widget_button_press(self, widget, event, movement):
        if event.button == 1:
            movement["sx"] = event.x_root - self.model.view["x"]
            movement["sy"] = event.y_root - self.model.view["y"]
        return True

    def _widget_button_release(self, widget, event, movement):
        if event.button == 1:
            self.model.view["x"] = event.x_root - movement["sx"]
            self.model.view["y"] = event.y_root - movement["sy"]
        return True

    def _widget_motion(self, widget, event, movement):
        if event.state & Gdk.ModifierType.BUTTON1_MASK:
            x = event.x_root - movement["sx"]
            y = event.y_root - movement["sy"]
            self.get_parent().move(self, x, y)
            self.get_parent().queue_draw_area(x, y, self.get_allocated_width(), self.get_allocated_height())
        return True

LWBasicBlock.set_css_name("basicblock")


class LWGraphView(Gtk.Fixed):
    BORDER_PADDING = 10
    def __init__(self, function):
        super(LWGraphView, self).__init__()
        self.widgets = []
        self.background = Gtk.DrawingArea()
        self.background.connect("draw", self._draw_background)
        self.backgroundImage = None
        self.put(self.background, LWGraphView.BORDER_PADDING, LWGraphView.BORDER_PADDING)
        # print(dir(Gtk.Align))
        self.set_property("halign", Gtk.Align.CENTER)
        for bb in function.basicBlocks:
            if not bb.view: bb.view = { "x": 0, "y": 0 }
            bbView = LWBasicBlock(bb)
            self.put(bbView, bb.view["x"], bb.view["y"])
            self.widgets.append(bbView)
        self.layoutTimeout = GLib.timeout_add_seconds(1, self._auto_layout, True)

    def _auto_layout(self, nodesPositions=False):
        PADDING = LWGraphView.BORDER_PADDING
        bbMap = {}
        graph = graphviz.Digraph()
        graph.attr("graph", nodesep="20")
        graph.attr("graph", ranksep="20")
        for i, bbView in enumerate(self.widgets):
            w, h = bbView.get_allocated_width(), bbView.get_allocated_height()
            bb = bbView.model
            bbMap[bb.address] = bbView, w, h
            nodeArgs = {
                "width": str(w),
                "height": str(h),
                "shape": "rectangle"
            }
            if not nodesPositions:
                nodeArgs["pos"] = "{},{}!".format(bb.view["x"], bb.view["y"])
                nodeArgs["pin"] = "true"
            print(nodeArgs)
            graph.node(str(bbView.model.address), **nodeArgs)

        for i, bbView in enumerate(self.widgets):
            bb = bbView.model
            if bb.branchTrue: graph.edge(str(bb.address), str(bb.branchTrue.address), label="taken")
            if bb.branchFalse and bb.branchTrue: graph.edge(str(bb.address), str(bb.branchFalse.address), label="nottaken")
            elif bb.branchFalse: graph.edge(str(bb.address), str(bb.branchFalse.address), label="unco")

        rendered = [x.split() for x in graph.pipe("plain").decode().split("\n")[:-1]]
        totalWidth, totalHeight = map(int, map(float, (rendered[0][2:4])))
        nodes = [(int(x[1]), float(x[2]), float(x[3])) for x in rendered if x[0] == "node"]
        edges = [x for x in rendered if x[0] == "edge"]
        print(edges)

        for addr, x, y in nodes:
            bbView, w, h = bbMap[addr]
            self.move_nocheck(bbView, PADDING + int(x) - w/2, PADDING + totalHeight - int(y) - h/2)

        self.background.set_size_request(totalWidth + PADDING, totalHeight + PADDING)
        self.backgroundImage = cairo.ImageSurface(cairo.FORMAT_ARGB32, totalWidth, totalHeight)
        ctx = cairo.Context(self.backgroundImage)

        colors = {
            "taken": (0, 0.6, 0),
            "nottaken": (0.8, 0, 0),
            "unco": (0, 0, 0.5),
        }
        for edge in edges:
            count = int(edge[3])
            coords = list(map(lambda x: tuple(map(float, x)), zip(edge[4:4+2*count:2], edge[5:5+2*count:2])))
            for x, y in coords: ctx.line_to(x, totalHeight - y)
            ctx.set_source_rgb(*colors[edge[-5]])
            ctx.stroke()
            angle = math.atan2(coords[-1][1] - coords[-2][1], coords[-2][0] - coords[-1][0])
            pos1DX, pos1DY = math.cos(angle + 0.5) * 15, math.sin(angle + 0.5) * 15
            pos2DX, pos2DY = math.cos(angle - 0.5) * 15, math.sin(angle - 0.5) * 15
            targetX, targetY = coords[-1][0], totalHeight - coords[-1][1]
            ctx.move_to(targetX, targetY)
            ctx.line_to(targetX + pos1DX, targetY + pos1DY)
            ctx.line_to(targetX + pos2DX, targetY + pos2DY)
            ctx.close_path()
            # ctx.line_to(coords[-1][0] + math.cos(angle) * 100, totalHeight - coords[-1][1] + math.sin(angle) * 100)
            ctx.fill()
        self.background.queue_draw()

    def _draw_background(self, widget, ctx):
        if self.backgroundImage:
            ctx.set_source_surface(self.backgroundImage)
            ctx.paint()

    def move_nocheck(self, widget, x, y):
        widget.model.view["x"] = x
        widget.model.view["y"] = y
        super(LWGraphView, self).move(widget, x, y)

    def move(self, widget, x, y):
        self.move_nocheck(widget, x, y)
        if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
        self.layoutTimeout = GLib.timeout_add_seconds(1, self._auto_layout, False)

LWGraphView.set_css_name("graphview")


class Window(object):
    def __init__(self, function):
        self.gtk = Gtk.Window()
        self.gtk.set_title("LWD")
        self.gtk.set_default_size(1024, 768)
        self.gtk.connect("destroy", Gtk.main_quit)

        scrolled = Gtk.ScrolledWindow(None, None)
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        graphView = LWGraphView(function)
        scrolled.add(graphView)

        self.gtk.add(scrolled)
        self.gtk.show_all()

css = """
LWBasicBlock { background: #fff }

graphview {
    padding: 10px;
}
basicblock {
    background: #ffffff;
    border: 1px solid #000000;
}
basicblock .header {
    border-bottom: 1px solid #000000;
}
basicblock textview {
    padding: 10px;
    font-family: Monospace;
    font-size: 90%;
}
"""

def main():
    parser = argparse.ArgumentParser(description="lwd")
    parser.add_argument("file", nargs=1, type=argparse.FileType('rb', 0))
    parser.add_argument("symbol", nargs=1)
    options = parser.parse_args()
    binaryFile = options.file[0].read()
    options.file[0].close()

    model = Model(binaryFile)
    model.parse_function(symbol=options.symbol[0])

    style_provider = Gtk.CssProvider()
    # style_provider.load_from_data(css)
    style_provider.load_from_data(css.encode())

    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        style_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )

    wnd = Window(model.functions[-1])

    Gtk.main()

    # print(options.file[0])
    return 1

if __name__ == "__main__":
    sys.exit(main())
