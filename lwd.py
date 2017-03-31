#!/usr/bin/env python3

import argparse
import math
import sys

from capstone.x86 import *
import graphviz

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GLib, Gtk, Gdk
import cairo

from model import OperandKind, Region, Model, Function, registerEqual

class GraphViewController(object):
    def __init__(self, model, graphView):
        self.model = model
        self.graphView = graphView
        self.highlights = []
    def renameBasicBlock(self, basicBlock, newName):
        basicBlock.name = newName
        self.model.update_instructions()
        self.graphView.update_cfg()
    def renameFunction(self, function, newName):
        function.name = newName
        function.entry.name = newName
        self.model.update_instructions()
        self.graphView.update_cfg()
        self.graphView.update_table_entry(function)
    def updateOperandKind(self, instr, operand, newKind):
        operand.kind[0] = newKind
        self.model.update_instruction(instr)
        self.graphView.update_cfg()

    def highlightRegion(self, region):
        for lwop in self.graphView.cfgView.iter_operands(region.kind):
            highlight = False
            if region.kind == Region.KIND_REG:
                highlight = registerEqual(lwop.region.meta, region.meta)
            if highlight:
                lwop.get_style_context().add_class("lw-highlight")
                self.highlights.append(lwop)
    def highlightClear(self):
        for widget in self.highlights:
            widget.get_style_context().remove_class("lw-highlight")
        self.highlights = []

    def showCode(self, address):
        if address in self.model.funcMap:
            self.graphView.show_function(address)
        for func in self.model.functions:
            if address in func.addrMap: return
        function = self.model.parse_function(address)
        self.graphView.update_cfg()
        if function:
            self.graphView.add_function(function)
            self.graphView.show_function(function.address)


# This is a bad practice, I know.
theController = GraphViewController(None, None)

class LWBasicBlockPopover(Gtk.PopoverMenu):
    def __init__(self, basicBlock):
        super(LWBasicBlockPopover, self).__init__()
        self.basicBlock = basicBlock
        self.menu = Gtk.Box()
        self.menu.set_property("margin", 10)
        self.menu.set_orientation(Gtk.Orientation.VERTICAL)
        self.menu.set_homogeneous(False)
        self.nameEntry = Gtk.Entry()
        self.nameEntry.set_text(basicBlock.name)
        nameBtn = Gtk.Button()
        nameBtn.add(Gtk.Label("Change"))
        nameBtn.set_property("can-default", True)
        nameBtn.set_property("receives-default", True)
        nameBtn.get_style_context().add_class("suggested-action")
        nameBtn.connect("clicked", self._update_name)
        nameBox = Gtk.Box(Gtk.Orientation.HORIZONTAL, 6)
        nameBox.add(self.nameEntry)
        nameBox.add(nameBtn)
        self.menu.add(nameBox)
        self.menu.show_all()
        self.nameEntry.set_activates_default(True)
        self.set_default_widget(nameBtn)
        self.add(self.menu)

    def _update_name(self, btn):
        self.popdown()
        GLib.idle_add(theController.renameBasicBlock, self.basicBlock, self.nameEntry.get_text())

class LWFunctionPopover(LWBasicBlockPopover):
    def __init__(self, function):
        super(LWFunctionPopover, self).__init__(function.entry)
        self.function = function
        noreturnBtn = Gtk.ModelButton()
        noreturnBtn.set_property("role", Gtk.ButtonRole.CHECK)
        noreturnBtn.set_property("text", "No Return")
        noreturnBtn.show_all()
        # separator = Gtk.Separator()
        # separator.show()
        # self.menu.add(separator)
        # separator.set_property("fill", False)
        self.menu.add(noreturnBtn)

    def _update_name(self, btn):
        self.popdown()
        GLib.idle_add(theController.renameFunction, self.function, self.nameEntry.get_text())

class LWOperandPopover(Gtk.PopoverMenu):
    def __init__(self, instr, region):
        super(LWOperandPopover, self).__init__()
        self.instruction = instr
        self.menu = Gtk.Box()
        self.menu.set_property("margin", 10)
        self.menu.set_orientation(Gtk.Orientation.VERTICAL)
        self.menu.set_homogeneous(False)
        if region.kind == Region.KIND_DATA:
            self.addrBtn = Gtk.ModelButton()
            self.addrBtn.set_property("role", Gtk.ButtonRole.CHECK)
            self.addrBtn.set_property("text", "Address")
            self.addrBtn.connect("clicked", self._update_kind, "address")
            self.menu.add(self.addrBtn)
            self.menu.add(Gtk.Separator())
            self.cstrBtn = Gtk.ModelButton()
            self.cstrBtn.set_property("role", Gtk.ButtonRole.CHECK)
            self.cstrBtn.set_property("text", "C String")
            self.cstrBtn.connect("clicked", self._update_kind, "cstr")
            self.menu.add(self.cstrBtn)
            self.decimalBtn = Gtk.ModelButton()
            self.decimalBtn.set_property("role", Gtk.ButtonRole.CHECK)
            self.decimalBtn.set_property("text", "Decimal")
            self.decimalBtn.connect("clicked", self._update_kind, "decimal")
            self.menu.add(self.decimalBtn)
        elif region.kind == Region.KIND_CODE_INDIRECT:
            self.jmpTableCheckBox = Gtk.ModelButton()
            self.jmpTableCheckBox.set_property("role", Gtk.ButtonRole.CHECK)
            self.jmpTableCheckBox.set_property("text", "Jump Table")
            self.menu.add(self.jmpTableCheckBox)

        self.menu.show_all()
        self.update(region)
        self.add(self.menu)

    def _update_kind(self, widget, property):
        if self.region.kind == Region.KIND_DATA:
            lut = {
                ("address", True): OperandKind.ADDR,
                ("address", False): OperandKind.IMM_HEX,
                ("cstr", True): OperandKind.ADDR_CSTR,
                ("cstr", False): OperandKind.ADDR,
                ("decimal", True): OperandKind.IMM_SDEC,
                ("decimal", False): OperandKind.IMM_HEX,
            }
            op = self.region.meta
            key = property, not widget.get_property("active")
            currentKind = op.kind[0]
            newKind = lut[key] if key in lut else currentKind
            if newKind != currentKind:
                theController.updateOperandKind(self.instruction, op, newKind)

    def update(self, region):
        self.region = region
        if region.kind == Region.KIND_DATA:
            operandKind = region.meta.kind[0]
            isAddress = OperandKind.isAddress(operandKind)
            self.addrBtn.set_property("active", isAddress)
            if isAddress:
                self.cstrBtn.show()
                self.decimalBtn.hide()
                self.cstrBtn.set_property("active", operandKind == OperandKind.ADDR_CSTR)
            else:
                self.cstrBtn.hide()
                self.decimalBtn.show()
                self.decimalBtn.set_property("active", operandKind == OperandKind.IMM_SDEC)


class LWInstrOperand(Gtk.Button):
    def __init__(self, instr, region):
        super(LWInstrOperand, self).__init__()
        self.instruction = instr
        self.region = region
        if region.kind in (Region.KIND_DATA, Region.KIND_CODE_INDIRECT):
            self.popover = LWOperandPopover(instr, region)
            self.popover.set_relative_to(self)
        else:
            self.popover = None
        self.connect("focus-in-event", self._focus_handler, True)
        self.connect("focus-out-event", self._focus_handler, False)
        self.connect("button-press-event", self._handle_click)
        self.get_style_context().add_class("lw-operand")
        self.get_style_context().add_class("lw-monospace")

    def update(self, instr, region):
        if self.region.kind != region.kind: raise Exception("operand region kind changed")
        self.region = region
        self.set_label(region.text)

        if self.popover: self.popover.update(region)

    def _focus_handler(self, widget, event, gained):
        if not self.region: return
        if gained: GLib.idle_add(theController.highlightRegion, self.region)
        else: GLib.idle_add(theController.highlightClear)

    def _handle_click(self, _, event):
        if event.type == Gdk.EventType.BUTTON_PRESS and event.button == Gdk.BUTTON_SECONDARY:
            if self.popover: self.popover.popup()
        elif event.type == Gdk.EventType._2BUTTON_PRESS:
            if self.region.kind == Region.KIND_CODE_ADDR:
                theController.showCode(self.region.meta.imm)


class LWBasicBlock(Gtk.Box):
    def __init__(self, function, basicBlock):
        super(LWBasicBlock, self).__init__(Gtk.Orientation.VERTICAL, 0)

        self.model = basicBlock
        self.bbHdr = Gtk.Box(Gtk.Orientation.HORIZONTAL, 5)
        self.hdrLabel = Gtk.Label("")
        hdrButton = Gtk.MenuButton()
        hdrButton.add(self.hdrLabel)
        hdrButton.get_style_context().add_class("flat")
        if function.entry == basicBlock:
            hdrButton.set_popover(LWFunctionPopover(function))
        else:
            hdrButton.set_popover(LWBasicBlockPopover(basicBlock))
        self.bbHdr.pack_start(hdrButton, True, True, 0)
        self.bbHdr.get_style_context().add_class("header")
        self.content = Gtk.ListBox()
        self.instructions = []

        self.set_homogeneous(False)
        self.set_orientation(Gtk.Orientation.VERTICAL)
        self.pack_start(self.bbHdr, False, False, 0)
        self.pack_end(self.content, False, True, 0)

        self.rebuild()

    def rebuild(self):
        self.content.destroy()
        self.content = Gtk.ListBox()
        self.content.set_selection_mode(Gtk.SelectionMode.NONE)
        self.instructions = []
        sg1 = Gtk.SizeGroup(Gtk.SizeGroupMode.HORIZONTAL)
        sg2 = Gtk.SizeGroup(Gtk.SizeGroupMode.HORIZONTAL)
        sg3 = Gtk.SizeGroup(Gtk.SizeGroupMode.HORIZONTAL)
        for instr in self.model.instructions:
            line = Gtk.Box(Gtk.Orientation.HORIZONTAL, 20)
            mnemonicLabel = Gtk.Label(instr.mnemonic)
            mnemonicLabel.set_property("xalign", 0.0)
            mnemonicLabel.get_style_context().add_class("lw-monospace")
            operandsBox = Gtk.Box()
            operands = []
            for region in instr.op_str:
                if region.isStatic():
                    label = Gtk.Label(region.text)
                    label.get_style_context().add_class("lw-dim")
                    label.get_style_context().add_class("lw-monospace")
                    operands.append(None)
                    operandsBox.pack_start(label, False, False, 0)
                else:
                    regionView = LWInstrOperand(instr, region)
                    operands.append(regionView)
                    operandsBox.pack_start(regionView, False, False, 0)
            commentLabel = Gtk.Label()
            commentLabel.set_property("xalign", 0.0)
            commentLabel.get_style_context().add_class("lw-dim")
            commentLabel.get_style_context().add_class("lw-monospace")
            line.pack_start(mnemonicLabel, False, False, 0)
            line.pack_start(operandsBox, False, False, 0)
            line.pack_end(commentLabel, False, False, 0)
            sg1.add_widget(mnemonicLabel)
            sg2.add_widget(operandsBox)
            sg3.add_widget(commentLabel)
            self.content.add(line)
            self.instructions.append([line, operands, commentLabel])
        self.update() # Fill actual data

        self.content.show_all()
        self.pack_end(self.content, False, True, 0)

    def update(self):
        self.hdrLabel.set_text(self.model.name)
        for instr, view in zip(self.model.instructions, self.instructions):
            for region, regionView in zip(instr.op_str, view[1]):
                if region.isStatic(): continue
                regionView.update(self.model, region)

            commentStr = instr.userComment
            if commentStr and instr.autoComment: commentStr += " | "
            commentStr += instr.autoComment
            # if commentStr:
            commentStr = "; " + commentStr
            view[2].set_text(commentStr)

    def iter_operands(self, kind):
        for instrView in self.instructions:
            for op in instrView[1]:
                if op and op.region.kind == kind:
                    yield op

LWBasicBlock.set_css_name("basicblock")


class LWControlFlowGraph(Gtk.Fixed):
    BORDER_PADDING = 30
    def __init__(self, function):
        super(LWControlFlowGraph, self).__init__()
        self.widgets = []
        self.edges = []
        self.function = function
        self.hasLayout = False
        # self.connect("size-allocate", self._on_size_allocate)
        self.background = Gtk.DrawingArea()
        self.background.connect("draw", self._draw_background)
        # self.backgroundImage = None
        self.put(self.background, self.BORDER_PADDING, self.BORDER_PADDING)
        self.set_property("halign", Gtk.Align.CENTER)
        self.layoutTimeout = None
        self.rebuild()

    def rebuild(self):
        self.hasLayout = False
        for bbView in self.widgets: bbView.destroy()
        self.widgets = []
        for bb in self.function.basicBlocks:
            bbView = LWBasicBlock(self.function, bb)
            bbView.connect("size-allocate", self._on_size_allocate, [0, 0])
            self.put(bbView, 0, -10000)
            self.widgets.append(bbView)
        if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
        self.layoutTimeout = None
        self.show_all()

    def update(self):
        for bbView in self.widgets: bbView.update()

    def iter_operands(self, kind):
        for bbView in self.widgets: yield from bbView.iter_operands(kind)

    def _on_size_allocate(self, bbView, allocation, oldSize):
        if [allocation.width, allocation.height] != oldSize:
            oldSize[0], oldSize[1] = allocation.width, allocation.height
            if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
            self.layoutTimeout = GLib.timeout_add(50, self._auto_layout, True)

    def _auto_layout(self, nodesPositions=False):
        PADDING = LWControlFlowGraph.BORDER_PADDING
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
            graph.node(str(bbView.model.address), **nodeArgs)

        for i, bbView in enumerate(self.widgets):
            bb = bbView.model
            if bb.branchTrue: graph.edge(str(bb.address), str(bb.branchTrue.address), label="taken")
            if bb.branchFalse and bb.branchTrue: graph.edge(str(bb.address), str(bb.branchFalse.address), label="nottaken")
            elif bb.branchFalse: graph.edge(str(bb.address), str(bb.branchFalse.address), label="unco")

        rendered = [x.split() for x in graph.pipe("plain").decode().split("\n")[:-1]]
        totalWidth, totalHeight = map(int, map(float, (rendered[0][2:4])))
        nodes = [(int(x[1]), float(x[2]), float(x[3])) for x in rendered if x[0] == "node"]
        self.edges = [x for x in rendered if x[0] == "edge"]

        for addr, x, y in nodes:
            bbView, w, h = bbMap[addr]
            self.move(bbView, PADDING + int(x) - w/2, PADDING + totalHeight - int(y) - h/2)

        self.background.set_size_request(totalWidth + PADDING, totalHeight + PADDING)
        self.background.queue_draw()

        self.layoutTimeout = None
        self.hasLayout = True

    def _draw_background(self, widget, ctx):
        if len(self.edges) > 0:
            styleCtx = widget.get_style_context()
            def get_color(name, fallback):
                ok, color = styleCtx.lookup_color(name)
                if ok: return color.red, color.green, color.blue, color.alpha
                return fallback

            colors = {
                "taken": get_color("success_color", (0, 0.6, 0, 1)),
                "nottaken": get_color("error_color", (0.8, 0, 0, 1)),
                "unco": get_color("theme_fg_color", (0, 0, 0.5)),
            }

            totalHeight = widget.get_allocated_height() - self.BORDER_PADDING
            for edge in self.edges:
                count = int(edge[3])
                coords = list(map(lambda x: tuple(map(float, x)), zip(edge[4:4+2*count:2], edge[5:5+2*count:2])))
                for x, y in coords: ctx.line_to(x, totalHeight - y)
                ctx.set_source_rgba(*colors[edge[-5]])
                ctx.stroke()
                angle = math.atan2(coords[-1][1] - coords[-2][1], coords[-2][0] - coords[-1][0])
                pos1DX, pos1DY = math.cos(angle + 0.5) * 15, math.sin(angle + 0.5) * 15
                pos2DX, pos2DY = math.cos(angle - 0.5) * 15, math.sin(angle - 0.5) * 15
                targetX, targetY = coords[-1][0], totalHeight - coords[-1][1]
                ctx.move_to(targetX, targetY)
                ctx.line_to(targetX + pos1DX, targetY + pos1DY)
                ctx.line_to(targetX + pos2DX, targetY + pos2DY)
                ctx.close_path()
                ctx.fill()


class LWGraphView(Gtk.Paned):
    def __init__(self, model):
        super(LWGraphView, self).__init__()
        self.model = model

        self.cfgView = None
        self.graphBin = Gtk.ScrolledWindow()
        self.graphBin.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.store = Gtk.ListStore(str, str, int)
        self.listView = Gtk.TreeView(self.store)
        renderer = Gtk.CellRendererText()
        listColName = Gtk.TreeViewColumn("Name", renderer, text=0)
        listColAddr = Gtk.TreeViewColumn("Address", renderer, text=1)
        self.listView.append_column(listColName)
        self.listView.append_column(listColAddr)
        self.listView.get_selection().connect("changed", self._update_graph)
        self.listBin = Gtk.ScrolledWindow()
        self.listBin.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.listBin.add(self.listView)
        self.pack1(self.listBin, False, False)
        self.pack2(self.graphBin, True, True)

        for func in model.functions:
            self.store.append([func.name, hex(func.address), func.address])

    def _update_graph(self, selection):
        model, treeiter = selection.get_selected()
        if treeiter:
            addr = model[treeiter][2]
            func = self.model.funcMap[addr]

            current = self.graphBin.get_child()
            if current: current.destroy()

            self.cfgView = LWControlFlowGraph(func)
            self.cfgView.show_all()
            self.graphBin.add(self.cfgView)

    def add_function(self, function):
        index = sorted(self.model.funcMap.keys()).index(function.address)
        treePath = Gtk.TreePath.new_from_indices([index])
        treeIter = self.store.get_iter(treePath)
        self.store.insert_before(treeIter, [function.name, hex(function.address), function.address])

    def update_cfg(self):
        self.cfgView.update()

    def rebuild_cfg(self):
        self.cfgView.rebuild()

    def update_table_entry(self, function):
        index = sorted(self.model.funcMap.keys()).index(function.address)
        treePath = Gtk.TreePath.new_from_indices([index])
        treeIter = self.store.get_iter(treePath)
        self.store.set(treeIter, 0, function.name)

    def show_function(self, address):
        index = sorted(self.model.funcMap.keys()).index(address)
        treePath = Gtk.TreePath.new_from_indices([index])
        treeIter = self.store.get_iter(treePath)
        self.listView.get_selection().select_iter(treeIter)


class Window(object):
    def __init__(self, model):
        self.model = model
        self.graphView = LWGraphView(model)

        theController.model = model
        theController.graphView = self.graphView

        self.gtk = Gtk.Window()
        self.gtk.set_title("LWD")
        self.gtk.set_default_size(1024, 768)
        self.gtk.connect("destroy", Gtk.main_quit)

        stack = Gtk.Stack()
        stack.add_titled(self.graphView, "graphview", "CFG")
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(stack)

        headerBar = Gtk.HeaderBar()
        headerBar.set_show_close_button(True)
        headerBar.set_property("custom_title", switcher)

        self.gtk.set_titlebar(headerBar)
        self.gtk.add(stack)
        self.gtk.show_all()


css = """
basicblock {
    background: @theme_base_color;
    border: 1px solid @borders;
}
basicblock .header {
    border-bottom: 1px solid @borders;
}
basicblock .header button {
    border: none;
    border-radius: 0;
}
.lw-monospace {
    font-family: Monospace;
}
.lw-dim {
    color: @insensitive_fg_color;
}
.lw-dim:backdrop {
    color: @unfocused_insensitive_color;
}
.lw-operand {
    padding: 0;
    background: none;
    border: none;
}
.lw-operand.lw-highlight {
    background: shade(@warning_color,1.5);
}
"""

def main():
    parser = argparse.ArgumentParser(description="lwd")
    parser.add_argument("file", nargs=1, type=argparse.FileType('rb', 0))
    parser.add_argument("symbols", nargs='+')
    options = parser.parse_args()
    binaryFile = options.file[0].read()
    options.file[0].close()

    model = Model(binaryFile)
    for sym in options.symbols:
        try:
            model.parse_function(sym)
        except Exception as e:
            print("Cannot parse", sym, e)
    model.functions.sort(key=lambda f: f.address)

    style_provider = Gtk.CssProvider()
    style_provider.load_from_data(css.encode())

    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        style_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )

    # TODO: Use Gtk.Application
    wnd = Window(model)

    Gtk.main()

    # print(options.file[0])
    return 0

if __name__ == "__main__":
    sys.exit(main())
