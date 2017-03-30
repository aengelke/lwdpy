#!/usr/bin/env python3

import argparse
import math
import sys

import graphviz

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GLib, Gtk, Gdk
import cairo

from model import Model, Function

class LWBasicBlock(Gtk.EventBox):
    def __init__(self, basicBlock):
        super(LWBasicBlock, self).__init__()#Gtk.Orientation.VERTICAL, 0)

        mnemonics = [instr.mnemonic for instr in basicBlock.instructions]
        mnemonicLen = max(5, len(max(mnemonics, key=len)))

        op_strs = ["".join(map(str, instr.op_str)) for instr in basicBlock.instructions]
        displayText = "\n".join([a + ((mnemonicLen - len(a) + 1) * " " + b if b else "") for a, b in zip(mnemonics, op_strs)])

        self.model = basicBlock
        self.bbHdr = Gtk.Box(Gtk.Orientation.HORIZONTAL, 0)
        self.bbHdr.pack_start(Gtk.Label(basicBlock.name), False, False, 5)
        self.bbHdr.pack_start(Gtk.Label(), True, True, 0)
        self.bbHdr.get_style_context().add_class("header")
        # self.bbHdrBox = Gtk.EventBox()
        # self.bbHdrBox.add(self.bbHdr)
        self.content = Gtk.TextView()
        self.content.set_editable(False)
        self.content.set_can_focus(False)
        self.content.set_monospace(True)
        self.buffer = self.content.get_buffer()
        self.buffer.set_text(displayText)
        self.box = Gtk.Box(Gtk.Orientation.VERTICAL, 0)
        self.box.set_homogeneous(False)
        self.box.set_orientation(Gtk.Orientation.VERTICAL)
        self.set_can_focus(True)
        self.set_focus_on_click(True)
        self.box.pack_start(self.bbHdr, False, False, 0)
        self.box.pack_start(self.content, False, True, 0)

        # movement = { "sx": 0, "sy": 0 }
        # self.bbHdrBox.connect("button-press-event", self._widget_button_press, movement)
        # self.bbHdrBox.connect("button-release-event", self._widget_button_release, movement)
        # self.bbHdrBox.connect("motion-notify-event", self._widget_motion, movement)
        self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
        self.add(self.box)

    # def _widget_button_press(self, widget, event, movement):
    #     if event.button == 1:
    #         movement["sx"] = event.x_root - self.model.view["x"]
    #         movement["sy"] = event.y_root - self.model.view["y"]
    #     return True

    # def _widget_button_release(self, widget, event, movement):
    #     if event.button == 1:
    #         self.model.view["x"] = event.x_root - movement["sx"]
    #         self.model.view["y"] = event.y_root - movement["sy"]
    #     return True

    # def _widget_motion(self, widget, event, movement):
    #     if event.state & Gdk.ModifierType.BUTTON1_MASK:
    #         x = event.x_root - movement["sx"]
    #         y = event.y_root - movement["sy"]
    #         self.get_parent().move(self, x, y)
    #         self.get_parent().queue_draw_area(x, y, self.get_allocated_width(), self.get_allocated_height())
    #     return True

LWBasicBlock.set_css_name("basicblock")


class LWGraphView(Gtk.Fixed):
    BORDER_PADDING = 10
    def __init__(self, function):
        super(LWGraphView, self).__init__()
        self.widgets = []
        self.hasLayout = False
        self.connect("size-allocate", self._on_size_allocate)
        self.background = Gtk.DrawingArea()
        self.background.connect("draw", self._draw_background)
        self.backgroundImage = None
        self.put(self.background, LWGraphView.BORDER_PADDING, LWGraphView.BORDER_PADDING)
        # print(dir(Gtk.Align))
        self.set_property("halign", Gtk.Align.CENTER)
        for bb in function.basicBlocks:
            # if not bb.view: bb.view = { "x": 0, "y": 0 }
            bbView = LWBasicBlock(bb)
            bbView.connect("size-allocate", self._on_size_allocate)
            self.put(bbView, 0, 0)
            self.widgets.append(bbView)
        self.layoutTimeout = None

    def _on_size_allocate(self, _1, _2):
        if not self.hasLayout:
            if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
            self.layoutTimeout = GLib.timeout_add(100, self._auto_layout, True)

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
            # if not nodesPositions:
            #     nodeArgs["pos"] = "{},{}!".format(bb.view["x"], bb.view["y"])
            #     nodeArgs["pin"] = "true"
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
            ctx.fill()

        self.background.queue_draw()

        self.layoutTimeout = None
        self.hasLayout = True

    def _draw_background(self, widget, ctx):
        if self.backgroundImage:
            ctx.set_source_surface(self.backgroundImage)
            ctx.paint()

    def move_nocheck(self, widget, x, y):
        # widget.model.view["x"] = x
        # widget.model.view["y"] = y
        super(LWGraphView, self).move(widget, x, y)

    def move(self, widget, x, y):
        self.move_nocheck(widget, x, y)
        # if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
        # self.layoutTimeout = GLib.timeout_add_seconds(1, self._auto_layout, False)

LWGraphView.set_css_name("graphview")


class Window(object):
    def __init__(self, model):
        self.model = model
        self.gtk = Gtk.Window()
        self.gtk.set_title("LWD")
        self.gtk.set_default_size(1024, 768)
        self.gtk.connect("destroy", Gtk.main_quit)

        self.paned = Gtk.Paned()#Gtk.Orientation.HORIZONTAL)

        self.graphBin = Gtk.ScrolledWindow(None, None)
        self.graphBin.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.store = Gtk.ListStore(str, str, int)
        self.listView = Gtk.TreeView(self.store)
        renderer = Gtk.CellRendererText()
        listColName = Gtk.TreeViewColumn("Name", renderer, text=0)
        listColAddr = Gtk.TreeViewColumn("Address", renderer, text=1)
        listColAddr.set_sort_column_id(2)
        self.listView.append_column(listColName)
        self.listView.append_column(listColAddr)
        self.listView.get_selection().connect("changed", self._update_graph)
        self.listBin = Gtk.ScrolledWindow(None, None)
        self.listBin.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.listBin.add(self.listView)
        # self.stack = Gtk.Stack()
        # self.stackSwitcher = Gtk.StackSidebar()
        # self.stackSwitcher.set_stack(self.stack)
        # hbox.pack_start(self.stackSwitcher, False, False, 0)
        self.paned.pack1(self.listBin, False, False)
        self.paned.pack2(self.graphBin, True, True)

        for func in model.functions:
            self.add_function(func)

        self.gtk.add(self.paned)
        self.gtk.show_all()

    def _update_graph(self, selection):
        model, treeiter = selection.get_selected()
        if treeiter:
            addr = model[treeiter][2]
            func = self.model.funcMap[addr]
            current = self.graphBin.get_child()
            if current: current.destroy()
            graphView = LWGraphView(func)
            # self.graphBin = Gtk.ScrolledWindow(None, None)
            # self.graphBin.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
            self.graphBin.add(graphView)
            graphView.show_all()
            # self.paned.pack2(self.graphBin)
            print("Show CFG for", hex(addr), func.name)

        # print(selection.get_user_data())

    def add_function(self, function):
        self.store.append([function.name, hex(function.address), function.address])
        # graphView = LWGraphView(function)
        # scrolled.add(graphView)
        # self.stack.add_titled(scrolled, "fn_" + hex(function.address)[2:], function.name)


css = """
LWBasicBlock { background: #fff }

graphview {
    padding: 10px;
}
basicblock > box {
    background: #ffffff;
    border: 1px solid #000000;
}
basicblock:focus box {
    background: #f00;
}
basicblock .header {
    border-bottom: 1px solid #000000;
}
basicblock textview {
    padding: 10px;
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
    for sym in options.symbols: model.parse_function(sym)
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
