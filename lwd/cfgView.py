
import math

import cairo
from gi.repository import Gtk

from basicblock import BasicBlockView
from viewmodel import CFGViewModel

class CFGView(Gtk.Fixed):
    BORDER_PADDING = 30
    def __init__(self, model, address):
        super(CFGView, self).__init__()
        self.model = model
        self.viewModel = CFGViewModel(model, address)
        self.viewModel.connect("cfg-changed", self.rebuild_basic_blocks)
        self.viewModel.connect("text-changed", self.update_texts)
        self.viewModel.connect("highlight-changed", self.update_highlights)
        self.viewModel.connect("layout-changed", self.update_positions)

        self.set_property("halign", Gtk.Align.CENTER)

        self.basicBlocks = []
        self.edges = []
        self.background = Gtk.DrawingArea()
        self.background.connect("draw", self.draw_background)
        self.put(self.background, self.BORDER_PADDING, self.BORDER_PADDING)

        self.viewModel.init()

    def on_size_allocate(self, bbView, allocation, index):
        self.viewModel.on_size_updated(index, allocation.width, allocation.height)

    def rebuild_basic_blocks(self, viewModel, basicBlocks):
        for bbView in self.basicBlocks:
            bbView.destroy()
        self.basicBlocks = []
        for index, basicBlock in enumerate(basicBlocks):
            bbView = BasicBlockView(self.viewModel, index, basicBlock)
            bbView.connect("size-allocate", self.on_size_allocate, index)
            bbView.show_all()
            self.put(bbView, -1000, -1000)
            self.basicBlocks.append(bbView)

    def update_texts(self, viewModel, basicBlocks):
        for bbView, basicBlock in zip(self.basicBlocks, basicBlocks):
            bbView.update_texts(basicBlock)

    def update_highlights(self, viewModel, bbHighlights):
        for bbView, bbHighlight in zip(self.basicBlocks, bbHighlights):
            bbView.update_highlights(bbHighlight)

    def update_positions(self, viewModel, totalSize, positions, edges):
        totalWidth, totalHeight = totalSize
        self.background.set_size_request(totalWidth + self.BORDER_PADDING, totalHeight + self.BORDER_PADDING)
        self.edges = edges
        for i, (x, y) in enumerate(positions):
            self.move(self.basicBlocks[i], self.BORDER_PADDING + x, self.BORDER_PADDING + y)

    def draw_background(self, widget, ctx):
        if len(self.edges) > 0:
            styleCtx = widget.get_style_context()
            def get_color(name, fallback):
                ok, color = styleCtx.lookup_color(name)
                if ok: return color.red, color.green, color.blue, color.alpha
                return fallback

            colors = {
                "jump": get_color("success_color", (0, 0.6, 0, 1)),
                "fallthrough": get_color("error_color", (0.8, 0, 0, 1)),
                # "unco": get_color("theme_fg_color", (0, 0, 0.5)),
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
