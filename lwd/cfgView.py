
import math

import cairo
from gi.repository import GLib, GObject, Gtk

from lwd import profile
from lwd.basicblock import BasicBlockView
from lwd.viewmodel import CFGViewModel

class CFGView(Gtk.Fixed):
    BORDER_PADDING = 100
    drawTimeout = None
    def __init__(self, model, address):
        super(CFGView, self).__init__()
        self.model = model
        self.viewModel = CFGViewModel(model, address)
        sig1 = self.viewModel.connect("cfg-changed", self.rebuild_basic_blocks)
        sig2 = self.viewModel.connect("text-changed", self.update_texts)
        sig3 = self.viewModel.connect("highlight-changed", self.update_highlights)
        sig4 = self.viewModel.connect("layout-changed", self.update_positions)
        def on_destroy(*args):
            if self.drawTimeout is not None:
                GLib.source_remove(self.drawTimeout)
            self.viewModel.disconnect(sig1)
            self.viewModel.disconnect(sig2)
            self.viewModel.disconnect(sig3)
            self.viewModel.disconnect(sig4)
            self.viewModel.destroy()

        self.connect("destroy", on_destroy)

        self.set_property("halign", Gtk.Align.CENTER)

        self.basicBlocks = []
        self.edges = []
        self.background = Gtk.Image.new_from_surface(None)
        self.put(self.background, 0, 0)

        self.viewModel.init()

    def on_size_allocate(self, bbView, allocation, index):
        self.viewModel.on_size_updated(index, allocation.width, allocation.height)

    @profile
    def rebuild_basic_blocks(self, viewModel, basicBlocks):
        for bbView in self.basicBlocks:
            bbView.destroy()
        self.basicBlocks = []
        for index, basicBlock in enumerate(basicBlocks):
            bbView = BasicBlockView(self.viewModel, index, basicBlock)
            bbView.connect("size-allocate", self.on_size_allocate, index)
            bbView.show_all()
            self.put(bbView, -10000, -0)
            self.basicBlocks.append(bbView)

    def update_texts(self, viewModel, basicBlocks):
        for bbView, basicBlock in zip(self.basicBlocks, basicBlocks):
            bbView.update_texts(basicBlock)

    def update_highlights(self, viewModel, bbHighlights):
        for bbView, bbHighlight in zip(self.basicBlocks, bbHighlights):
            bbView.update_highlights(bbHighlight)

    @profile
    def update_positions(self, viewModel, totalSize, positions, edges):
        totalWidth, totalHeight = totalSize
        imageWidth, imageHeight = totalWidth + 2*self.BORDER_PADDING, totalHeight + 2*self.BORDER_PADDING
        self.background.set_size_request(imageWidth, imageHeight)
        self.edges = edges
        # self.draw_background(self, ctx)
        self.drawTimeout = GLib.idle_add(self.draw_background, imageWidth, imageHeight)

        for i, (x, y) in enumerate(positions):
            self.move(self.basicBlocks[i], self.BORDER_PADDING + x, self.BORDER_PADDING + y)

    @profile
    def draw_background(self, imageWidth, imageHeight):
        self.drawTimeout = None
        if len(self.edges) > 0:
            backgroundImage = cairo.ImageSurface(cairo.FORMAT_ARGB32, imageWidth, imageHeight)
            ctx = cairo.Context(backgroundImage)
            ctx.translate(self.BORDER_PADDING, imageHeight - self.BORDER_PADDING)
            ctx.scale(1, -1)
            styleCtx = self.get_style_context()
            def get_color(name, fallback):
                ok, color = styleCtx.lookup_color(name)
                if ok: return color.red, color.green, color.blue, color.alpha
                return fallback

            colors = {
                "jump": get_color("success_color", (0, 0.6, 0, 1)),
                "fallthrough": get_color("error_color", (0.8, 0, 0, 1)),
                # "unco": get_color("theme_fg_color", (0, 0, 0.5)),
            }

            for edge in self.edges:
                count = int(edge[3])
                coords = list(map(lambda x: tuple(map(float, x)), zip(edge[4:4+2*count:2], edge[5:5+2*count:2])))
                for x, y in coords: ctx.line_to(x,  y)
                ctx.set_source_rgba(*colors[edge[-5]])
                ctx.stroke()
                angle = math.atan2(coords[-2][1] - coords[-1][1], coords[-2][0] - coords[-1][0])
                pos1DX, pos1DY = math.cos(angle + 0.5) * 15, math.sin(angle + 0.5) * 15
                pos2DX, pos2DY = math.cos(angle - 0.5) * 15, math.sin(angle - 0.5) * 15
                targetX, targetY = coords[-1][0], coords[-1][1]
                ctx.move_to(targetX, targetY)
                ctx.line_to(targetX + pos1DX, targetY + pos1DY)
                ctx.line_to(targetX + pos2DX, targetY + pos2DY)
                ctx.close_path()
                ctx.fill()

            self.background.set_from_surface(backgroundImage)
