
from gi.repository import GObject, Gtk, Gdk

from model import OperandKind, RegionKind
from immediatePopover import ImmediatePopover


class RegionView(Gtk.Button):
    def __init__(self, viewModel, indices, region):
        super(RegionView, self).__init__()
        self.indices = indices
        self.viewModel = viewModel
        self.region = region
        self.popover = None
        if region.kind == RegionKind.IMM:
            self.popover = ImmediatePopover(viewModel, indices, region)
        if self.popover:
            self.popover.set_relative_to(self)
        self.connect("focus-in-event", self._focus_handler, True)
        self.connect("focus-out-event", self._focus_handler, False)
        self.connect("button-press-event", self._handle_click)

    def update(self, region):
        if self.region.kind != region.kind: raise Exception("operand region kind changed")
        self.region = region
        self.set_label(region.text)

        if self.popover:
            self.popover.set_relative_to(self)
            self.popover.update(region)

    def set_highlight(self, highlight):
        if highlight:
            self.get_style_context().add_class("lw-highlight")
        else:
            self.get_style_context().remove_class("lw-highlight")

    def _focus_handler(self, widget, event, gained):
        if not self.region: return
        if gained:
            self.viewModel.set_highlight_region(self.region)
        else:
            self.viewModel.set_highlight_region(None)

    def _handle_click(self, _, event):
        if event.type == Gdk.EventType.BUTTON_PRESS and event.button == Gdk.BUTTON_SECONDARY:
            if self.popover: self.popover.popup()
        # elif event.type == Gdk.EventType._2BUTTON_PRESS:
        #     if self.region.kind == Region.KIND_CODE_ADDR:
        #         showCode(self.region.meta.imm)

RegionView.set_css_name("region")

class BasicBlockView(Gtk.Box):
    __gtype_name__ = "LWBasicBlockView"
    __gtemplate_children__ = [
        "headerLabel",
        "listBox",
        "popover",
        "nameEntry",
        "nameButton",
        "functionSettings",
        "noreturnButton",
    ]

    def __init__(self, viewModel, index, basicBlock):
        super(BasicBlockView, self).__init__()
        self.init_template()
        for child in BasicBlockView.__gtemplate_children__:
            setattr(self, child, self.get_template_child(BasicBlockView, child))

        self.viewModel = viewModel
        self.index = index


        self.popover.set_default_widget(self.nameButton)
        self.popover.get_child().show_all()
        if basicBlock.data["kind"] != "function":
            self.functionSettings.hide()

        sizeGroup1 = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)
        sizeGroup2 = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)
        sizeGroup3 = Gtk.SizeGroup(mode=Gtk.SizeGroupMode.HORIZONTAL)

        self.instructions = []
        for instrIndex, instr in enumerate(basicBlock.instructions):
            line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=20)
            mnemonicLabel = Gtk.Label(label=instr.mnemonic)
            mnemonicLabel.set_property("xalign", 0)
            regionViewsBox = Gtk.Box()
            regionViews = []
            for regionIndex, region in enumerate(instr.regions):
                if region.kind == RegionKind.STATIC:
                    label = Gtk.Label(label=region.text)
                    label.get_style_context().add_class("lw-dim")
                    regionViews.append(None)
                    regionViewsBox.pack_start(label, False, False, 0)
                else:
                    regionView = RegionView(viewModel, (index, instrIndex, regionIndex), region)
                    regionViews.append(regionView)
                    regionViewsBox.pack_start(regionView, False, False, 0)
            commentLabel = Gtk.Label()
            commentLabel.set_property("xalign", 0)
            commentLabel.get_style_context().add_class("lw-dim")
            line.pack_start(mnemonicLabel, False, False, 0)
            line.pack_start(regionViewsBox, False, False, 0)
            line.pack_end(commentLabel, False, False, 0)
            sizeGroup1.add_widget(mnemonicLabel)
            sizeGroup2.add_widget(regionViewsBox)
            sizeGroup3.add_widget(commentLabel)
            self.listBox.add(line)
            self.instructions.append((regionViews, commentLabel))
        self.update_texts(basicBlock)

    def on_clicked(self, *args):
        print(args)

    def update_texts(self, basicBlock):
        self.headerLabel.set_label(basicBlock.name)
        self.nameEntry.set_text(basicBlock.name)
        self.noreturnButton.set_property("active", "noreturn" in basicBlock.data)

        for instr, (regionViews, commentLabel) in zip(basicBlock.instructions, self.instructions):
            for region, regionView in zip(instr.regions, regionViews):
                if regionView:
                    regionView.update(region)
            commentLabel.set_text(instr.comment)

    def update_highlights(self, bbHighlights):
        for (regionViews, _), regionHighlights in zip(self.instructions, bbHighlights):
            for regionView, highlight in zip(regionViews, regionHighlights):
                if regionView:
                    regionView.set_highlight(highlight)

    def on_name_button_clicked(self, nameButton):
        self.popover.popdown()
        self.viewModel.rename_basic_block(self.index, self.nameEntry.get_text())

    def on_noreturn_button_clicked(self, noreturnButton):
        self.popover.popdown()
        isNoreturn = not self.noreturnButton.get_property("active")
        self.viewModel.set_basic_block_property(self.index, "noreturn", isNoreturn)

    @staticmethod
    def _connect_func(builder, obj, signalName, handlerName, connectObject, flags, cls):
        templateInst = builder.get_object(cls.__gtype_name__)
        obj.connect(signalName, getattr(templateInst, handlerName))

BasicBlockView.set_css_name("basicblock")
BasicBlockView.set_template_from_resource("/org/lwd/LWD/basicblock.ui")
BasicBlockView.set_connect_func(BasicBlockView._connect_func, BasicBlockView)
for child in BasicBlockView.__gtemplate_children__:
    BasicBlockView.bind_template_child_full(child, True, 0)
