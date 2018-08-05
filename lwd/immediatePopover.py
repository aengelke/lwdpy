
from gi.repository import Gtk

from lwd.model import OperandKind, RegionKind


KIND_GROUPS = {
    "address": [OperandKind.ADDR, OperandKind.ADDR_CSTR, OperandKind.STACKFRAME],
    "immediate": [OperandKind.IMM_HEX, OperandKind.IMM_SDEC, OperandKind.IMM_CHAR],
}

class ImmediatePopover(Gtk.Popover):
    __gtype_name__ = "LWImmediatePopover"
    __gtemplate_children__ = [
        "detailSettings",
        "globalButton",
        "cstrButton",
        "stackframeButton",
        "nameEntry",
        "dataHexButton",
        "dataDecimalButton",
        "dataCharButton",
    ]

    operand = None

    def __init__(self, viewModel, indices, region):
        super(ImmediatePopover, self).__init__()
        self.init_template()
        for child in ImmediatePopover.__gtemplate_children__:
            setattr(self, child, self.get_template_child(ImmediatePopover, child))

        self.get_child().show_all()
        self.viewModel = viewModel
        self.indices = indices
        self.operand = region.meta

    def update(self, region):
        if region.kind != RegionKind.IMM:
            raise Exception("immediate popover for non-immediate")
        self.operand = region.meta

        groupName = next(name for name in KIND_GROUPS if self.operand.kind in KIND_GROUPS[name])
        self.detailSettings.set_property("visible-child-name", groupName)

        operandKind = self.operand.kind
        self.nameEntry.set_text(region.text)
        self.globalButton.set_property("active", operandKind == OperandKind.ADDR)
        self.cstrButton.set_property("active", operandKind == OperandKind.ADDR_CSTR)
        self.stackframeButton.set_property("active", operandKind == OperandKind.STACKFRAME)
        self.dataHexButton.set_property("active", operandKind == OperandKind.IMM_HEX)
        self.dataDecimalButton.set_property("active", operandKind == OperandKind.IMM_SDEC)
        self.dataCharButton.set_property("active", operandKind == OperandKind.IMM_CHAR)

    def on_stack_switch(self, stack, paramName):
        name = stack.get_property("visible-child-name")
        if self.operand and self.operand.kind not in KIND_GROUPS[name]:
            self.viewModel.set_operand_kind(self.indices, self.operand, KIND_GROUPS[name][0])

    def on_radio_button_clicked(self, button):
        mapping = {
            self.dataHexButton: OperandKind.IMM_HEX,
            self.dataDecimalButton: OperandKind.IMM_SDEC,
            self.dataCharButton: OperandKind.IMM_CHAR,
            self.globalButton: OperandKind.ADDR,
            self.cstrButton: OperandKind.ADDR_CSTR,
            self.stackframeButton: OperandKind.STACKFRAME,
        }
        kind = mapping[button]
        self.viewModel.set_operand_kind(self.indices, self.operand, kind)

    def on_name_button_clicked(self, nameButton):
        self.popdown()
        self.viewModel.set_operand_name(self.indices, self.operand, self.nameEntry.get_text())
        # self.viewModel.rename_basic_block(self.index, self.nameEntry.get_text())

    @staticmethod
    def _connect_func(builder, obj, signalName, handlerName, connectObject, flags, cls):
        templateInst = builder.get_object(cls.__gtype_name__)
        obj.connect(signalName, getattr(templateInst, handlerName))

ImmediatePopover.set_template_from_resource("/org/lwd/LWD/immediate-popover.ui")
ImmediatePopover.set_connect_func(ImmediatePopover._connect_func, ImmediatePopover)
for child in ImmediatePopover.__gtemplate_children__:
    ImmediatePopover.bind_template_child_full(child, True, 0)
