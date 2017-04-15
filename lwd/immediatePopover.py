
from gi.repository import Gtk

from model import OperandKind, RegionKind


class ImmediatePopover(Gtk.Popover):
    __gtype_name__ = "LWImmediatePopover"
    __gtemplate_children__ = [
        "addressButton",
        "addressSettings",
        "dataSettings",
        "cstrButton",
        "dataHexButton",
        "dataDecimalButton",
        "dataCharButton",
    ]

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
        isAddress = OperandKind.isAddress(self.operand.kind)

        self.addressSettings.set_property("visible", isAddress)
        self.dataSettings.set_property("visible", not isAddress)
        self.addressButton.set_property("active", isAddress)

        operandKind = self.operand.kind
        self.cstrButton.set_property("active", operandKind == OperandKind.ADDR_CSTR)
        self.dataHexButton.set_property("active", operandKind == OperandKind.IMM_HEX)
        self.dataDecimalButton.set_property("active", operandKind == OperandKind.IMM_SDEC)
        self.dataCharButton.set_property("active", operandKind == OperandKind.IMM_CHAR)

    def on_radio_button_clicked(self, button):
        mapping = {
            self.dataHexButton: OperandKind.IMM_HEX,
            self.dataDecimalButton: OperandKind.IMM_SDEC,
            self.dataCharButton: OperandKind.IMM_CHAR,
        }
        kind = mapping[button]
        self.viewModel.set_operand_kind(self.indices, self.operand, kind)

    def on_check_button_clicked(self, button):
        mapping = {
            self.addressButton: (OperandKind.ADDR, OperandKind.IMM_HEX),
            self.cstrButton: (OperandKind.ADDR_CSTR, OperandKind.ADDR),
        }
        kind = mapping[button][1 if button.get_property("active") else 0]
        self.viewModel.set_operand_kind(self.indices, self.operand, kind)


    @staticmethod
    def _connect_func(builder, obj, signalName, handlerName, connectObject, flags, cls):
        templateInst = builder.get_object(cls.__gtype_name__)
        obj.connect(signalName, getattr(templateInst, handlerName))

ImmediatePopover.set_template_from_resource("/org/lwd/LWD/immediate-popover.ui")
ImmediatePopover.set_connect_func(ImmediatePopover._connect_func, ImmediatePopover)
for child in ImmediatePopover.__gtemplate_children__:
    ImmediatePopover.bind_template_child_full(child, True, 0)
