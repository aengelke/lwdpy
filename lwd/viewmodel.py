
from collections import namedtuple

import graphviz
from gi.repository import GLib, GObject, Gtk

from lwd import profile
from lwd.model import OperandKind, OperandType

class FunctionTableViewModel(GObject.GObject):
    __gsignals__ = {
        "function-changed": (GObject.SignalFlags.RUN_FIRST, None, (int,)),
    }

    def __init__(self, model):
        super(FunctionTableViewModel, self).__init__()
        self.model = model
        self.selection = None
        self.treeStore = Gtk.ListStore(str, str, int)
        self.model.connect("name-changed", self.update)
        self.update()

    def get_tree_store(self):
        return self.treeStore

    def update(self, *args):
        newFunctions = self.model.get_functions()
        newFunctions.sort(key=lambda fn: fn[0])

        treeIter = self.treeStore.get_iter_first()
        for address, name in newFunctions:
            append = True
            while treeIter:
                currentAddress = self.treeStore.get_value(treeIter, 2)
                if currentAddress < address:
                    self.treeStore.remove(treeIter)
                    continue
                append = False
                if currentAddress == address:
                    self.treeStore.set(treeIter, 0, name)
                    treeIter = self.treeStore.iter_next(treeIter)
                    break
                if currentAddress > address:
                    self.treeStore.insert_before(treeIter, [name, hex(address), address])
                    break
            if append: # We are at the end
                self.treeStore.append([name, hex(address), address])

    def on_selection_changed(self, selection):
        _, treeIter = selection.get_selected()
        newSelection = self.treeStore[treeIter][2] if treeIter else None
        if self.selection != newSelection:
            self.selection = newSelection
            self.emit("function-changed", newSelection)

BasicBlockViewModel = namedtuple("BasicBlockViewModel", "name,instructions,data")
InstructionViewModel = namedtuple("InstructionViewModel", "address,mnemonic,regions,comment")

class CFGViewModel(GObject.GObject):
    __gsignals__ = {
        # Emitted when the whole view has to be rebuilt
        # Arguments: List of basic blocks
        "cfg-changed": (GObject.SignalFlags.RUN_FIRST, None, (GObject.TYPE_PYOBJECT,)),

        # Emitted when the text of the instructions or the labels changed, but
        # no deeper change is required
        # Arguments: List of basic blocks
        "text-changed": (GObject.SignalFlags.RUN_FIRST, None, (GObject.TYPE_PYOBJECT,)),

        # Emitted when the highlighting of regions is updated
        # Arguments: List of lists of lists of bools
        "highlight-changed": (GObject.SignalFlags.RUN_FIRST, None, (GObject.TYPE_PYOBJECT,)),

        # Emitted when new basic block positions are available
        # Arguments: Total size, list of coordinates and list of edges
        "layout-changed": (GObject.SignalFlags.RUN_FIRST, None, (GObject.TYPE_PYOBJECT, GObject.TYPE_PYOBJECT, GObject.TYPE_PYOBJECT)),
    }

    def __init__(self, model, address):
        super(CFGViewModel, self).__init__()
        self.model = model
        self.address = address
        self.function = None
        self.basicBlockPositions = []
        self.basicBlockAddresses = []
        self.basicBlockViews = []
        self.layoutTimeout = None
        self.sig1 = self.model.connect("name-changed", self.on_name_changed, True)
        self.sig2 = self.model.connect("instruction-changed", self.on_name_changed, False)
        self.sig3 = self.model.connect("cfg-changed", self.on_cfg_changed)

    def destroy(self):
        if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
        self.model.disconnect(self.sig1)
        self.model.disconnect(self.sig2)
        self.model.disconnect(self.sig3)

    def init(self):
        self.function = self.model.get_function(self.address)
        self.basicBlockPositions = [
            [-1000, -1000, 0, 0] for _ in self.function.basicBlocks
        ]
        self.basicBlockAddresses = [bb.address for bb in self.function.basicBlocks]
        GLib.idle_add(self.update_texts, "cfg-changed")

    def on_name_changed(self, model, address, fullUpdate):
        # If address is -1, more than one instruction changed.
        fullUpdate = fullUpdate or address == -1
        print(fullUpdate)
        GLib.idle_add(self.update_texts)

    def on_cfg_changed(self, model):
        self.init()

    @profile
    def update_texts(self, signalName="text-changed"):
        print("CFG UPText")
        self.basicBlockViews = []
        for basicBlock in self.function.basicBlocks:
            instructionViews = []
            for instr in basicBlock.instructions:
                # This computes auto comment as well
                regions = self.model.regionize_instruction(self.function, instr)
                comment = instr.userComment
                if comment and instr.autoComment:
                    comment += " | "
                comment += instr.autoComment
                comment = "; " + comment
                instructionViews.append(InstructionViewModel(instr.address, instr.mnemonic, regions, comment))
            name = self.model.get_name(basicBlock.address)
            self.basicBlockViews.append(BasicBlockViewModel(name, instructionViews, basicBlock.data))
        self.emit(signalName, self.basicBlockViews)

    def _is_highlighted(self, region, highlightedRegion):
        # TODO: Do better highlighting of equal regions.
        return region == highlightedRegion

    def set_highlight_region(self, highlightRegion):
        highlight = [[[self._is_highlighted(region, highlightRegion) \
                        for region in instr.regions] \
                        for instr in bb.instructions] \
                        for bb in self.basicBlockViews]
        self.emit("highlight-changed", highlight)

    @profile
    def layout(self):
        print("Relayout")
        bbMap = {}
        graph = graphviz.Digraph()
        graph.attr("graph", nodesep="20")
        graph.attr("graph", ranksep="20")
        for index, basicBlock in enumerate(self.function.basicBlocks):
            position = self.basicBlockPositions[index]
            nodeArgs = {
                "width": str(position[2]),
                "height": str(position[3]),
                "shape": "rectangle"
            }
            graph.node(str(index), **nodeArgs)
            for succName in basicBlock.successors:
                targetIndex = self.basicBlockAddresses.index(basicBlock.successors[succName])
                graph.edge(str(index), str(targetIndex), label=succName)

        rendered = [x.split() for x in graph.pipe("plain").decode().split("\n")[:-1]]

        totalSize = tuple(map(int, map(float, (rendered[0][2:4]))))
        nodes = {int(x[1]): (float(x[2]), float(x[3])) for x in rendered if x[0] == "node"}
        edges = [x for x in rendered if x[0] == "edge"]

        for index, position in enumerate(self.basicBlockPositions):
            cx, cy = nodes[index]
            position[0] = int(cx) - position[2] / 2
            position[1] = totalSize[1] - int(cy) - position[3] / 2

        positions = [(p[0], p[1]) for p in self.basicBlockPositions]

        self.layoutTimeout = None
        self.emit("layout-changed", totalSize, positions, edges)

    def rename_basic_block(self, index, newName):
        self.model.rename(self.function.basicBlocks[index].address, newName)

    def set_operand_name(self, indices, operand, newName):
        value = None
        if operand.type == OperandType.MEM:
            value = operand.mem.disp
        elif operand.type == OperandType.IMM:
            value = operand.imm
        else:
            return

        if operand.kind == OperandKind.STACKFRAME:
            self.function.data.set_stackframe_name(value, newName)
        elif operand.kind.isaddress:
            self.model.rename(value, newName)

    def set_function_property(self, name, value):
        if name == "noreturn":
            self.function.data.noreturn = value
        # if name == "noreturn":
        #     self.model.set_attribute(self.basicBlockAddresses[index], name, value)

    def set_operand_kind(self, indices, operand, kind):
        bbIndex, instrIndex, regionIndex = indices
        instr = self.function.basicBlocks[bbIndex].instructions[instrIndex]
        operandIndex = instr.operands.index(operand)
        self.model.set_operand_kind(instr.address, operandIndex, kind)

    @profile
    def on_size_updated(self, index, width, height):
        position = self.basicBlockPositions[index]
        if position[2] != width or position[3] != height:
            position[2], position[3] = width, height
            if self.layoutTimeout: GLib.source_remove(self.layoutTimeout)
            self.layoutTimeout = GLib.timeout_add(10, self.layout)
