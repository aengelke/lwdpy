#!/usr/bin/env python3

import argparse
import pickle
import os.path
import sys

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import GObject, GLib, Gio, Gtk, Gdk

base_path = os.path.abspath(os.path.dirname(__file__))
resource_path = os.path.join(base_path, '../data/org.lwd.LWD.gresource')
resource = Gio.Resource.load(resource_path)._register()

from model import Model
from viewmodel import FunctionTableViewModel
from cfgView import CFGView


class Window2(object):
    def __init__(self, model):
        self.model = model

        self.functionTableViewModel = FunctionTableViewModel(model)
        self.functionTableViewModel.connect("function-changed", self.cfg_show_function)

        builder = Gtk.Builder()
        builder.add_from_resource("/org/lwd/LWD/window.ui")
        builder.connect_signals({
            "windowDestroy": Gtk.main_quit,
            "treeViewSelectionChanged": self.functionTableViewModel.on_selection_changed,
        })

        self.gtk = builder.get_object("window")

        # CFG view
        self.graphBin = builder.get_object("graphBin")
        self.treeView = builder.get_object("treeView")
        self.treeView.set_property("model", self.functionTableViewModel.get_tree_store())
        builder.get_object("column1").add_attribute(builder.get_object("renderer1"), "text", 0)
        builder.get_object("column2").add_attribute(builder.get_object("renderer2"), "text", 1)

        self.gtk.show_all()

    def cfg_show_function(self, viewModel, address):
        current = self.graphBin.get_child()
        if current:
            current.destroy()

        if address:
            self.cfgView = CFGView(self.model, address)
            self.cfgView.show_all()
            self.graphBin.add(self.cfgView)



def main():
    parser = argparse.ArgumentParser(description="lwd")
    parser.add_argument("file", nargs=1, type=str)
    parser.add_argument("symbols", nargs='*')
    options = parser.parse_args()

    fileName = options.file[0]
    pickleFile = fileName + ".pickle"

    model = None
    # if os.path.isfile(pickleFile):
    #     with open(pickleFile, "rb") as f:
    #         model = pickle.load(f)

    if not model:
        with open(fileName, "rb") as f:
            binaryFile = f.read()
        model = Model(binaryFile)
        for sym in options.symbols:
            # try:
            model.get_function(sym)
            # except Exception as e:
            #     print("Cannot parse", sym, e)
        # model.functions.sort(key=lambda f: f.address)

    # m2 = Model(model.binaryFile)
    # print(m2.get_function(options.symbols[0]))
    # print(m2)

    style_provider = Gtk.CssProvider()
    style_provider.load_from_resource("/org/lwd/LWD/lwd.css")

    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        style_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )

    # TODO: Use Gtk.Application
    wnd = Window2(model)

    Gtk.main()

    with open(pickleFile, "wb") as f:
        pickle.dump(model, f)

    return 0

if __name__ == "__main__":
    sys.exit(main())
