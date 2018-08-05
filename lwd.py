#!/usr/bin/env python3

import os.path
import sys

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gio, Gtk, Gdk

base_path = os.path.abspath(os.path.dirname(__file__))
resource_path = os.path.join(base_path, 'data/org.lwd.LWD.gresource')
resource = Gio.Resource.load(resource_path)._register()

import lwd

if __name__ == "__main__":
    style_provider = Gtk.CssProvider()
    style_provider.load_from_resource("/org/lwd/LWD/lwd.css")

    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        style_provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
    sys.exit(lwd.main())
