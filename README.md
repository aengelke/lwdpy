## Lightweight Disassembler

**This code is deprecated and not maintained. The code was last tested in April 2017. There are no guarantees that the code still works. The code is (partly) ugly, the implementation is slow and leaking large amounts of memory. The repository has the sole purpose of publishing this code, because somebody found parts of the code useful and needs to cite it.**

### Features
- CFG disassembly
- Register highlighting on focus
- Inline display of C-Strings
- Automatic save and reload of edited sections
- ... and probably more to come.

LWD misses, and will ever miss, *lots* of features. Otherwise, it wouldn't be called light-weight.

### Why another disassembler?
In contrast to other full-featured disassemblers, LWD has slightly different goals:

- Good and intuitive usability, as opposed to the R2 terminal interface;
- Light-weight, i.e. it works on my laptop without draining the battery, as opposed to the R2 web interface;
- Has a CFG disassembly, as opposed to objdump; and
- Is free (like objdump), as opposed to almost all (good) disassemblers like IDA.

### Requirements
Pyelftools, Capstone, Graphviz, Gtk+ 3.22 (might work on earlier versions, too)
