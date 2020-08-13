# Ghidra YSC

Ghidra Processor and Loader for YSC script format.

The project allows you to decompile/disassemble/reverse engineer YSC script files. 

It's able to properly identify branches, switch structures, function calls, local variables, static variables, etc.

![](https://i.imgur.com/5z9wIKb.png)

## Compilation

To build the extension manually, install `gradle` and run

   gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra
   
## Usage 

Follow the installation like described in the [Ghidra docs](https://ghidra-sre.org/InstallationGuide.html#Extensions). 

To load a ysc file, export a ysc.full file from OpenIV or similar, and open it in Ghidra. It should then suggest YSC Loader and YSC Language for the project.

## TODO

- Struct analysis
- Implement unimplemented instructions
- Improve documentation for opcodes
- A way to share global variable definitions across multiple script files. Also common signatures for script files would be handy.
- Native Function Analysis (mostly naming natives and setting arguments properly).
- Function Analysis
- Improve cspec default call prototype (so that the arguments aren't reversed).
