# ExportDecompiled.py
# Exports decompiled C code for all functions in the binary.
# Usage: analyzeHeadless <project> <process> -import <file> -postScript ExportDecompiled.py <output_file>

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os

def run():
    program = currentProgram
    decomplib = DecompInterface()
    decomplib.openProgram(program)
    
    # Get output path from args
    args = getScriptArgs()
    if len(args) > 0:
        out_path = args[0]
        # If arg is a directory, append the filename
        if os.path.isdir(out_path):
            out_path = os.path.join(out_path, program.getName() + ".c")
    else:
        # Default to current dir / <filename>.c
        out_path = os.path.join(os.getcwd(), program.getName() + ".c")

    print("Exporting decompiled code to: " + out_path)

    fm = program.getFunctionManager()
    funcs = fm.getFunctions(True)
    
    try:
        with open(out_path, "w") as f:
            # Header
            f.write("// Decompiled by Ghidra - Driver Analyzer AI\n")
            f.write("// Source: " + program.getName() + "\n\n")

            for func in funcs:
                # Decompile
                monitor = ConsoleTaskMonitor()
                res = decomplib.decompileFunction(func, 60, monitor)
                if res.decompileCompleted():
                    c_code = res.getDecompiledFunction().getC()
                    f.write(c_code)
                    f.write("\n")
        print("Export complete.")
    except Exception as e:
        print("Error exporting: " + str(e))

if __name__ == "__main__":
    run()
