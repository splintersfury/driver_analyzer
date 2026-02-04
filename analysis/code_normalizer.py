"""
Code normalizer for decompiled output.
Strips address-specific patterns to enable meaningful diffs.
"""

import re
from typing import Dict


def normalize_decompiled_code(code: str) -> str:
    """
    Normalize Ghidra decompiled code for diffing.

    Replaces address-specific patterns:
    - DAT_14xxx -> GLOBAL
    - FUN_14xxx -> FUNC
    - LAB_14xxx -> LABEL
    - local_xxx -> LOCAL_VAR
    - param_xxx -> PARAM
    - 0x14xxxxxxxx -> ADDR
    """
    normalized = code

    # Global data references: DAT_140001234 -> GLOBAL
    normalized = re.sub(r'\bDAT_[0-9a-fA-F]{8,16}\b', 'GLOBAL', normalized)

    # Function references: FUN_140001234 -> FUNC
    normalized = re.sub(r'\bFUN_[0-9a-fA-F]{8,16}\b', 'FUNC', normalized)

    # Labels: LAB_140001234 -> LABEL
    normalized = re.sub(r'\bLAB_[0-9a-fA-F]{8,16}\b', 'LABEL', normalized)

    # Local variables: local_xx -> LOCAL_VAR
    normalized = re.sub(r'\blocal_[0-9a-fA-F]+\b', 'LOCAL_VAR', normalized)

    # Parameters: param_x -> PARAM
    normalized = re.sub(r'\bparam_\d+\b', 'PARAM', normalized)

    # Raw addresses: 0x140001234 -> ADDR
    normalized = re.sub(r'\b0x[0-9a-fA-F]{8,16}\b', 'ADDR', normalized)

    # Stack offsets: Stack[-0x10] -> Stack[OFFSET]
    normalized = re.sub(r'Stack\[-?0x[0-9a-fA-F]+\]', 'Stack[OFFSET]', normalized)

    # Undefined types: undefined8, undefined4 -> UNDEF
    normalized = re.sub(r'\bundefined[0-9]*\b', 'UNDEF', normalized)

    return normalized


def parse_decompiled_functions(file_path: str) -> Dict[str, str]:
    """
    Parse decompiled C file into function name -> code dict.

    Expects Ghidra export format with:
    // FUNCTION_START: function_name
    ... function code ...
    // FUNCTION_END: function_name

    Returns dict mapping function names to their code.
    """
    functions = {}
    current_func = None
    current_code = []

    with open(file_path, 'r', errors='replace') as f:
        for line in f:
            # Check for function start marker
            if line.strip().startswith('// FUNCTION_START:'):
                func_name = line.strip().split(':', 1)[1].strip()
                current_func = func_name
                current_code = []

            # Check for function end marker
            elif line.strip().startswith('// FUNCTION_END:'):
                if current_func:
                    functions[current_func] = ''.join(current_code)
                current_func = None
                current_code = []

            # Accumulate function code
            elif current_func:
                current_code.append(line)

    # If no markers found, try to parse as raw function definitions
    if not functions:
        functions = _parse_raw_functions(file_path)

    return functions


def _parse_raw_functions(file_path: str) -> Dict[str, str]:
    """
    Parse functions from raw decompiled output without markers.
    Looks for function definitions like: returntype funcname(params) {
    """
    functions = {}

    with open(file_path, 'r', errors='replace') as f:
        content = f.read()

    # Pattern to match function definitions
    # Matches: type name(params) { ... }
    func_pattern = re.compile(
        r'(?:^|\n)\s*'
        r'([a-zA-Z_][a-zA-Z0-9_*\s]+?)'  # Return type
        r'\s+([a-zA-Z_][a-zA-Z0-9_]*)'    # Function name
        r'\s*\(([^)]*)\)'                  # Parameters
        r'\s*\{',                          # Opening brace
        re.MULTILINE
    )

    matches = list(func_pattern.finditer(content))

    for i, match in enumerate(matches):
        func_name = match.group(2)
        start = match.start()

        # Find matching closing brace
        brace_count = 0
        end = match.end() - 1  # Position of opening brace

        for j in range(end, len(content)):
            if content[j] == '{':
                brace_count += 1
            elif content[j] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = j + 1
                    break

        functions[func_name] = content[start:end]

    return functions
