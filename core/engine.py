"""
core/engine.py — Gadget Engine

Responsibility: Own the entire gadget search algorithm and the default gadget
list. Receives section data from the parser's output and a libc path from the
resolver's output, runs the full two-pass search, and returns a unified result
list. This is the only module that uses Capstone.
"""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from core.parser import parse_elf


# ---------------------------------------------------------------------------
# Gadget targets
# ---------------------------------------------------------------------------

GADGET_LIST = [
    "pop rdi ; ret",
    "pop rsi ; ret",
    "pop rdx ; ret",
    "pop rcx ; ret",
    "xor rax, rax ; ret",
    "pop rax ; ret",
    "syscall ; ret",
    "syscall",
    "ret",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_gadgets(sections, libc_path, max_depth=10):
    """
    Search for every gadget in GADGET_LIST across the binary and, if needed,
    libc — in that priority order.

    Args:
        sections  (list[dict]): Output of parser.parse_elf() on the binary.
        libc_path (str | None): Absolute path to libc, or None.
        max_depth (int):        Backward window depth forwarded from parse_args().

    Returns:
        list[dict]: One dict per gadget in GADGET_LIST:
            gadget  (str)      -- the pattern string
            source  (str)      -- "Binary", "libc.so", or "Not Found"
            address (int|None) -- virtual address if found, else None
    """
    results = []
    remaining = list(GADGET_LIST)  # patterns not yet found

    # --- Pass 1: search the binary sections ---
    found = _sweep_sections(sections, remaining, max_depth)

    for gadget in GADGET_LIST:
        if gadget in found:
            results.append({"gadget": gadget, "source": "Binary", "address": found[gadget]})
        else:
            remaining.append(gadget) if gadget not in remaining else None

    # rebuild remaining as gadgets missing after pass 1
    remaining = [g for g in GADGET_LIST if g not in found]

    # --- Pass 2: fall back to libc for anything still missing ---
    if remaining and libc_path is not None:
        libc_sections = parse_elf(libc_path)
        libc_found = _sweep_sections(libc_sections, remaining, max_depth)

        for gadget in remaining:
            if gadget in libc_found:
                results.append({"gadget": gadget, "source": "libc.so", "address": libc_found[gadget]})
            else:
                results.append({"gadget": gadget, "source": "Not Found", "address": None})
    else:
        for gadget in remaining:
            results.append({"gadget": gadget, "source": "Not Found", "address": None})

    # Return in GADGET_LIST order regardless of discovery order.
    order = {g: i for i, g in enumerate(GADGET_LIST)}
    results.sort(key=lambda r: order[r["gadget"]])

    return results


# ---------------------------------------------------------------------------
# Search internals
# ---------------------------------------------------------------------------

def _sweep_sections(sections, gadget_list, max_depth):
    """
    Run linear_sweep over every section, accumulating results.

    Returns a combined dict[str, int] of all found gadgets across all sections.
    Stops searching for a gadget the moment it is first found in any section.
    """
    found = {}
    for section in sections:
        remaining = [g for g in gadget_list if g not in found]
        if not remaining:
            break
        hits = linear_sweep(section["data"], section["base_addr"], remaining, max_depth)
        found.update(hits)
    return found


def linear_sweep(data, base_addr, gadget_list, max_depth):
    """
    Sweep every byte offset in data looking for gadget-terminating sequences.

    Args:
        data       (bytes):     Raw bytes of a single executable section.
        base_addr  (int):       Virtual address of data[0].
        gadget_list (list[str]): Patterns not yet found.
        max_depth  (int):       Maximum backward window size in bytes.

    Returns:
        dict[str, int]: Maps found pattern strings to their virtual addresses.
    """
    terminators = get_terminators()
    found = {}
    remaining = list(gadget_list)

    for offset in range(len(data)):
        if not remaining:
            break

        # Check whether a terminator starts at this offset.
        terminator_len = _match_terminator(data, offset, terminators)
        if terminator_len == 0:
            continue

        # Try windows of increasing size before the terminator.
        for window in backward_slice(data, offset, max_depth, terminator_len):
            disassembled = disassemble_chain(window, base_addr + (offset - (len(window) - terminator_len)))
            if disassembled is None:
                continue

            matched = match_gadget(disassembled, remaining)
            if matched is not None:
                gadget_addr = base_addr + (offset - (len(window) - terminator_len))
                found[matched] = gadget_addr
                remaining.remove(matched)
                break  # move on; one match per terminator occurrence is enough

    return found


def get_terminators():
    """
    Return the byte sequences that mark valid gadget chain endings.

    Returns:
        list[bytes]: e.g. [b'\\xc3', b'\\x0f\\x05']
            0xc3       = ret
            0x0f 0x05  = syscall
    """
    return [b"\xc3", b"\x0f\x05"]


def backward_slice(data, offset, depth, terminator_len):
    """
    Generate candidate byte windows ending at the terminator, shortest first.

    Args:
        data           (bytes): Full section byte array.
        offset         (int):   Index of the terminator's first byte in data.
        depth          (int):   Maximum bytes to look back before the terminator.
        terminator_len (int):   Byte length of the terminator instruction.

    Returns:
        list[bytes]: Windows ordered shortest-first; each is
                     data[offset - n : offset + terminator_len] for n in 1..depth.
    """
    windows = []
    for n in range(1, depth + 1):
        start = offset - n
        if start < 0:
            break
        windows.append(data[start : offset + terminator_len])
    return windows


def disassemble_chain(byte_window, base_addr):
    """
    Disassemble byte_window and validate it as a legal gadget chain.

    Validation rules:
        1. Full consumption  — decoded bytes == len(byte_window)
        2. No invalid insns  — no unrecognised opcodes
        3. No unwanted flow  — no jmp / call / int3 / conditional jumps before terminator
        4. Valid terminator  — last instruction is ret or syscall

    Args:
        byte_window (bytes): Candidate instruction sequence.
        base_addr   (int):   Virtual address of byte_window[0] for Capstone.

    Returns:
        str | None: Normalised gadget string like "pop rdi ; ret", or None.
    """
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = False

    instructions = list(cs.disasm(byte_window, base_addr))

    if not instructions:
        return None

    # Rule 1: full consumption.
    total_bytes = sum(i.size for i in instructions)
    if total_bytes != len(byte_window):
        return None

    # Rule 2 & 3: scan all but the last instruction for invalid/unwanted ops.
    _BLOCKED = {"jmp", "call", "int3", "jo", "jno", "jb", "jnb", "jz", "jnz",
                "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg",
                "je", "jne", "jc", "jnc"}

    for insn in instructions[:-1]:
        if insn.id == 0:          # CS_OP_INVALID
            return None
        if insn.mnemonic in _BLOCKED:
            return None

    # Rule 4: last instruction must be ret or syscall.
    last = instructions[-1]
    if last.mnemonic not in ("ret", "syscall"):
        return None

    # Build the normalised string.
    parts = []
    for insn in instructions:
        text = insn.mnemonic
        if insn.op_str:
            text += " " + insn.op_str
        parts.append(text.strip())

    return " ; ".join(parts)


def match_gadget(disassembled_str, gadget_list):
    """
    Return the first pattern in gadget_list that matches disassembled_str.

    Comparison is case-insensitive and strips surrounding whitespace.

    Args:
        disassembled_str (str):       Output of disassemble_chain().
        gadget_list      (list[str]): Patterns to match against.

    Returns:
        str | None: The matching pattern, or None.
    """
    normalised = disassembled_str.strip().lower()
    for pattern in gadget_list:
        if normalised == pattern.strip().lower():
            return pattern
    return None


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _match_terminator(data, offset, terminators):
    """
    Return the byte length of the terminator starting at data[offset], or 0.
    """
    for t in terminators:
        end = offset + len(t)
        if end <= len(data) and data[offset:end] == t:
            return len(t)
    return 0