"""
core/formatter.py — Output Formatter
"""

_ANSI = {
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "cyan":   "\033[36m",
    "reset":  "\033[0m",
}

_SOURCE_COLOR = {
    "Binary":    "green",
    "libc.so":   "yellow",
    "Not Found": "red",
}

_COL_GADGET  = "Gadget"
_COL_SOURCE  = "Found In"
_COL_ADDRESS = "Address / Offset"


def print_table(binary_path, results):
    w_gadget  = max(len(_COL_GADGET),  max((len(r["gadget"])                   for r in results), default=0))
    w_source  = max(len(_COL_SOURCE),  max((len(r["source"])                   for r in results), default=0))
    w_address = max(len(_COL_ADDRESS), max((len(format_address(r["address"]))  for r in results), default=0))

    sep = "-" * (w_gadget + w_source + w_address + 10)

    print(f"\n[+] Analysis for: {binary_path}")
    print(sep)
    print(f"  {_COL_GADGET:<{w_gadget}}  |  {_COL_SOURCE:<{w_source}}  |  {_COL_ADDRESS:<{w_address}}")
    print(sep)

    for r in results:
        gadget  = r["gadget"]
        source  = r["source"]
        address = format_address(r["address"])
        color   = _SOURCE_COLOR.get(source, "reset")

        colored_source  = colorize(f"{source:<{w_source}}", color)
        colored_address = colorize(f"{address:<{w_address}}", color)

        print(f"  {gadget:<{w_gadget}}  |  {colored_source}  |  {colored_address}")

    print(sep)


def format_address(address):
    if address is None:
        return "-"
    return f"0x{address:08x}"


def colorize(text, color):
    code = _ANSI.get(color)
    if code is None:
        return text
    return f"{code}{text}{_ANSI['reset']}"
