#!/usr/bin/env python3
"""
ropkit.py — Entry Point

Pure orchestrator. Reads CLI args, calls each module in order,
passes the output of one as the input to the next. Zero business logic.
"""

import argparse
import itertools
import sys
import threading
import time

from core import parser, resolver, engine, formatter


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class Spinner:
    """
    Displays an animated spinner with a status message on stderr.
    Runs in a background thread so it never blocks the main pipeline.
    """

    _FRAMES = ["●○○○", "○●○○", "○○●○", "○○○●", "○○●○", "○●○○"]

    def __init__(self, message):
        self._message = message
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self, final_message=None):
        self._stop_event.set()
        self._thread.join()
        # Clear the spinner line, print final status.
        sys.stderr.write("\r\033[K")
        if final_message:
            sys.stderr.write(f"{final_message}\n")
        sys.stderr.flush()

    def _spin(self):
        for frame in itertools.cycle(self._FRAMES):
            if self._stop_event.is_set():
                break
            sys.stderr.write(f"\r  {frame}   {self._message}")
            sys.stderr.flush()
            time.sleep(0.15)

    # Context-manager support: `with Spinner("...") as s:`
    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    arg_parser = argparse.ArgumentParser(
        prog="ropkit",
        description="ROP gadget finder for ELF binaries.",
    )
    arg_parser.add_argument("binary", help="Path to the target ELF binary.")
    arg_parser.add_argument(
        "--depth",
        type=int,
        default=10,
        metavar="N",
        help="Backward window depth for gadget search (default: 10). Must be > 0.",
    )

    args = arg_parser.parse_args()

    if args.depth <= 0:
        arg_parser.error("--depth must be a positive integer greater than zero.")

    return args


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    # Stage 1: Parse ELF.
    with Spinner("Parsing ELF sections..."):
        try:
            sections = parser.parse_elf(args.binary)
        except FileNotFoundError:
            sys.stderr.write("\r\033[K")
            print(f"[!] Error: binary not found: {args.binary}", file=sys.stderr)
            sys.exit(1)
        except ValueError as exc:
            sys.stderr.write("\r\033[K")
            print(f"[!] Error: invalid ELF file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Stage 2: Resolve libraries.
    with Spinner("Resolving shared libraries..."):
        library_map = resolver.resolve_libraries(args.binary)

    # Stage 3: Extract libc path.
    libc_path = resolver.get_libc_path(library_map)

    # Stage 4: Search for gadgets.
    libc_note = f"  (libc fallback: {libc_path})" if libc_path else ""
    with Spinner(f"Scanning for ROP gadgets...{libc_note}"):
        results = engine.find_gadgets(sections, libc_path, args.depth)

    # Stage 5: Print results.
    formatter.print_table(args.binary, results)


if __name__ == "__main__":
    main()