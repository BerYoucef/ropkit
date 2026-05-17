"""
core/resolver.py — Dependency Resolver

Responsibility: Run ldd on the binary, parse its output, and return a clean
map of library names to absolute paths. Knows nothing about ELF internals,
gadgets, or Capstone.
"""

import re
import subprocess


def resolve_libraries(binary_path):
    """
    Run ldd on the binary and return a map of library names to absolute paths.

    Args:
        binary_path (str): Path to the target ELF binary.

    Returns:
        dict[str, str]: Maps short library names to absolute paths, e.g.
                        {"libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6"}.
                        Returns an empty dict if ldd fails or is unavailable.
    """
    try:
        raw = run_ldd(binary_path)
    except RuntimeError:
        return {}

    library_map = {}

    # Each ldd line of interest looks like:
    #   libname.so.N => /absolute/path/to/libname.so.N (0xaddress)
    # Virtual entries (linux-vdso.so, ld-linux.so with no '=>') are skipped
    # because they have no real path on disk.
    pattern = re.compile(r"^\s*(\S+)\s+=>\s+(/\S+)\s+\(0x[0-9a-f]+\)", re.IGNORECASE)

    for line in raw.splitlines():
        match = pattern.match(line)
        if match:
            name, path = match.group(1), match.group(2)
            library_map[name] = path

    return library_map


def get_libc_path(library_map):
    """
    Extract the absolute path of libc from the library map.

    Args:
        library_map (dict[str, str]): Output of resolve_libraries().

    Returns:
        str | None: Absolute path of libc, or None if not present.
    """
    for name, path in library_map.items():
        if name.startswith("libc.so"):
            return path
    return None


def run_ldd(binary_path):
    """
    Execute ldd against the binary and return its raw stdout.

    Args:
        binary_path (str): Path to the target binary.

    Returns:
        str: Raw stdout of the ldd command.

    Raises:
        RuntimeError: If ldd exits non-zero or reports a static binary.
    """
    result = subprocess.run(
        ["ldd", binary_path],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"ldd exited with code {result.returncode}: {result.stderr.strip()}"
        )

    if "not a dynamic executable" in result.stdout:
        raise RuntimeError(f"'{binary_path}' is a static binary — ldd found no dynamic dependencies.")

    return result.stdout