## File Structure

```
ropkit/
├── ropkit.py
└── core/
    ├── __init__.py
    ├── parser.py
    ├── engine.py
    ├── resolver.py
    └── formatter.py
```

---

## Data Flow (Pipeline)

```
ropkit.py
    │
    ├─► parse_args()                                      → args
    │
    ├─► parser.parse_elf(args.binary)                     → sections[]
    │
    ├─► resolver.resolve_libraries(args.binary)
    │       └─► resolver.run_ldd()
    │       └─► resolver.get_libc_path()                  → libc_path
    │
    ├─► engine.find_gadgets(sections, libc_path, args.depth)
    │       └─► engine.linear_sweep()
    │               └─► engine.get_terminators()
    │               └─► engine.backward_slice()
    │               └─► engine.disassemble_chain()
    │               └─► engine.match_gadget()             → results[]
    │
    └─► formatter.print_table(args.binary, results)
            └─► formatter.format_address()
            └─► formatter.colorize()
```

**Rule: No module calls another module. Only `ropkit.py` connects them. Every module owns exactly one responsibility.**

---

## `ropkit.py` — Entry Point

**Responsibility:** Pure orchestrator. Reads CLI args, calls each module in order, passes the output of one as the input to the next. Zero business logic lives here.

---

### `parse_args()`

- **Args:** none — reads `sys.argv` internally via `argparse`
- **Returns:** `argparse.Namespace` with:
    - `binary` _(str)_ — path to the target ELF binary
    - `depth` _(int)_ — backward window depth, default `10`
- **Interacts with:** nothing — standalone, no imports from `core/`
- **Description:** Defines and validates all CLI arguments using `argparse`. Prints usage and exits with code `0` if `--help` is passed or `binary` is missing. Validates that `depth` is a positive integer greater than zero. This is the **only place** `sys.argv` is read in the entire project.

---

### `main()`

- **Args:** none
- **Returns:** none
- **Interacts with:** `parse_args()` → `parser.parse_elf()` → `resolver.resolve_libraries()` → `resolver.get_libc_path()` → `engine.find_gadgets()` → `formatter.print_table()`
- **Description:** Calls `parse_args()` to get validated arguments, then passes data down the pipeline in strict order — each function's output becomes the next function's input. Wraps `parse_elf()` in a `try/except` to catch `FileNotFoundError` and `ValueError` (invalid ELF), printing a clean error and exiting with code `1`. Contains no loops, no conditionals beyond error handling, and no business logic.

---

## `core/__init__.py` — Package Init

No functions. Empty file that marks `core/` as a Python package.

---

## `core/parser.py` — ELF Parser

**Responsibility:** Open an ELF file, locate executable sections, return their raw bytes and virtual addresses. Knows nothing about gadgets, searching, or libc.

---

### `parse_elf(binary_path)`

- **Args:**
    - `binary_path` _(str)_ — path to the target ELF binary or `.so` library
- **Returns:** `list[dict]` — one dict per executable section:
    - `name` _(str)_ — section name, e.g. `".text"`
    - `data` _(bytes)_ — raw opcodes of the section
    - `base_addr` _(int)_ — virtual memory start address of the section
- **Interacts with:** `is_executable_section()` — delegates the flag check to it
- **Description:** Opens the file in binary mode and wraps it in `pyelftools.ELFFile`. Iterates over all sections and calls `is_executable_section()` on each. For sections that pass, extracts raw bytes via `.data()` and start address via `section['sh_addr']`. Returns the collected list. Raises `ValueError` if the file is not a valid ELF. This output is passed directly to `engine.find_gadgets()` by `ropkit.py`.

---

### `is_executable_section(section)`

- **Args:**
    - `section` _(elftools.elf.sections.Section)_ — a section object from pyelftools
- **Returns:** `bool`
- **Interacts with:** nothing — pure flag check, no external calls
- **Description:** Reads `section['sh_flags']` and checks whether the `SHF_EXECINSTR` bit (`0x4`) is set using bitwise AND. Returns `True` only if the flag is present. Private helper used exclusively by `parse_elf()`. Isolated so the flag logic can be tested independently.

---

## `core/engine.py` — Gadget Engine

**Responsibility:** Own the entire gadget search algorithm and the default gadget list. Receives section data from the parser's output and a libc path from the resolver's output, runs the full two-pass search, and returns a unified result list. This is the **only module** that uses Capstone.

---

### `GADGET_LIST` _(module-level constant)_

- **Type:** `list[str]`
- **Example values:** `["pop rdi ; ret", "pop rsi ; ret", "pop rdx ; ret", "pop rax ; ret", "syscall ; ret", "syscall", "ret"]`
- **Interacts with:** consumed by `find_gadgets()` as the default search target
- **Description:** The canonical list of gadget patterns the tool searches for. Lives here — not in `ropkit.py` — because it is engine logic, not CLI logic. Centralizing it here means adding a new gadget target requires touching only this file.

---

### `find_gadgets(sections, libc_path, max_depth=10)`

- **Args:**
    - `sections` _(list[dict])_ — output of `parser.parse_elf()` called on the binary
    - `libc_path` _(str | None)_ — absolute path to libc, output of `resolver.get_libc_path()`; `None` if libc was not resolved
    - `max_depth` _(int)_ — backward window depth forwarded from `parse_args()`
- **Returns:** `list[dict]` — one dict per gadget in `GADGET_LIST`:
    - `gadget` _(str)_ — the pattern string
    - `source` _(str)_ — `"Binary"`, `"libc.so"`, or `"Not Found"`
    - `address` _(int | None)_ — virtual address if found, else `None`
- **Interacts with:** `linear_sweep()` for both search passes; calls `parser.parse_elf(libc_path)` internally for the libc fallback pass
- **Description:** **First pass** — calls `linear_sweep()` across every section in `sections`. **Second pass** — for gadgets not found in the binary, and only if `libc_path` is not `None`, calls `parse_elf(libc_path)` to get libc sections then runs `linear_sweep()` on those. This is the **only place** the two-pass (binary → libc) fallback logic lives. Marks each result dict with the correct `source` string. Returns the final list consumed by `formatter.print_table()`.

---

### `linear_sweep(data, base_addr, gadget_list, max_depth)`

- **Args:**
    - `data` _(bytes)_ — raw bytes of a single executable section
    - `base_addr` _(int)_ — virtual address of `data[0]`, used to compute real addresses
    - `gadget_list` _(list[str])_ — patterns not yet found, passed down from `find_gadgets()`
    - `max_depth` _(int)_ — maximum backward window size in bytes
- **Returns:** `dict[str, int]` — maps found gadget pattern strings to their virtual addresses; only contains patterns that were actually matched (missing ones handled by `find_gadgets()`)
- **Interacts with:** `get_terminators()`, `backward_slice()`, `disassemble_chain()`, `match_gadget()`
- **Description:** Iterates over every byte offset in `data`. At each offset, checks whether the bytes match any terminator from `get_terminators()`. On a match, calls `backward_slice()` to generate candidate windows of increasing size, then calls `disassemble_chain()` on each window. If disassembly succeeds, calls `match_gadget()` to check for a pattern match. Stops searching for a gadget once its first occurrence is found. The virtual address of a found gadget is `base_addr + (offset - window_size)`.

---

### `get_terminators()`

- **Args:** none
- **Returns:** `list[bytes]` — e.g. `[b'\xc3', b'\x0f\x05']`
- **Interacts with:** nothing — returns a hardcoded constant
- **Description:** Returns the byte sequences that mark valid gadget chain endings. `0xc3` = `ret`, `0x0f 0x05` = `syscall`. Defined as a function rather than a module constant so new terminators can be added without changing any call sites in `linear_sweep()`.

---

### `backward_slice(data, offset, depth)`

- **Args:**
    - `data` _(bytes)_ — full section byte array
    - `offset` _(int)_ — index of the terminator's first byte within `data`
    - `depth` _(int)_ — maximum number of bytes to look back before the terminator
- **Returns:** `list[bytes]` — candidate windows ordered shortest-first; each window is `data[offset - n : offset + terminator_len]` for n in `1..depth`
- **Interacts with:** nothing — pure slicing, no external calls
- **Description:** For each value of `n` from `1` to `depth`, slices a window starting `n` bytes before `offset` and ending after the terminator. Skips windows where `offset - n < 0` (avoids reading before the section boundary). Returns shortest windows first so `disassemble_chain()` finds minimal gadgets before larger ones. Consumed exclusively by `linear_sweep()`.

---

### `disassemble_chain(byte_window, base_addr)`

- **Args:**
    - `byte_window` _(bytes)_ — candidate instruction sequence ending at a terminator
    - `base_addr` _(int)_ — virtual address of `byte_window[0]`, passed to Capstone for accurate address tracking
- **Returns:** `str | None` — normalized gadget string like `"pop rdi ; ret"`, or `None` if the window fails any validation check
- **Interacts with:** Capstone disassembly engine in x86-64 mode — the only call site for Capstone in the project
- **Description:** Creates a Capstone `Cs` instance (`CS_ARCH_X86`, `CS_MODE_64`) and disassembles `byte_window`. Applies four validation checks: (1) **Full consumption** — total byte size of all decoded instructions equals `len(byte_window)`; (2) **No invalid instructions** — rejects windows containing unrecognized opcodes; (3) **No unwanted control flow** — rejects `jmp`, `call`, `int3`, and conditional jumps anywhere before the terminator; (4) **Valid terminator last** — the final instruction must be `ret` or `syscall`. If all checks pass, joins each instruction's mnemonic and operands with `" ; "` and returns the string. Returns `None` on any failure without raising exceptions.

---

### `match_gadget(disassembled_str, gadget_list)`

- **Args:**
    - `disassembled_str` _(str)_ — output of `disassemble_chain()`, e.g. `"pop rdi ; ret"`
    - `gadget_list` _(list[str])_ — patterns to match against
- **Returns:** `str | None` — the matching pattern from `gadget_list`, or `None`
- **Interacts with:** nothing — pure string comparison, no external calls
- **Description:** Strips and lowercases both `disassembled_str` and each pattern before comparing. Returns the first matching pattern string from `gadget_list`. Isolated as its own function so exact matching can be swapped for regex or fuzzy matching in the future without modifying `linear_sweep()`.

---

## `core/resolver.py` — Dependency Resolver

**Responsibility:** Run `ldd` on the binary, parse its output, and return a clean map of library names to absolute paths. Knows nothing about ELF internals, gadgets, or Capstone.

---

### `resolve_libraries(binary_path)`

- **Args:**
    - `binary_path` _(str)_ — path to the target ELF binary
- **Returns:** `dict[str, str]` — maps short library names to absolute paths, e.g. `{"libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6"}`
- **Interacts with:** `run_ldd()` — calls it to get raw stdout, then parses the result
- **Description:** Calls `run_ldd()` and splits the result into lines. Each `ldd` line follows the pattern `libname => /path/to/lib (0xaddress)`. Parses each line with a regex, extracting the library name and absolute path. Skips virtual entries like `linux-vdso.so` which have no real path on disk. If `run_ldd()` raises `RuntimeError` (static binary or `ldd` not available), catches it and returns an empty dict — the downstream caller handles the missing libc case gracefully.

---

### `get_libc_path(library_map)`

- **Args:**
    - `library_map` _(dict[str, str])_ — output of `resolve_libraries()`
- **Returns:** `str | None` — absolute path of libc, or `None` if absent
- **Interacts with:** nothing — pure dict lookup, no external calls
- **Description:** Iterates over keys in `library_map` and returns the value for the first key starting with `"libc.so"`. Returns `None` if no match is found. This result is passed directly to `engine.find_gadgets()` as the `libc_path` argument.

---

### `run_ldd(binary_path)`

- **Args:**
    - `binary_path` _(str)_ — path to the target binary
- **Returns:** `str` — raw stdout of the `ldd` command
- **Interacts with:** `subprocess.run()` — the **only place** in the entire project that shells out to a system command
- **Description:** Executes `ldd <binary_path>` using `subprocess.run` with `capture_output=True` and `text=True`. Raises `RuntimeError` if the return code is non-zero or if stdout contains `"not a dynamic executable"`. Returns raw stdout string on success. Keeping all subprocess calls here makes shell interaction easy to mock in tests and easy to replace (e.g. swap `ldd` for `readelf -d`) without touching other files.

---

## `core/formatter.py` — Output Formatter

**Responsibility:** Take the final results list and render it cleanly to the terminal. Knows nothing about ELF, Capstone, gadgets, or searching — only presentation.

---

### `print_table(binary_path, results)`

- **Args:**
    - `binary_path` _(str)_ — displayed in the header line
    - `results` _(list[dict])_ — output of `engine.find_gadgets()`; each dict has keys `gadget` _(str)_, `source` _(str)_, `address` _(int | None)_
- **Returns:** `None`
- **Interacts with:** `format_address()` for every row's address field; `colorize()` for every row's source and address fields
- **Description:** Prints the header `[+] Analysis for: <binary_path>`, a separator line, column headers (`Gadget | Found In | Address / Offset`), then one row per entry in `results`. Column widths are calculated dynamically from the longest value in each column so the table stays aligned regardless of gadget name length. Color coding: `"Binary"` → green, `"libc.so"` → yellow, `"Not Found"` → red. Calls `format_address()` to convert integers and `colorize()` to wrap strings in ANSI codes.

---

### `format_address(address)`

- **Args:**
    - `address` _(int | None)_ — virtual address integer, or `None`
- **Returns:** `str` — hex string like `"0x00401234"`, or `"-"` if `None`
- **Interacts with:** nothing — pure formatting, no external calls
- **Description:** If `address` is `None`, returns `"-"`. Otherwise formats it as a zero-padded lowercase hex string with `0x` prefix using `f"0x{address:08x}"`. The consistent format makes addresses directly copy-pasteable into Python exploit scripts without modification.

---

### `colorize(text, color)`

- **Args:**
    - `text` _(str)_ — the string to wrap in color
    - `color` _(str)_ — one of `"green"`, `"yellow"`, `"red"`, `"cyan"`, `"reset"`
- **Returns:** `str` — `text` wrapped between the ANSI opening code and `\033[0m` reset
- **Interacts with:** nothing — pure string wrapping, no external calls
- **Description:** Maps color names to ANSI escape codes via a local dict. Wraps `text` between the code and the reset sequence. If the color name is unrecognized, returns `text` unchanged (safe fallback). Used exclusively by `print_table()` to color-code rows based on their `source` field.

Share