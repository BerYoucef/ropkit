# ropkit (v1.0.0)

A modular, lightweight Command-Line Interface (CLI) tool designed for static ROP gadget hunting within x86_64 ELF binaries, featuring automatic dynamic library (`libc`) resolving and fallback analysis.

## 🛠️ Architecture & Core Principles

The project strictly follows a **Pipeline Architecture** governed by two core rules:
1. **Single Responsibility Principle (SRP):** Each module owns exactly one distinct phase of execution.
2. **Zero Inter-Module Coupling:** Modules do not import or call each other. All communications and data routing are handled exclusively by the orchestrator (`ropkit.py`).

ropkit/
├── ropkit.py            # Entry Point & Pure Orchestrator
└── core/
├── init.py      # Package Marker
├── parser.py        # ELF Section Extractor (pyelftools)
├── engine.py        # Gadget Analyzer & Matcher (Capstone)
├── resolver.py      # Dynamic Dependency Resolver (ldd)
└── formatter.py     # Terminal Output Formatter (ANSI)


---

## 🔄 Data Flow (Pipeline)

ropkit.py
│
├─► parse_args()                                      → args (Namespace)
│
├─► parser.parse_elf(args.binary)                     → sections[dict]
│
├─► resolver.resolve_libraries(args.binary)           → library_map[dict]
│       └─► resolver.get_libc_path(library_map)       → libc_path (str | None)
│
├─► engine.find_gadgets(sections, libc_path, depth)   → results[dict]
│
└─► formatter.print_table(args.binary, results)       → Terminal Output


---

## 🧠 Gadget Engine (Two-Pass Search Algorithm)

The core logic inside `core/engine.py` implements a **Linear Sweep** scanning algorithm paired with **Backward Slicing** operating in two distinct scopes:

### 1. Two-Pass Search Strategy
- **Pass 1 (Binary Scope):** Iterates over all executable sections explicitly marked with the `SHF_EXECINSTR` (0x4) flag within the target binary.
- **Pass 2 (Libc Fallback Scope):** For any targeted gadget not found in the primary binary, the engine queries the `resolver` for the system's `libc.so` path. If present, it extracts its executable sections and triggers a fallback search to fill missing requirements.

### 2. Validation & Slicing Pipeline
When a valid instruction terminator (`0xc3` for `ret` or `0x0f 0x05` for `syscall`) is hit:
1. **Backward Window Slicing:** Extracts candidate windows of increasing byte lengths from 1 up to `max_depth` prior to the terminator. Windows are ordered shortest-first to guarantee minimal gadget extraction.
2. **Capstone Disassembly Verification:** Each window is disassembled via Capstone (configured for `CS_ARCH_X86`, `CS_MODE_64`) and must pass 4 strict validation checks:
   - **Full Consumption:** The total byte size of decoded instructions must exactly match the candidate window size.
   - **No Invalid Opcodes:** The window must contain entirely valid instructions with zero decoding errors.
   - **No Control Flow Poisoning:** Windows containing intermediate control flow instructions (`jmp`, `call`, `int3`, or conditional jumps) prior to the terminator are discarded.
   - **Valid Tail:** The final decoded instruction in the sequence must be a true terminator (`ret` or `syscall`).

---

## 📊 Modules Specifications

| Module | Core Responsibility | External Dependencies | Input | Output |
| :--- | :--- | :--- | :--- | :--- |
| **`ropkit.py`** | CLI parsing, operational ordering, and linear pipeline data-routing. | `argparse` | `sys.argv` | High-level orchestration |
| **`parser.py`** | Binary structure validation and raw executable section extraction. | `pyelftools` | `binary_path` (str) | `list[dict]` (Raw bytes & `v-addr`) |
| **`resolver.py`** | Dynamic dependency scanning via standard linker hooks. | `subprocess`, `re` | `binary_path` (str) | `libc_path` (str \| None) |
| **`engine.py`** | Linear sweep execution, backward slicing, and mnemonic validation. | `capstone` | Sections, Libc Path, Depth | `list[dict]` (Matched gadget metadata) |
| **`formatter.py`**| Dynamic width padding and contextual ANSI stdout terminal formatting.| None | Results List | Structured console table |

---

## 🚀 Usage & Diagnostics

```bash
python3 ropkit.py <path_to_elf> [--depth <window_size>]
