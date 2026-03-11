# idax — Python bindings for the IDA SDK

Python bindings for **idax**, the cross-language interface to the IDA disassembler SDK.
Built with [pybind11](https://github.com/pybind/pybind11) and
[scikit-build-core](https://github.com/scikit-build/scikit-build-core), exposing
the full idax C++ API as idiomatic Python with snake\_case naming and complete
type annotations.

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| IDA SDK | Set `IDASDK` environment variable |
| IDA installation | Set `IDADIR` environment variable |
| C++ compiler | C++23 support (Clang 17+, GCC 13+, MSVC 17.8+) |
| CMake | 3.27+ |
| pybind11 | 2.13+ (pulled automatically) |
| scikit-build-core | 0.10+ (pulled automatically) |

## Installation

```bash
# From the bindings/python directory:
uv pip install --no-build-isolation -e .

# Or via the project root build script:
./build.sh python
```

## Quick start

```python
import idax
from idax import database, function, decompiler

# Initialise the IDA kernel (once per process)
database.init(quiet=True)

# Open a database
database.open("/path/to/binary.i64")

# Iterate over all functions
for fn in function.all():
    print(f"{fn.name} @ 0x{fn.start:x}")

# Decompile a function
dec = decompiler.decompile(fn.start)
print(dec.pseudocode())

# Clean up
database.close()
```

## API overview

The package exposes 20 submodules, each mapping to a C++ namespace in libidax:

| Submodule | Description |
|---|---|
| `database` | Lifecycle (init/open/save/close), metadata, snapshots |
| `address` | Navigation, predicates, search, item iteration |
| `segment` | Segment CRUD, properties, traversal |
| `function` | Function CRUD, chunks, frames, register variables |
| `instruction` | Decode, operand access/formatting, classification |
| `data` | Byte read/write/patch, define items, binary search |
| `name` | Naming, demangling, name inventory, validation |
| `xref` | Cross-reference enumeration and mutation |
| `comment` | Regular, repeatable, anterior/posterior comments |
| `search` | Text, immediate, and binary pattern searches |
| `analysis` | Auto-analysis control, scheduling, waiting |
| `types` | Type construction, introspection, application |
| `entry` | Program entry points (exports) |
| `fixup` | Relocation / fixup information |
| `event` | Typed IDB event subscriptions |
| `storage` | Persistent key-value storage (netnode abstraction) |
| `diagnostics` | Logging, invariants, performance counters |
| `lumina` | Lumina metadata pull/push |
| `lines` | Color tag manipulation and constants |
| `decompiler` | Hex-Rays decompilation, microcode filters, events |

> **Note:** The `types` submodule is named `types` (not `type`) to avoid collision
> with the Python builtin.

## Running tests

```bash
# Unit tests (no IDA database required)
uv run pytest tests/unit/ -v

# Integration tests (requires IDASDK and IDADIR)
uv run pytest tests/integration/ -v
```

## Building

### Standalone (editable install)

```bash
cd bindings/python
uv pip install --no-build-isolation -e .
```

### Via build.sh

```bash
# Build only Python bindings
./build.sh python

# Build everything (core + node + rust + python)
./build.sh
```

### Direct CMake

```bash
cd bindings/python
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## Type checking

The package ships with full `.pyi` type stubs for mypy and IDE autocomplete:

```bash
uv run mypy --strict your_script.py
```

All submodules, classes, enums, and functions have complete type annotations.

## Naming conventions

The Python bindings use **snake\_case** throughout, matching Python conventions:

| Node.js (camelCase) | Python (snake\_case) |
|---|---|
| `database.inputFilePath()` | `database.input_file_path()` |
| `function.nameAt(addr)` | `function.name_at(addr)` |
| `segment.setPermissions(...)` | `segment.set_permissions(...)` |
| `instruction.isConditionalJump(addr)` | `instruction.is_conditional_jump(addr)` |

Enum values also use snake\_case (e.g., `OpenMode.skip_analysis` instead of
`"skipAnalysis"`). Reserved words are suffixed with an underscore
(e.g., `register_`, `import_`, `null_`).

## Known issues

### Decompiler crash on extern/special segment functions

Calling `decompiler.decompile()` on a function that lives in an extern or special
segment (e.g. imported functions like `printf`, `__libc_start_main`) will cause a
**SIGSEGV** that cannot be caught by Python's `try/except`. This is a crash inside
the Hex-Rays SDK's `decompile_func()`, which does not gracefully handle these
segment types. The Node.js bindings survive this because V8 installs its own
structured exception handlers.

**Workaround:** check the segment type before decompiling:

```python
seg = idax.segment.at(func.start)
if seg and seg.type != idax.segment.Type.external:
    dfunc = idax.decompiler.decompile(func.start)
```

A proper fix requires a guard in the idax C++ core (`src/decompiler.cpp`) to
reject extern segment addresses before calling `decompile_func()`.

### Process exit crash

Python interpreter shutdown may segfault after `database.close()` due to
conflicting cleanup order between pybind11 destructor and idalib's `atexit`
handlers. Use `os._exit(0)` after `database.close()` in standalone scripts
to avoid this.
