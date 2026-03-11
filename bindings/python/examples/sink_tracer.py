#!/usr/bin/env python3
"""
Automated Vulnerability Sink Tracer -- headless idax script.

Scans a binary for dangerous imported functions (sinks), traces all
cross-references back to their call sites, decompiles the parent functions,
and extracts the exact lines of pseudocode surrounding the vulnerability.
It also extracts referenced strings to provide immediate context.

Features demonstrated:
  - database lifecycle (init / open / close / wait for analysis)
  - import table enumeration
  - cross-reference (xref) traversal
  - decompiler: pseudocode, line-to-address mapping
  - data extraction (reading strings from memory)

Usage:
    python examples/sink_tracer.py <path-to-binary>
"""

from __future__ import annotations

import os
import re
import sys

import idax


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

# A list of potentially dangerous functions we want to hunt for.
DANGEROUS_APIS: list[str] = [
    "system", "execve", "popen", "strcpy", "sprintf", "gets",
    "VirtualAlloc", "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
    # Added a few C++ filesystem ones based on your output
    "__remove_all", "__create_symlink", "__copy_file",
]

# Maximum bytes to read when attempting to extract a context string.
MAX_STRING_READ_LENGTH: int = 100


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════


def hex_addr(addr: int) -> str:
    """Format an address as a zero-prefixed hex string."""
    return f"0x{addr:x}"


def is_idax_error(err: BaseException) -> bool:
    """Check whether an unknown catch value is an IdaxError."""
    return isinstance(err, idax.IdaxError)


def error_message(err: BaseException) -> str:
    """Extract a human-readable message from an unknown error value."""
    if isinstance(err, idax.IdaxError):
        return f"[{err.category}] {err}"
    return str(err)


# ═══════════════════════════════════════════════════════════════════════════
# Core analysis
# ═══════════════════════════════════════════════════════════════════════════


def extract_function_strings(func_address: int) -> list[str]:
    """
    Extract all readable strings referenced by a function.

    This helps give context to what the vulnerable function is actually doing
    (e.g., finding the format string passed to ``sprintf``).
    """
    strings_found: set[str] = set()

    try:
        items: list[int] = idax.function.item_addresses(func_address)

        for item in items:
            d_refs = idax.xref.data_refs_from(item)

            for d_ref in d_refs:
                try:
                    s: str = idax.data.read_string(d_ref.to, MAX_STRING_READ_LENGTH)
                    # Basic check to ensure it's a printable ASCII string of decent length
                    if s and len(s) >= 4 and re.fullmatch(r"[ -~]+", s):
                        strings_found.add(s)
                except Exception:
                    # Ignore read errors (e.g., reading from unmapped memory)
                    pass
    except Exception as err:
        print(f"  [warn] Could not extract strings: {error_message(err)}")

    return list(strings_found)


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python examples/sink_tracer.py <path-to-binary>", file=sys.stderr)
        sys.exit(1)

    target_binary: str = sys.argv[1]
    if not os.path.exists(target_binary):
        print(f"[!] File not found: {target_binary}", file=sys.stderr)
        sys.exit(1)

    print("[+] Initializing IDA kernel in headless mode...")
    idax.database.init(quiet=True)

    try:
        print(f"[+] Opening database for: {target_binary}")
        idax.database.open(target_binary, True)

        print("[+] Waiting for IDA auto-analysis to complete (this may take a moment)...")
        idax.analysis.wait()

        print(
            f"[+] Analysis complete. Architecture: "
            f"{idax.database.processor_name()} ({idax.database.address_bitness()}-bit)"
        )

        # ── 1. Scan the Import Table ────────────────────────────────────────
        print("\n[+] Scanning import table for dangerous sinks...")
        modules = idax.database.import_modules()
        target_sinks: list[dict] = []

        for mod in modules:
            for sym in mod.symbols:
                if any(api in sym.name for api in DANGEROUS_APIS):
                    target_sinks.append({
                        "module": mod.name,
                        "name": sym.name,
                        "address": sym.address,
                    })

        if not target_sinks:
            print("[-] No dangerous APIs found in imports. Binary looks relatively safe!")
            return

        print(
            f"[!] Found {len(target_sinks)} dangerous imported functions. "
            "Tracing cross-references..."
        )

        can_decompile: bool = idax.decompiler.available()
        if not can_decompile:
            print("[!] Hex-Rays decompiler not available. Falling back to raw disassembly.")

        # ── 2. Trace Cross-References and Decompile ─────────────────────────
        for sink in target_sinks:
            print()
            print("=" * 75)
            print(f"SINK: {sink['name']} (from {sink['module']}) at {hex_addr(sink['address'])}")
            print("=" * 75)

            refs = idax.xref.refs_to(sink["address"])
            code_refs = [r for r in refs if r.is_code]

            if not code_refs:
                print(
                    "   [-] No direct code cross-references found. "
                    "(Might be dead code or dynamically resolved)"
                )
                continue

            for ref in code_refs:
                call_addr: int = ref.from_

                # ── 3. Identify the parent function ─────────────────────────
                parent_func = None
                try:
                    parent_func = idax.function.at(call_addr)
                except Exception:
                    # Throws if the address isn't inside a defined function
                    pass

                if parent_func is None:
                    print(f"   [?] Call at {hex_addr(call_addr)} (Not inside a recognized function)")
                    print(f"       -> {idax.instruction.text(call_addr)}")
                    continue

                print(f"   [!] Called from function '{parent_func.name}' at {hex_addr(call_addr)}")

                # ── 4. Extract Context Strings ──────────────────────────────
                context_strings: list[str] = extract_function_strings(parent_func.start)
                if context_strings:
                    quoted = ", ".join(f'"{s}"' for s in context_strings)
                    print(f"       [Context Strings]: {quoted}")

                # ── 5. Decompile and map vulnerability ──────────────────────
                if can_decompile:
                    try:
                        dfunc = idax.decompiler.decompile(parent_func.start)
                        lines: list[str] = dfunc.lines()
                        addr_map: list[dict] = dfunc.address_map()

                        matching_map = None
                        for m in addr_map:
                            if m["address"] == call_addr:
                                matching_map = m
                                break

                        if matching_map is not None and matching_map["line_number"] < len(lines):
                            line_idx: int = matching_map["line_number"]
                            print("       [Pseudocode Snippet]:")

                            start_line: int = max(0, line_idx - 1)
                            end_line: int = min(len(lines) - 1, line_idx + 1)

                            for idx in range(start_line, end_line + 1):
                                prefix = "      --> " if idx == line_idx else "         "
                                print(f"{prefix}{lines[idx].strip()}")
                        else:
                            print("       [Pseudocode]: (Could not map exact line, dumping signature)")
                            print(f"         {dfunc.declaration()}")
                    except Exception as err:
                        print(
                            f"       [!] Failed to decompile {parent_func.name}: "
                            f"{error_message(err)}"
                        )
                else:
                    # Fallback to disassembly context
                    print("       [Disassembly Snippet]:")
                    try:
                        prev_addr: int = idax.address.prev_head(call_addr)
                        print(f"         {hex_addr(prev_addr)}: {idax.instruction.text(prev_addr)}")
                        print(f"      --> {hex_addr(call_addr)}: {idax.instruction.text(call_addr)}")
                    except Exception:
                        print(f"      --> {hex_addr(call_addr)}: {idax.instruction.text(call_addr)}")

    except Exception as err:
        print(f"\n[!] Fatal Error: {error_message(err)}", file=sys.stderr)
    finally:
        print("\n[+] Closing database and cleaning up...")
        # ── Teardown ────────────────────────────────────────────────────────
        idax.database.close(False)


if __name__ == "__main__":
    main()
    os._exit(0)  # avoid idalib shutdown crash
