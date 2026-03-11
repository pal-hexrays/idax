#!/usr/bin/env python3
"""
Automated C++ Class & VTable Reconstructor -- headless idax script.

This script performs advanced heuristic analysis to reconstruct C++ objects:
  1. Scans data segments for arrays of function pointers (VTables).
  2. Dynamically builds TypeInfo structs for the VTable and the Class.
  3. Saves these structs into IDA's Local Types (TIL).
  4. Applies the VTable struct directly to the memory addresses.
  5. Renames the discovered virtual functions (e.g., Class_XYZ::vmethod_1).
  6. Uses data cross-references to find the Class Constructors.
  7. Renames the constructors and annotates them.

Features demonstrated:
  - Memory scanning and pointer arithmetic.
  - Dynamic Type creation (create_struct, pointer_to, function_type).
  - Local Type Library (TIL) manipulation.
  - Cross-reference (xref) traversal for logic discovery.
  - Global naming and commenting.

Usage:
  python examples/class_reconstructor.py <path-to-binary>
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

import idax


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

# Minimum number of consecutive function pointers to be considered a VTable.
MIN_VTABLE_METHODS: int = 3


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════

def fmt_addr(addr: int) -> str:
    """Format an address as a zero-prefixed hex string."""
    return f"0x{addr:x}"


def is_idax_error(err: BaseException) -> bool:
    """Check whether an exception is an IdaxError."""
    return isinstance(err, idax.IdaxError)


def error_message(err: BaseException) -> str:
    """Extract a human-readable message from an error value."""
    if isinstance(err, idax.IdaxError):
        ctx = f" ({err.context})" if err.context else ""
        return f"[{err.category}] {err}{ctx}"
    return str(err)


# ═══════════════════════════════════════════════════════════════════════════
# Core Logic
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DiscoveredClass:
    class_name: str
    vtable_address: int
    methods: list[int] = field(default_factory=list)
    constructors: list[int] = field(default_factory=list)


def read_pointer(addr: int, bitness: int) -> Optional[int]:
    """
    Reads a pointer-sized integer from memory based on the binary's architecture.
    """
    try:
        if bitness == 64:
            return idax.data.read_qword(addr)
        else:
            return idax.data.read_dword(addr)
    except Exception:
        return None  # Unmapped memory or read error


def scan_segment_for_vtables(seg: idax.segment.Segment, bitness: int) -> list[DiscoveredClass]:
    """
    Heuristically scans a segment for VTables.
    """
    classes: list[DiscoveredClass] = []
    ptr_size = 8 if bitness == 64 else 4

    current_addr = seg.start

    while current_addr < seg.end:
        methods: list[int] = []
        scan_addr = current_addr

        # Look for consecutive pointers that point to the START of valid functions
        while scan_addr < seg.end:
            ptr = read_pointer(scan_addr, bitness)
            if ptr is None or ptr == 0:
                break

            try:
                func = idax.function.at(ptr)
                # Must point exactly to the start of a function
                if func and func.start == ptr:
                    methods.append(ptr)
                    scan_addr += ptr_size
                else:
                    break
            except Exception:
                break  # Not a function

        if len(methods) >= MIN_VTABLE_METHODS:
            class_name = f"AutoClass_{current_addr:X}"

            # Find constructors by looking at what references this VTable
            constructors: list[int] = []
            refs = idax.xref.data_refs_to(current_addr)
            for ref in refs:
                try:
                    ref_func = idax.function.at(ref.from_)
                    if ref_func and ref_func.start not in constructors:
                        constructors.append(ref_func.start)
                except Exception:
                    pass  # Ref is not in a function

            classes.append(DiscoveredClass(
                class_name=class_name,
                vtable_address=current_addr,
                methods=methods,
                constructors=constructors,
            ))

            # Skip past the discovered VTable
            current_addr = scan_addr
        else:
            current_addr += ptr_size

    return classes


def reconstruct_class(cls: DiscoveredClass, bitness: int) -> None:
    """
    Generates C++ Structs for the VTable and the Class, applies them to memory,
    and renames the associated functions.
    """
    vtable_name = f"VTable_{cls.class_name}"

    print(f"\n[+] Reconstructing: {cls.class_name}")
    print(f"    VTable Address: {fmt_addr(cls.vtable_address)} ({len(cls.methods)} virtual methods)")

    try:
        # 1. Create the VTable Struct
        vtable_struct = idax.types.create_struct()

        # Use a C declaration string for the method pointer type so the SDK can
        # always resolve the size. "void*(__cdecl*)(void*)" is a pointer to a
        # function that takes a void* (the implicit `this`) and returns void*.
        method_ptr_type = idax.types.from_declaration("void*(__cdecl*)(void*)")

        ptr_size = 8 if bitness == 64 else 4

        for index, method_addr in enumerate(cls.methods):
            method_name = f"vmethod_{index}"
            full_method_name = f"{cls.class_name}::{method_name}"

            # Rename the function in the database
            try:
                idax.name.force_set(method_addr, full_method_name)
            except Exception:
                print(f"    [warn] Could not rename method at {fmt_addr(method_addr)}")

            # Add the method pointer at its correct byte offset within the struct
            vtable_struct.add_member(method_name, method_ptr_type, index * ptr_size)

        # Save the VTable struct to the Local Types window (TIL)
        vtable_struct.save_as(vtable_name)
        print(f"    [*] Created struct '{vtable_name}' in Local Types.")

        # Re-fetch by name so the pointer below targets a proper named TIL reference
        saved_vtable_type = idax.types.by_name(vtable_name)

        # Apply the struct directly to the VTable bytes in memory
        saved_vtable_type.apply(cls.vtable_address)
        idax.name.force_set(cls.vtable_address, f"vftable_{cls.class_name}")

        # 2. Create the actual Class Struct
        class_struct = idax.types.create_struct()
        # Pointer to the named VTable struct (resolved through TIL)
        vtable_ptr_type = idax.types.pointer_to(saved_vtable_type)
        class_struct.add_member("__vftable", vtable_ptr_type)
        class_struct.save_as(cls.class_name)
        print(f"    [*] Created struct '{cls.class_name}' in Local Types.")

        # 3. Process Constructors
        if len(cls.constructors) > 0:
            print(f"    [*] Found {len(cls.constructors)} potential constructor(s):")
            for idx, ctor_addr in enumerate(cls.constructors):
                ctor_name = f"{cls.class_name}::Constructor_{idx}"
                try:
                    idax.name.force_set(ctor_addr, ctor_name)
                    idax.comment.set(ctor_addr,
                                     f"Auto-discovered constructor for {cls.class_name}",
                                     True)
                    print(f"        -> Renamed {fmt_addr(ctor_addr)} to {ctor_name}")
                except Exception:
                    print(f"        -> Found at {fmt_addr(ctor_addr)} (Rename failed)")
        else:
            print("    [?] No constructors found (VTable might be referenced dynamically).")

    except Exception as err:
        print(f"    [!] Failed to reconstruct class: {error_message(err)}")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python examples/class_reconstructor.py <path-to-binary>",
              file=sys.stderr)
        sys.exit(1)

    target_binary: str = sys.argv[1]
    if not os.path.exists(target_binary):
        print(f"[!] File not found: {target_binary}", file=sys.stderr)
        sys.exit(1)

    print("[+] Initializing IDA kernel...")
    idax.database.init(quiet=True)

    try:
        print("[+] Opening database and running auto-analysis...")
        idax.database.open(target_binary, True)
        idax.analysis.wait()

        bitness: int = idax.database.address_bitness()
        print(f"[+] Analysis complete. Architecture: {idax.database.processor_name()} ({bitness}-bit)")

        segments = idax.segment.all()
        discovered_classes: list[DiscoveredClass] = []

        print("[+] Scanning data segments for Virtual Method Tables...")
        for seg in segments:
            # We only care about data segments (usually .rdata, .rodata, or .data)
            if seg.type == idax.segment.Type.data or "data" in seg.name:
                classes_in_seg = scan_segment_for_vtables(seg, bitness)
                discovered_classes.extend(classes_in_seg)

        if len(discovered_classes) == 0:
            print("[-] No VTables found. This might be a C binary or heavily obfuscated.")
            return

        print(f"[!] Discovered {len(discovered_classes)} C++ Classes. Beginning reconstruction...")

        for cls in discovered_classes:
            reconstruct_class(cls, bitness)

        print("\n[+] Reconstruction complete!")
        print("[+] Saving changes to the IDA database...")

        # Save the database so the user can open it in the IDA GUI and see the results
        idax.database.save()

    except Exception as err:
        print(f"\n[!] Fatal Error: {error_message(err)}", file=sys.stderr)
    finally:
        print("[+] Closing database...")
        idax.database.close(False)


if __name__ == "__main__":
    main()
    os._exit(0)  # avoid idalib shutdown crash
