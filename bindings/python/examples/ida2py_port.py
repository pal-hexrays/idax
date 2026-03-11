#!/usr/bin/env python3
"""
Headless Python adaptation of examples/tools/ida2py_port.cpp.

Usage:
    python examples/ida2py_port.py <binary-or-idb> [--list-user-symbols]
        [--show <name|ea>] [--cast <name|ea> <cdecl>] [--callsites <name|ea>]
        [--max-symbols <n>] [--appcall-smoke] [--quiet]
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

import idax


@dataclass(frozen=True)
class CastRequest:
    target: str
    declaration: str


@dataclass(frozen=True)
class Options:
    input: str
    quiet: bool = False
    list_user_symbols: bool = False
    show_targets: list[str] = field(default_factory=list)
    casts: list[CastRequest] = field(default_factory=list)
    callsites: list[str] = field(default_factory=list)
    appcall_smoke: bool = False
    max_symbols: int = 200


def is_idax_error(err: BaseException) -> bool:
    return isinstance(err, idax.IdaxError)


def error_message(err: BaseException) -> str:
    if isinstance(err, idax.IdaxError):
        context = f" ({err.context})" if err.context else ""
        return f"[{err.category}] {err}{context}"
    return str(err)


def hex_addr(address: int) -> str:
    return f"0x{address:x}"


def parse_address(text: str) -> int | None:
    trimmed = text.strip()
    if not trimmed:
        return None
    try:
        return int(trimmed, 0)
    except ValueError:
        return None


def resolve_symbol_or_address(token: str) -> int:
    direct = parse_address(token)
    if direct is not None:
        return direct
    return idax.name.resolve(token, idax.BAD_ADDRESS)


def parse_options(args: list[str]) -> Options:
    if not args:
        raise SystemExit("missing binary_file argument")

    input_path = args[0]
    quiet = False
    list_user_symbols = False
    appcall_smoke = False
    max_symbols = 200
    show_targets: list[str] = []
    callsites: list[str] = []
    casts: list[CastRequest] = []

    i = 1
    while i < len(args):
        arg = args[i]
        if arg in ("--help", "-h"):
            print(
                "Usage: python examples/ida2py_port.py <binary-or-idb> "
                "[--list-user-symbols] [--show <name|ea>] "
                "[--cast <name|ea> <cdecl>] [--callsites <name|ea>] "
                "[--max-symbols <n>] [--appcall-smoke] [--quiet]"
            )
            sys.exit(0)
        if arg in ("--quiet", "-q"):
            quiet = True
            i += 1
            continue
        if arg == "--list-user-symbols":
            list_user_symbols = True
            i += 1
            continue
        if arg == "--show":
            i += 1
            if i >= len(args):
                raise SystemExit("--show requires a value")
            show_targets.append(args[i])
            i += 1
            continue
        if arg == "--callsites":
            i += 1
            if i >= len(args):
                raise SystemExit("--callsites requires a value")
            callsites.append(args[i])
            i += 1
            continue
        if arg == "--cast":
            i += 1
            if i + 1 >= len(args):
                raise SystemExit("--cast requires <name|ea> <cdecl>")
            target = args[i]
            i += 1
            declaration = args[i]
            casts.append(CastRequest(target=target, declaration=declaration))
            i += 1
            continue
        if arg == "--max-symbols":
            i += 1
            if i >= len(args):
                raise SystemExit("--max-symbols requires a value")
            try:
                parsed = int(args[i])
            except ValueError:
                raise SystemExit("invalid --max-symbols value")
            if parsed <= 0:
                raise SystemExit("invalid --max-symbols value")
            max_symbols = parsed
            i += 1
            continue
        if arg == "--appcall-smoke":
            appcall_smoke = True
            i += 1
            continue
        raise SystemExit(f"unknown option: {arg}")

    if (
        not list_user_symbols
        and not show_targets
        and not callsites
        and not casts
        and not appcall_smoke
    ):
        list_user_symbols = True

    return Options(
        input=input_path,
        quiet=quiet,
        list_user_symbols=list_user_symbols,
        show_targets=show_targets,
        casts=casts,
        callsites=callsites,
        appcall_smoke=appcall_smoke,
        max_symbols=max_symbols,
    )


def list_user_symbols(max_symbols: int) -> None:
    entries = idax.name.all_user_defined(idax.BAD_ADDRESS, idax.BAD_ADDRESS)
    print("Address              Name                                Type")
    print("--------------------------------------------------------------------------")
    for entry in entries[:max_symbols]:
        type_name = "<none>"
        try:
            type_name = str(idax.types.retrieve(entry.address))
        except Exception:
            # No type at this symbol.
            pass
        print(f"{hex_addr(entry.address):<20} {entry.name:<34} {type_name}")


def inspect_symbol(token: str) -> None:
    ea = resolve_symbol_or_address(token)

    try:
        symbol_name = idax.name.get(ea)
    except Exception:
        symbol_name = "<unnamed>"

    refs_to = idax.xref.refs_to(ea)
    refs_from = idax.xref.refs_from(ea)
    preview = idax.data.read_bytes(ea, 16).hex(" ")

    print(f"\n== Show: {token} ==")
    print(f"address: {hex_addr(ea)}")
    print(f"name: {symbol_name}")

    try:
        demangled = idax.name.demangled(ea, idax.name.DemangleForm.short_)
        if len(demangled) > 0:
            print(f"demangled: {demangled}")
    except Exception:
        # Keep going.
        pass

    try:
        f = idax.function.at(ea)
        print(f"function: {f.name} [{hex_addr(f.start)} - {hex_addr(f.end)})")
    except Exception:
        # Not a function.
        pass

    try:
        ty = str(idax.types.retrieve(ea))
        print(f"type: {ty}")
    except Exception:
        # No type.
        pass

    print(f"bytes[16]: {preview}")
    print(f"xrefs_to: {len(refs_to)}")
    print(f"xrefs_from: {len(refs_from)}")


def apply_cast(request: CastRequest) -> None:
    ea = resolve_symbol_or_address(request.target)
    parsed = idax.types.from_declaration(request.declaration)
    parsed.apply(ea)
    roundtrip = str(idax.types.retrieve(ea))

    print(f"\n== Cast: {request.target} ==")
    print(f"address: {hex_addr(ea)}")
    print(f"applied: {request.declaration}")
    print(f"retrieved: {roundtrip}")


def show_callsites(target: str) -> None:
    callee = resolve_symbol_or_address(target)
    refs = [r for r in idax.xref.refs_to(callee) if r.is_code and idax.xref.is_call(r.type)]

    print(f"\n== Callsites: {target} ==")
    print(f"target: {hex_addr(callee)}")

    for ref in refs:
        try:
            caller = idax.function.at(ref.from_).name
        except Exception:
            caller = "<unknown>"
        try:
            line = idax.instruction.text(ref.from_)
        except Exception:
            line = "<decode failed>"

        print(f"  from {hex_addr(ref.from_)} ({caller}) -> {hex_addr(ref.to)} : {line}")

    print(f"callsites: {len(refs)}")


def main() -> None:
    options = parse_options(sys.argv[1:])

    try:
        idax.database.init(quiet=options.quiet)
        idax.database.open(options.input, True)
        idax.analysis.wait()

        if not options.quiet:
            print("== ida2py_port (Python adaptation) ==")
            print(f"input: {options.input}")
            print(f"processor: {idax.database.processor_name()}")
            print(f"address_bitness: {idax.database.address_bitness()}")

        if options.list_user_symbols:
            list_user_symbols(options.max_symbols)

        for target in options.show_targets:
            inspect_symbol(target)

        for cast in options.casts:
            apply_cast(cast)

        for target in options.callsites:
            show_callsites(target)

        if options.appcall_smoke:
            print("\n== Appcall smoke ==")
            print(
                "Appcall smoke is not exposed in this Python adaptation yet; "
                "use the C++ idax tool example for debugger-backed appcall validation."
            )
    except Exception as err:
        print(f"error: {error_message(err)}", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            idax.database.close(False)
        except Exception:
            # Ignore close errors during teardown.
            pass


if __name__ == "__main__":
    main()
    os._exit(0)  # avoid idalib shutdown crash
