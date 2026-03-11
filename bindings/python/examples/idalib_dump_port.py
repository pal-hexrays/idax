#!/usr/bin/env python3
"""
Headless Python adaptation of examples/tools/idalib_dump_port.cpp.

Usage:
    python examples/idalib_dump_port.py <binary-or-idb> [--list]
        [--asm] [--pseudo] [--asm-only] [--pseudo-only]
        [--filter <text>] [--function <name>] [--output <path>]
        [--max-asm-lines <n>] [--no-summary]
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

import idax


@dataclass(frozen=True)
class Options:
    input: str
    output: str | None = None
    filter: str | None = None
    function_names: list[str] = field(default_factory=list)
    list_only: bool = False
    show_assembly: bool = True
    show_pseudocode: bool = True
    no_summary: bool = False
    max_asm_lines: int = 120


def is_idax_error(err: BaseException) -> bool:
    return isinstance(err, idax.IdaxError)


def error_message(err: BaseException) -> str:
    if isinstance(err, idax.IdaxError):
        context = f" ({err.context})" if err.context else ""
        return f"[{err.category}] {err}{context}"
    return str(err)


def hex_addr(address: int) -> str:
    return f"0x{address:x}"


def parse_options(args: list[str]) -> Options:
    if not args:
        raise SystemExit("missing binary_file argument")

    input_path = args[0]
    output: str | None = None
    filter_text: str | None = None
    function_names: list[str] = []
    list_only = False
    show_assembly = True
    show_pseudocode = True
    no_summary = False
    max_asm_lines = 120

    i = 1
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            print(
                "Usage: python examples/idalib_dump_port.py <binary-or-idb> [--list] "
                "[--asm] [--pseudo] [--asm-only] [--pseudo-only] "
                "[--filter <text>] [--function <name>] [--output <path>] "
                "[--max-asm-lines <n>] [--no-summary]"
            )
            sys.exit(0)
        if arg in ("--list", "-l"):
            list_only = True
            i += 1
            continue
        if arg == "--asm":
            show_assembly = True
            i += 1
            continue
        if arg == "--pseudo":
            show_pseudocode = True
            i += 1
            continue
        if arg == "--asm-only":
            show_assembly = True
            show_pseudocode = False
            i += 1
            continue
        if arg == "--pseudo-only":
            show_assembly = False
            show_pseudocode = True
            i += 1
            continue
        if arg in ("--filter", "-f"):
            i += 1
            if i >= len(args):
                raise SystemExit("--filter requires a value")
            filter_text = args[i]
            i += 1
            continue
        if arg in ("--function", "-F"):
            i += 1
            if i >= len(args):
                raise SystemExit("--function requires a value")
            function_names.append(args[i])
            i += 1
            continue
        if arg in ("--output", "-o"):
            i += 1
            if i >= len(args):
                raise SystemExit("--output requires a path")
            output = args[i]
            i += 1
            continue
        if arg == "--max-asm-lines":
            i += 1
            if i >= len(args):
                raise SystemExit("--max-asm-lines requires a value")
            try:
                parsed = int(args[i])
            except ValueError:
                raise SystemExit("invalid --max-asm-lines value")
            if parsed <= 0:
                raise SystemExit("invalid --max-asm-lines value")
            max_asm_lines = parsed
            i += 1
            continue
        if arg == "--no-summary":
            no_summary = True
            i += 1
            continue
        raise SystemExit(f"unknown option: {arg}")

    if not list_only and not show_assembly and not show_pseudocode:
        show_assembly = True
        show_pseudocode = True

    return Options(
        input=input_path,
        output=output,
        filter=filter_text,
        function_names=function_names,
        list_only=list_only,
        show_assembly=show_assembly,
        show_pseudocode=show_pseudocode,
        no_summary=no_summary,
        max_asm_lines=max_asm_lines,
    )


def matches(fn_name: str, options: Options) -> bool:
    if options.function_names and fn_name not in options.function_names:
        return False
    if options.filter is not None and options.filter not in fn_name:
        return False
    return True


def render_output(options: Options) -> str:
    funcs = [f for f in idax.function.all() if matches(f.name, options)]
    output = ""
    decompile_failures: list[dict] = []

    try:
        decompiler_available = idax.decompiler.available()
    except Exception:
        decompiler_available = False

    if options.list_only:
        output += "Address              Size      Name\n"
        output += "---------------------------------------------\n"
        for f in funcs:
            output += f"{hex_addr(f.start):<20} {str(f.size):<9} {f.name}\n"
    else:
        for f in funcs:
            output += "============================================================\n"
            output += f"Function: {f.name} @ {hex_addr(f.start)} (size={f.size})\n"
            output += "============================================================\n"

            if options.show_assembly:
                output += "\n-- Assembly --\n"
                addrs = idax.function.code_addresses(f.start)[: options.max_asm_lines]
                for index, ea in enumerate(addrs):
                    line = "<decode error>"
                    try:
                        line = idax.instruction.text(ea)
                    except Exception:
                        # Keep placeholder.
                        pass
                    output += f"{index:04d}  {hex_addr(ea)}  {line}\n"

            if options.show_pseudocode:
                output += "\n-- Pseudocode --\n"
                if decompiler_available:
                    try:
                        output += f"{idax.decompiler.decompile(f.start).pseudocode()}\n"
                    except Exception as err:
                        reason = error_message(err)
                        decompile_failures.append(
                            {"address": f.start, "name": f.name, "reason": reason}
                        )
                        output += f"<pseudocode error: {reason}>\n"
                else:
                    output += "<Hex-Rays unavailable on this host>\n"

            output += "\n"

    if not options.no_summary:
        output += "\n================ Summary ================\n"
        output += f"Input: {options.input}\n"
        output += f"Total functions: {idax.function.count()}\n"
        output += f"Selected functions: {len(funcs)}\n"
        output += f"Decompiler failures: {len(decompile_failures)}\n"
        if decompile_failures:
            output += "\nDecompiler failures:\n"
            for fail in decompile_failures:
                output += f"  - {hex_addr(fail['address'])} {fail['name']}: {fail['reason']}\n"

    return output


def main() -> None:
    options = parse_options(sys.argv[1:])

    try:
        idax.database.init(quiet=True)
        idax.database.open(options.input, True)
        idax.analysis.wait()

        result = render_output(options)
        if options.output is not None:
            with open(options.output, "w", encoding="utf-8") as fh:
                fh.write(result)
        else:
            sys.stdout.write(result)
            sys.stdout.flush()
    except Exception as err:
        print(f"error: {error_message(err)}", file=sys.stderr)
        sys.exit(1)
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


if __name__ == "__main__":
    main()
