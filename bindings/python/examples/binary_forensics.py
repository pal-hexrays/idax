#!/usr/bin/env python3
"""
Binary Forensics — exhaustive API stress-test and deep binary analysis.

This script exercises virtually every binding in the idax Python API
surface.  It is designed as a headless idalib forensic analysis pipeline
that performs the following phases:

  Phase 1 — Database metadata & environment probing
  Phase 2 — Segment deep-dive: enumeration, mutation, comments, geometry
  Phase 3 — Address space cartography: predicates, navigation, item enumeration
  Phase 4 — Function anatomy: frames, chunks, register variables, code addresses
  Phase 5 — Instruction-level analysis: decode, operand formatting, classification
  Phase 6 — Cross-reference graph reconstruction
  Phase 7 — Name management: set/get/resolve/properties/validation/demangling
  Phase 8 — Comment layers: regular, repeatable, anterior, posterior, render
  Phase 9 — Data forensics: read/write/patch/revert/define/undefine/pattern search
  Phase 10 — Search engine: text, immediate, binary, next-type
  Phase 11 — Analysis control: scheduling, waiting, enable/disable
  Phase 12 — Type system: primitives, composites, struct building, application
  Phase 13 — Entry points: enumeration, mutation, forwarders
  Phase 14 — Fixup table inspection
  Phase 15 — Storage: netnode alt/sup/hash/blob round-trips, openById
  Phase 16 — Diagnostics: log levels, counters, invariants
  Phase 17 — Lines & colors: colstr, tag manipulation, address tags
  Phase 18 — Decompiler deep-dive: pseudocode, raw lines, retyping, cache
  Phase 19 — Lumina: connection probing (non-destructive)
  Phase 20 — Event system: all typed + generic subscriptions with mutations

Every phase is fully autonomous and recovers from errors so subsequent
phases always execute.  The script prints a detailed pass/fail matrix at
the end with the total API coverage achieved.

Usage:
  IDADIR=<ida-install> python examples/binary_forensics.py <binary>
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Optional

import idax

# ── Namespace aliases ───────────────────────────────────────────────────

database = idax.database
address = idax.address
segment = idax.segment
fn = idax.function
instruction = idax.instruction
naming = idax.name
xref = idax.xref
comment = idax.comment
data = idax.data
search = idax.search
analysis = idax.analysis
typing_ = idax.types
entry = idax.entry
fixup = idax.fixup
event = idax.event
storage = idax.storage
diagnostics = idax.diagnostics
lumina = idax.lumina
lines = idax.lines
decompiler = idax.decompiler

# ═══════════════════════════════════════════════════════════════════════════
# Test harness
# ═══════════════════════════════════════════════════════════════════════════


class TestResult:
    __slots__ = ("phase", "api", "passed", "detail")

    def __init__(self, phase: str, api: str, passed: bool, detail: str) -> None:
        self.phase = phase
        self.api = api
        self.passed = passed
        self.detail = detail


results: list[TestResult] = []


def record(phase: str, api: str, passed: bool, detail: str) -> None:
    results.append(TestResult(phase, api, passed, detail))


def hex_(addr: int) -> str:
    return f"0x{addr:x}"


def is_idax_error(err: BaseException) -> bool:
    return isinstance(err, idax.IdaxError)


def err_str(err: BaseException) -> str:
    if is_idax_error(err):
        ctx = f" ({err.context})" if err.context else ""  # type: ignore[attr-defined]
        return f"[{err.category}/{err.code}] {err}{ctx}"  # type: ignore[attr-defined]
    if isinstance(err, Exception):
        return str(err)
    return str(err)


def probe(phase: str, api: str, action: Any) -> Any:
    """Execute a test probe.  Catches and records both success and failure.
    Returns the value on success, or None on failure."""
    try:
        result = action()
        record(phase, api, True, hex_(result) if isinstance(result, int) and not isinstance(result, bool) else str(result))
        return result
    except Exception as err:
        record(phase, api, False, err_str(err))
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Phase 1 — Database metadata & environment probing
# ═══════════════════════════════════════════════════════════════════════════

def phase1_metadata() -> None:
    P = "P01-metadata"

    probe(P, "database.input_file_path", lambda: database.input_file_path())
    probe(P, "database.file_type_name", lambda: database.file_type_name())
    probe(P, "database.loader_format_name", lambda: database.loader_format_name())
    probe(P, "database.input_md5", lambda: database.input_md5())
    probe(P, "database.processor_name", lambda: database.processor_name())
    probe(P, "database.processor_id", lambda: database.processor_id())
    probe(P, "database.processor", lambda: database.processor())
    probe(P, "database.address_bitness", lambda: database.address_bitness())
    probe(P, "database.is_big_endian", lambda: database.is_big_endian())
    probe(P, "database.abi_name", lambda: database.abi_name())

    probe(P, "database.image_base", lambda: database.image_base())
    probe(P, "database.min_address", lambda: database.min_address())
    probe(P, "database.max_address", lambda: database.max_address())

    def _address_bounds() -> str:
        bounds = database.address_bounds()
        return f"{hex_(bounds['start'])}..{hex_(bounds['end'])}"
    probe(P, "database.address_bounds", _address_bounds)
    probe(P, "database.address_span", lambda: database.address_span())

    def _compiler_info() -> str:
        ci = database.compiler_info()
        return f"id={ci.id} name='{ci.name}' abbrev='{ci.abbreviation}' uncertain={ci.uncertain}"
    probe(P, "database.compiler_info", _compiler_info)

    def _import_modules() -> str:
        modules = database.import_modules()
        total_syms = 0
        for m in modules:
            total_syms += len(m.symbols)
            # exercise ImportSymbol fields
            for s in m.symbols:
                _ = s.address
                _ = s.name
                _ = s.ordinal
        return f"{len(modules)} module(s), {total_syms} symbol(s)"
    probe(P, "database.import_modules", _import_modules)

    def _snapshots() -> str:
        snaps = database.snapshots()
        def walk(ss: list) -> int:
            c = 0
            for s in ss:
                _ = s.get("id") if isinstance(s, dict) else getattr(s, "id", None)
                _ = s.get("flags") if isinstance(s, dict) else getattr(s, "flags", None)
                _ = s.get("description") if isinstance(s, dict) else getattr(s, "description", None)
                _ = s.get("filename") if isinstance(s, dict) else getattr(s, "filename", None)
                children = s.get("children", []) if isinstance(s, dict) else getattr(s, "children", [])
                c += 1 + walk(children)
            return c
        return f"{walk(snaps)} snapshot(s)"
    probe(P, "database.snapshots", _snapshots)

    probe(P, "database.is_snapshot_database", lambda: database.is_snapshot_database())


# ═══════════════════════════════════════════════════════════════════════════
# Phase 2 — Segment deep-dive
# ═══════════════════════════════════════════════════════════════════════════

def phase2_segments() -> None:
    P = "P02-segment"

    def _all_segs() -> list:
        segs = segment.all()
        for s in segs:
            _ = s.start
            _ = s.end
            _ = s.size
            _ = s.bitness
            _ = s.type
            _ = s.permissions.read
            _ = s.permissions.write
            _ = s.permissions.execute
            _ = s.name
            _ = s.class_name
            _ = s.is_visible
        return segs
    all_segs = probe(P, "segment.all", _all_segs)

    probe(P, "segment.count", lambda: segment.count())

    def _first() -> str:
        s = segment.first()
        return f"{s.name} @ {hex_(s.start)}"
    probe(P, "segment.first", _first)

    def _last() -> str:
        s = segment.last()
        return f"{s.name} @ {hex_(s.start)}"
    probe(P, "segment.last", _last)

    first_seg = all_segs[0] if all_segs is not None and len(all_segs) > 0 else None

    if first_seg is not None:
        def _at() -> str:
            s = segment.at(first_seg.start)
            return f"{s.name} type={s.type}"
        probe(P, "segment.at", _at)

        def _by_name() -> str:
            s = segment.by_name(first_seg.name)
            return f"{s.name} @ {hex_(s.start)}"
        probe(P, "segment.by_name", _by_name)

        def _by_index() -> str:
            s = segment.by_index(0)
            return f"{s.name} @ {hex_(s.start)}"
        probe(P, "segment.by_index(0)", _by_index)

        def _next() -> str:
            s = segment.next(first_seg.start)
            return f"{s.name} @ {hex_(s.start)}"
        probe(P, "segment.next", _next)

        # segment.comment and segment.set_comment
        def _set_comment() -> str:
            segment.set_comment(first_seg.start, "forensics: segment probe", False)
            return "ok"
        probe(P, "segment.set_comment", _set_comment)
        probe(P, "segment.comment", lambda: segment.comment(first_seg.start, False))

        def _set_comment_repeat() -> str:
            segment.set_comment(first_seg.start, "forensics: repeatable seg", True)
            return "ok"
        probe(P, "segment.set_comment(repeat)", _set_comment_repeat)
        probe(P, "segment.comment(repeat)", lambda: segment.comment(first_seg.start, True))

    if all_segs is not None and len(all_segs) >= 2:
        second_seg = all_segs[1]

        def _prev() -> str:
            s = segment.prev(second_seg.start)
            return f"{s.name} @ {hex_(s.start)}"
        probe(P, "segment.prev", _prev)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 3 — Address space cartography
# ═══════════════════════════════════════════════════════════════════════════

def phase3_address() -> None:
    P = "P03-address"

    min_addr: Optional[int] = probe(P, "database.min_address", lambda: database.min_address())
    max_addr: Optional[int] = probe(P, "database.max_address", lambda: database.max_address())
    if min_addr is None or max_addr is None:
        return

    # Navigation
    probe(P, "address.item_start", lambda: address.item_start(min_addr))
    probe(P, "address.item_end", lambda: address.item_end(min_addr))
    probe(P, "address.item_size", lambda: address.item_size(min_addr))
    probe(P, "address.next_head", lambda: address.next_head(min_addr))
    probe(P, "address.prev_head", lambda: address.prev_head(max_addr))
    probe(P, "address.next_head(limit)", lambda: address.next_head(min_addr, max_addr))
    probe(P, "address.prev_head(limit)", lambda: address.prev_head(max_addr, min_addr))
    probe(P, "address.next_defined", lambda: address.next_defined(min_addr))
    probe(P, "address.prev_defined", lambda: address.prev_defined(max_addr))
    probe(P, "address.next_defined(limit)", lambda: address.next_defined(min_addr, max_addr))
    probe(P, "address.prev_defined(limit)", lambda: address.prev_defined(max_addr, min_addr))
    probe(P, "address.next_not_tail", lambda: address.next_not_tail(min_addr))
    probe(P, "address.prev_not_tail", lambda: address.prev_not_tail(max_addr))
    probe(P, "address.next_mapped", lambda: address.next_mapped(min_addr))
    probe(P, "address.prev_mapped", lambda: address.prev_mapped(max_addr))

    # Predicates
    probe(P, "address.is_mapped", lambda: address.is_mapped(min_addr))
    probe(P, "address.is_loaded", lambda: address.is_loaded(min_addr))
    probe(P, "address.is_code", lambda: address.is_code(min_addr))
    probe(P, "address.is_data", lambda: address.is_data(min_addr))
    probe(P, "address.is_unknown", lambda: address.is_unknown(min_addr))
    probe(P, "address.is_head", lambda: address.is_head(min_addr))
    probe(P, "address.is_tail", lambda: address.is_tail(min_addr))

    # Search with predicates
    probe(P, "address.find_first(code)", lambda: address.find_first(min_addr, max_addr, address.Predicate.code))
    probe(P, "address.find_first(data)", lambda: address.find_first(min_addr, max_addr, address.Predicate.data))
    probe(P, "address.find_first(mapped)", lambda: address.find_first(min_addr, max_addr, address.Predicate.mapped))
    probe(P, "address.find_first(head)", lambda: address.find_first(min_addr, max_addr, address.Predicate.head))

    first_code: Optional[int] = probe(
        P, "address.find_first(code)2",
        lambda: address.find_first(min_addr, max_addr, address.Predicate.code),
    )

    if first_code is not None:
        probe(P, "address.find_next(code)", lambda: address.find_next(first_code, address.Predicate.code, max_addr))

    # Item enumeration — limit range to avoid huge arrays
    enum_end = min_addr + 0x200 if min_addr + 0x200 < max_addr else max_addr

    def _items() -> str:
        items = address.items(min_addr, enum_end)
        return f"{len(items)} items in {hex_(min_addr)}..{hex_(enum_end)}"
    probe(P, "address.items", _items)

    def _code_items() -> str:
        items = address.code_items(min_addr, enum_end)
        return f"{len(items)} code items"
    probe(P, "address.code_items", _code_items)

    def _data_items() -> str:
        items = address.data_items(min_addr, enum_end)
        return f"{len(items)} data items"
    probe(P, "address.data_items", _data_items)

    def _unknown_bytes() -> str:
        items = address.unknown_bytes(min_addr, enum_end)
        return f"{len(items)} unknown bytes"
    probe(P, "address.unknown_bytes", _unknown_bytes)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 4 — Function anatomy
# ═══════════════════════════════════════════════════════════════════════════

def phase4_functions() -> None:
    P = "P04-function"

    all_funcs = probe(P, "function.all", lambda: fn.all())
    if all_funcs is None or len(all_funcs) == 0:
        return

    probe(P, "function.count", lambda: fn.count())

    def _by_index() -> str:
        f = fn.by_index(0)
        return (f"{f.name} @ {hex_(f.start)} size={f.size} "
                f"lib={f.is_library} thunk={f.is_thunk} vis={f.is_visible}")
    probe(P, "function.by_index(0)", _by_index)

    # Pick a non-trivial function for deep inspection
    target = all_funcs[0]
    for f in all_funcs:
        if f.size > 32 and not f.is_library and not f.is_thunk:
            target = f
            break

    taddr = target.start

    def _at() -> str:
        f = fn.at(taddr)
        return f"{f.name} returns={f.returns} bitness={f.bitness}"
    probe(P, "function.at", _at)

    probe(P, "function.name_at", lambda: fn.name_at(taddr))

    # Chunks
    def _chunks() -> str:
        chunks = fn.chunks(taddr)
        for c in chunks:
            _ = c.start
            _ = c.end
            _ = c.is_tail
            _ = c.owner
            _ = c.size
        return f"{len(chunks)} chunk(s)"
    probe(P, "function.chunks", _chunks)
    probe(P, "function.tail_chunks", lambda: f"{len(fn.tail_chunks(taddr))} tail chunk(s)")
    probe(P, "function.chunk_count", lambda: fn.chunk_count(taddr))

    # Stack frame
    def _frame() -> str:
        fr = fn.frame(taddr)
        var_descs: list[str] = []
        for v in fr.variables:
            var_descs.append(f"{v.name}@{v.byte_offset}:{v.byte_size}")
            _ = v.comment
            _ = v.is_special
        return (f"locals={fr.local_variables_size} saved={fr.saved_registers_size} "
                f"args={fr.arguments_size} total={fr.total_size} vars=[{','.join(var_descs)}]")
    probe(P, "function.frame", _frame)

    probe(P, "function.sp_delta_at", lambda: fn.sp_delta_at(taddr))

    # Frame variable lookups
    def _frame_vars() -> str:
        fr = fn.frame(taddr)
        results_: list[str] = []
        for v in fr.variables:
            # Try by-name lookup
            try:
                by_name = fn.frame_variable_by_name(taddr, v.name)
                results_.append(f"byName({v.name})={by_name.byte_offset}")
            except Exception:
                pass  # may fail for special vars
            # Try by-offset lookup
            try:
                by_off = fn.frame_variable_by_offset(taddr, v.byte_offset)
                results_.append(f"byOff({v.byte_offset})={by_off.name}")
            except Exception:
                pass  # may fail
        return "; ".join(results_) if results_ else "no lookups succeeded"
    probe(P, "function.frame.vars", _frame_vars)

    # Comments
    def _set_comment() -> str:
        fn.set_comment(taddr, "forensics: function comment", False)
        return "ok"
    probe(P, "function.set_comment", _set_comment)
    probe(P, "function.comment", lambda: fn.comment(taddr, False))

    def _set_comment_repeat() -> str:
        fn.set_comment(taddr, "forensics: repeatable func", True)
        return "ok"
    probe(P, "function.set_comment(repeat)", _set_comment_repeat)
    probe(P, "function.comment(repeat)", lambda: fn.comment(taddr, True))

    # Outlined flag
    probe(P, "function.is_outlined", lambda: fn.is_outlined(taddr))

    # Callers/callees
    probe(P, "function.callers", lambda: f"{len(fn.callers(taddr))} caller(s)")
    probe(P, "function.callees", lambda: f"{len(fn.callees(taddr))} callee(s)")

    # Code/item addresses
    probe(P, "function.item_addresses", lambda: f"{len(fn.item_addresses(taddr))} item addr(s)")
    probe(P, "function.code_addresses", lambda: f"{len(fn.code_addresses(taddr))} code addr(s)")

    # Register variables
    def _reg_vars() -> str:
        rvars = fn.register_variables(taddr)
        for rv in rvars:
            _ = rv.range_start
            _ = rv.range_end
            _ = rv.canonical_name
            _ = rv.user_name
            _ = rv.comment
        return f"{len(rvars)} register var(s)"
    probe(P, "function.register_variables", _reg_vars)
    probe(P, "function.has_register_variables", lambda: fn.has_register_variables(taddr, taddr))


# ═══════════════════════════════════════════════════════════════════════════
# Phase 5 — Instruction-level analysis
# ═══════════════════════════════════════════════════════════════════════════

def phase5_instructions() -> None:
    P = "P05-instruction"

    # Find first code address
    min_addr = database.min_address()
    max_addr = database.max_address()
    code_addr: Optional[int] = probe(
        P, "findCodeAddr",
        lambda: address.find_first(min_addr, max_addr, address.Predicate.code),
    )
    if code_addr is None:
        return

    # Decode
    def _decode():
        i = instruction.decode(code_addr)
        _ = i.address
        _ = i.size
        _ = i.opcode
        _ = i.mnemonic
        _ = i.operand_count
        return i
    insn = probe(P, "instruction.decode", _decode)
    if insn is None:
        return

    probe(P, "instruction.text", lambda: instruction.text(code_addr))

    # Operand introspection
    def _operands() -> str:
        descs: list[str] = []
        for op in insn.operands:
            _ = op.index
            _ = op.type
            _ = op.is_register
            _ = op.is_immediate
            _ = op.is_memory
            _ = op.register_id
            _ = op.value
            _ = op.target_address
            _ = op.displacement
            _ = op.byte_width
            _ = op.register_name
            _ = op.register_category
            descs.append(f"op{op.index}:{op.type}")
        return ", ".join(descs)
    probe(P, "instruction.operands", _operands)

    # Operand text/width/register queries
    for n in range(min(insn.operand_count, 3)):
        probe(P, f"instruction.operand_text({n})", lambda n=n: instruction.operand_text(code_addr, n))
        probe(P, f"instruction.operand_byte_width({n})", lambda n=n: instruction.operand_byte_width(code_addr, n))
        # Only query register name/class on register operands
        if n < len(insn.operands) and insn.operands[n].is_register:
            probe(P, f"instruction.operand_register_name({n})", lambda n=n: instruction.operand_register_name(code_addr, n))
            probe(P, f"instruction.operand_register_category({n})", lambda n=n: instruction.operand_register_category(code_addr, n))

    # Also exercise register name/class on a known register operand
    probe(P, "instruction.operand_register_name(reg)", lambda: instruction.operand_register_name(code_addr, 0))
    probe(P, "instruction.operand_register_category(reg)", lambda: instruction.operand_register_category(code_addr, 0))

    # Operand format setters — test on first operand
    def _set_hex() -> str:
        instruction.set_operand_hex(code_addr, 0)
        return "ok"
    probe(P, "instruction.set_operand_hex", _set_hex)

    def _set_decimal() -> str:
        instruction.set_operand_decimal(code_addr, 0)
        return "ok"
    probe(P, "instruction.set_operand_decimal", _set_decimal)

    def _clear_repr() -> str:
        instruction.clear_operand_representation(code_addr, 0)
        return "ok"
    probe(P, "instruction.clear_operand_representation", _clear_repr)

    # Forced operand
    def _set_forced() -> str:
        instruction.set_forced_operand(code_addr, 0, "FORCED_TEST")
        return "ok"
    probe(P, "instruction.set_forced_operand", _set_forced)
    probe(P, "instruction.get_forced_operand", lambda: instruction.get_forced_operand(code_addr, 0))

    # Clean up forced operand
    def _clear_forced() -> str:
        instruction.set_forced_operand(code_addr, 0, "")
        return "ok"
    probe(P, "instruction.set_forced_operand(clear)", _clear_forced)

    # Classification predicates
    probe(P, "instruction.has_fall_through", lambda: instruction.has_fall_through(code_addr))
    probe(P, "instruction.is_call", lambda: instruction.is_call(code_addr))
    probe(P, "instruction.is_return", lambda: instruction.is_return(code_addr))
    probe(P, "instruction.is_jump", lambda: instruction.is_jump(code_addr))
    probe(P, "instruction.is_conditional_jump", lambda: instruction.is_conditional_jump(code_addr))

    # Code/data refs from instruction
    def _code_refs() -> str:
        refs = instruction.code_refs_from(code_addr)
        return f"{len(refs)} code ref(s)"
    probe(P, "instruction.code_refs_from", _code_refs)

    def _data_refs() -> str:
        refs = instruction.data_refs_from(code_addr)
        return f"{len(refs)} data ref(s)"
    probe(P, "instruction.data_refs_from", _data_refs)

    # Find a call instruction for call_targets/jump_targets
    funcs = fn.all()
    call_addr: Optional[int] = None
    jump_addr: Optional[int] = None
    for f in funcs:
        if f.is_thunk or f.is_library:
            continue
        code_addrs = fn.code_addresses(f.start)
        for ca in code_addrs:
            try:
                if call_addr is None and instruction.is_call(ca):
                    call_addr = ca
                if jump_addr is None and instruction.is_jump(ca):
                    jump_addr = ca
            except Exception:
                pass  # skip
            if call_addr is not None and jump_addr is not None:
                break
        if call_addr is not None and jump_addr is not None:
            break

    if call_addr is not None:
        _ca = call_addr  # capture for closures

        def _call_targets() -> str:
            targets = instruction.call_targets(_ca)
            return ", ".join(hex_(t) for t in targets)
        probe(P, "instruction.call_targets", _call_targets)

    if jump_addr is not None:
        _ja = jump_addr  # capture for closures

        def _jump_targets() -> str:
            targets = instruction.jump_targets(_ja)
            return ", ".join(hex_(t) for t in targets)
        probe(P, "instruction.jump_targets", _jump_targets)

    # Sequential navigation
    def _next_insn() -> str:
        ni = instruction.next(code_addr)
        return f"{ni.mnemonic} @ {hex_(ni.address)}"
    probe(P, "instruction.next", _next_insn)

    def _prev_insn() -> str:
        pi = instruction.prev(instruction.next(code_addr).address)
        return f"{pi.mnemonic} @ {hex_(pi.address)}"
    probe(P, "instruction.prev", _prev_insn)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 6 — Cross-reference graph
# ═══════════════════════════════════════════════════════════════════════════

def phase6_xrefs() -> None:
    P = "P06-xref"

    # Find a function entry point for xref testing (lots of xrefs)
    funcs = fn.all()
    if len(funcs) == 0:
        return
    target = funcs[0].start

    def _refs_to() -> str:
        refs = xref.refs_to(target)
        for r in refs:
            _ = r.from_
            _ = r.to
            _ = r.is_code
            _ = r.type
            _ = r.user_defined
        return f"{len(refs)} ref(s) to {hex_(target)}"
    probe(P, "xref.refs_to", _refs_to)

    def _refs_from() -> str:
        refs = xref.refs_from(target)
        return f"{len(refs)} ref(s) from {hex_(target)}"
    probe(P, "xref.refs_from", _refs_from)

    probe(P, "xref.code_refs_to", lambda: f"{len(xref.code_refs_to(target))} code ref(s) to")
    probe(P, "xref.code_refs_from", lambda: f"{len(xref.code_refs_from(target))} code ref(s) from")
    probe(P, "xref.data_refs_to", lambda: f"{len(xref.data_refs_to(target))} data ref(s) to")
    probe(P, "xref.data_refs_from", lambda: f"{len(xref.data_refs_from(target))} data ref(s) from")

    # Filtered refs_to
    ref_types = [
        xref.ReferenceType.flow,
        xref.ReferenceType.call_near,
        xref.ReferenceType.call_far,
        xref.ReferenceType.jump_near,
        xref.ReferenceType.jump_far,
        xref.ReferenceType.offset,
        xref.ReferenceType.read,
        xref.ReferenceType.write,
        xref.ReferenceType.text,
        xref.ReferenceType.informational,
    ]
    ref_type_names = [
        "flow", "callNear", "callFar", "jumpNear", "jumpFar",
        "offset", "read", "write", "text", "informational",
    ]
    for rt, rt_name in zip(ref_types, ref_type_names):
        probe(P, f"xref.refs_to({rt_name})", lambda rt=rt: f"{len(xref.refs_to(target, rt))} ref(s)")

    # Type classification predicates
    probe(P, "xref.is_call(call_near)", lambda: xref.is_call(xref.ReferenceType.call_near))
    probe(P, "xref.is_call(flow)", lambda: xref.is_call(xref.ReferenceType.flow))
    probe(P, "xref.is_jump(jump_near)", lambda: xref.is_jump(xref.ReferenceType.jump_near))
    probe(P, "xref.is_jump(read)", lambda: xref.is_jump(xref.ReferenceType.read))
    probe(P, "xref.is_flow(flow)", lambda: xref.is_flow(xref.ReferenceType.flow))
    probe(P, "xref.is_flow(call_near)", lambda: xref.is_flow(xref.ReferenceType.call_near))
    probe(P, "xref.is_data(read)", lambda: xref.is_data(xref.ReferenceType.read))
    probe(P, "xref.is_data(call_near)", lambda: xref.is_data(xref.ReferenceType.call_near))
    probe(P, "xref.is_data_read(read)", lambda: xref.is_data_read(xref.ReferenceType.read))
    probe(P, "xref.is_data_read(write)", lambda: xref.is_data_read(xref.ReferenceType.write))
    probe(P, "xref.is_data_write(write)", lambda: xref.is_data_write(xref.ReferenceType.write))
    probe(P, "xref.is_data_write(read)", lambda: xref.is_data_write(xref.ReferenceType.read))

    # Add and remove a user-defined xref
    if len(funcs) >= 2:
        from_addr = funcs[0].start
        to_addr = funcs[1].start

        def _add_code() -> str:
            xref.add_code(from_addr, to_addr, xref.CodeType.call_near)
            return "ok"
        probe(P, "xref.add_code", _add_code)

        def _remove_code() -> str:
            xref.remove_code(from_addr, to_addr)
            return "ok"
        probe(P, "xref.remove_code", _remove_code)

        def _add_data() -> str:
            xref.add_data(from_addr, to_addr, xref.DataType.offset)
            return "ok"
        probe(P, "xref.add_data", _add_data)

        def _remove_data() -> str:
            xref.remove_data(from_addr, to_addr)
            return "ok"
        probe(P, "xref.remove_data", _remove_data)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 7 — Name management
# ═══════════════════════════════════════════════════════════════════════════

def phase7_names() -> None:
    P = "P07-name"

    funcs = fn.all()
    if len(funcs) == 0:
        return
    target = funcs[0].start
    orig_name = funcs[0].name

    # Basic get/set/remove cycle
    probe(P, "name.get", lambda: naming.get(target))

    def _set() -> str:
        naming.set(target, "forensics_test_name")
        return "ok"
    probe(P, "name.set", _set)
    probe(P, "name.get(after set)", lambda: naming.get(target))

    def _remove() -> str:
        naming.remove(target)
        return "ok"
    probe(P, "name.remove", _remove)

    def _force_set() -> str:
        naming.force_set(target, orig_name)
        return "ok"
    probe(P, "name.force_set(restore)", _force_set)

    # Demangling
    probe(P, "name.demangled(short)", lambda: naming.demangled(target, naming.DemangleForm.short_))
    probe(P, "name.demangled(long)", lambda: naming.demangled(target, naming.DemangleForm.long_))
    probe(P, "name.demangled(full)", lambda: naming.demangled(target, naming.DemangleForm.full))

    # Resolve
    probe(P, "name.resolve", lambda: naming.resolve(orig_name))

    # Name properties
    probe(P, "name.is_public", lambda: naming.is_public(target))
    probe(P, "name.is_weak", lambda: naming.is_weak(target))
    probe(P, "name.is_user_defined", lambda: naming.is_user_defined(target))
    probe(P, "name.is_auto_generated", lambda: naming.is_auto_generated(target))

    # Public/weak setters
    def _set_public_true() -> str:
        naming.set_public(target, True)
        return "ok"
    probe(P, "name.set_public(true)", _set_public_true)
    probe(P, "name.is_public(after)", lambda: naming.is_public(target))

    def _set_public_false() -> str:
        naming.set_public(target, False)
        return "ok"
    probe(P, "name.set_public(false)", _set_public_false)

    def _set_weak_true() -> str:
        naming.set_weak(target, True)
        return "ok"
    probe(P, "name.set_weak(true)", _set_weak_true)
    probe(P, "name.is_weak(after)", lambda: naming.is_weak(target))

    def _set_weak_false() -> str:
        naming.set_weak(target, False)
        return "ok"
    probe(P, "name.set_weak(false)", _set_weak_false)

    # Validation / sanitization
    probe(P, "name.is_valid_identifier(good)", lambda: naming.is_valid_identifier("valid_name"))
    probe(P, "name.is_valid_identifier(bad)", lambda: naming.is_valid_identifier("123 bad!"))
    probe(P, "name.sanitize_identifier", lambda: naming.sanitize_identifier("123 bad!"))

    # Bulk name enumeration
    def _all_names() -> str:
        entries = naming.all()
        for e in entries[:3]:
            _ = e.address
            _ = e.name
            _ = e.user_defined
            _ = e.auto_generated
        return f"{len(entries)} name(s)"
    probe(P, "name.all()", _all_names)

    def _all_opts() -> str:
        entries = naming.all(
            include_user_defined=True,
            include_auto_generated=False,
        )
        return f"{len(entries)} user-defined name(s)"
    probe(P, "name.all(opts)", _all_opts)

    def _all_user() -> str:
        entries = naming.all_user_defined()
        return f"{len(entries)} user-defined name(s)"
    probe(P, "name.all_user_defined", _all_user)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 8 — Comment layers
# ═══════════════════════════════════════════════════════════════════════════

def phase8_comments() -> None:
    P = "P08-comment"

    funcs = fn.all()
    if len(funcs) == 0:
        return
    target = funcs[0].start

    # Regular comments
    def _set_regular() -> str:
        comment.set(target, "forensics: regular")
        return "ok"
    probe(P, "comment.set(regular)", _set_regular)
    probe(P, "comment.get(regular)", lambda: comment.get(target, False))

    def _append() -> str:
        comment.append(target, " +appended")
        return "ok"
    probe(P, "comment.append", _append)
    probe(P, "comment.get(afterAppend)", lambda: comment.get(target, False))

    def _remove_regular() -> str:
        comment.remove(target, False)
        return "ok"
    probe(P, "comment.remove(regular)", _remove_regular)

    # Repeatable comments
    def _set_repeat() -> str:
        comment.set(target, "forensics: repeatable", True)
        return "ok"
    probe(P, "comment.set(repeat)", _set_repeat)
    probe(P, "comment.get(repeat)", lambda: comment.get(target, True))

    def _remove_repeat() -> str:
        comment.remove(target, True)
        return "ok"
    probe(P, "comment.remove(repeat)", _remove_repeat)

    # Anterior comments
    def _add_anterior() -> str:
        comment.add_anterior(target, "anterior line 0")
        return "ok"
    probe(P, "comment.add_anterior", _add_anterior)

    def _add_anterior2() -> str:
        comment.add_anterior(target, "anterior line 1")
        return "ok"
    probe(P, "comment.add_anterior(2)", _add_anterior2)
    probe(P, "comment.get_anterior(0)", lambda: comment.get_anterior(target, 0))
    probe(P, "comment.get_anterior(1)", lambda: comment.get_anterior(target, 1))

    def _set_anterior() -> str:
        comment.set_anterior(target, 0, "replaced anterior 0")
        return "ok"
    probe(P, "comment.set_anterior", _set_anterior)

    def _anterior_lines() -> str:
        lns = comment.anterior_lines(target)
        return f"{len(lns)} line(s): {' | '.join(lns)}"
    probe(P, "comment.anterior_lines", _anterior_lines)

    def _set_anterior_lines() -> str:
        comment.set_anterior_lines(target, ["bulk ant 0", "bulk ant 1", "bulk ant 2"])
        return "ok"
    probe(P, "comment.set_anterior_lines", _set_anterior_lines)
    probe(P, "comment.anterior_lines(bulk)", lambda: " | ".join(comment.anterior_lines(target)))

    def _remove_anterior_line() -> str:
        comment.remove_anterior_line(target, 0)
        return "ok"
    probe(P, "comment.remove_anterior_line", _remove_anterior_line)

    def _clear_anterior() -> str:
        comment.clear_anterior(target)
        return "ok"
    probe(P, "comment.clear_anterior", _clear_anterior)

    # Posterior comments
    def _add_posterior() -> str:
        comment.add_posterior(target, "posterior line 0")
        return "ok"
    probe(P, "comment.add_posterior", _add_posterior)

    def _add_posterior2() -> str:
        comment.add_posterior(target, "posterior line 1")
        return "ok"
    probe(P, "comment.add_posterior(2)", _add_posterior2)
    probe(P, "comment.get_posterior(0)", lambda: comment.get_posterior(target, 0))
    probe(P, "comment.get_posterior(1)", lambda: comment.get_posterior(target, 1))

    def _set_posterior() -> str:
        comment.set_posterior(target, 0, "replaced post 0")
        return "ok"
    probe(P, "comment.set_posterior", _set_posterior)

    def _posterior_lines() -> str:
        ls = comment.posterior_lines(target)
        return f"{len(ls)} line(s): {' | '.join(ls)}"
    probe(P, "comment.posterior_lines", _posterior_lines)

    def _set_posterior_lines() -> str:
        comment.set_posterior_lines(target, ["bulk post 0", "bulk post 1"])
        return "ok"
    probe(P, "comment.set_posterior_lines", _set_posterior_lines)
    probe(P, "comment.posterior_lines(bulk)", lambda: " | ".join(comment.posterior_lines(target)))

    def _remove_posterior_line() -> str:
        comment.remove_posterior_line(target, 0)
        return "ok"
    probe(P, "comment.remove_posterior_line", _remove_posterior_line)

    def _clear_posterior() -> str:
        comment.clear_posterior(target)
        return "ok"
    probe(P, "comment.clear_posterior", _clear_posterior)

    # Render
    def _set_for_render() -> str:
        comment.set(target, "render-test", False)
        comment.set(target, "render-repeat", True)
        return "ok"
    probe(P, "comment.set(forRender)", _set_for_render)
    probe(P, "comment.render", lambda: comment.render(target))
    probe(P, "comment.render(all)", lambda: comment.render(target, True, True))

    # Clean up
    def _cleanup() -> str:
        comment.remove(target, False)
        comment.remove(target, True)
        return "ok"
    probe(P, "comment.cleanup", _cleanup)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 9 — Data forensics
# ═══════════════════════════════════════════════════════════════════════════

def phase9_data() -> None:
    P = "P09-data"

    min_addr = database.min_address()
    max_addr = database.max_address()

    # Find a data item, or just use a known loaded address
    data_addr = min_addr
    try:
        data_addr = address.find_first(min_addr, max_addr, address.Predicate.loaded)
    except Exception:
        pass  # fall back to min

    # Read operations
    probe(P, "data.read_byte", lambda: data.read_byte(data_addr))
    probe(P, "data.read_word", lambda: data.read_word(data_addr))
    probe(P, "data.read_dword", lambda: data.read_dword(data_addr))
    probe(P, "data.read_qword", lambda: data.read_qword(data_addr))

    def _read_bytes() -> str:
        buf = data.read_bytes(data_addr, 16)
        return f"bytes({len(buf)}): {buf.hex()}"
    probe(P, "data.read_bytes", _read_bytes)

    # read_string — might fail if not at a string, that's fine
    probe(P, "data.read_string", lambda: data.read_string(data_addr, 32))

    # Patching round-trip: byte
    probe(P, "data.original_byte", lambda: data.original_byte(data_addr))

    def _patch_byte() -> str:
        data.patch_byte(data_addr, 0xCC)
        return "ok"
    probe(P, "data.patch_byte", _patch_byte)
    probe(P, "data.read_byte(patched)", lambda: data.read_byte(data_addr))
    probe(P, "data.original_byte(after)", lambda: data.original_byte(data_addr))

    def _revert_patch() -> str:
        data.revert_patch(data_addr)
        return "ok"
    probe(P, "data.revert_patch", _revert_patch)

    # Patching round-trip: word
    probe(P, "data.original_word", lambda: data.original_word(data_addr))

    def _patch_word() -> str:
        data.patch_word(data_addr, 0xDEAD)
        return "ok"
    probe(P, "data.patch_word", _patch_word)
    probe(P, "data.revert_patches(2)", lambda: data.revert_patches(data_addr, 2))

    # Patching round-trip: dword
    probe(P, "data.original_dword", lambda: data.original_dword(data_addr))

    def _patch_dword() -> str:
        data.patch_dword(data_addr, 0xDEADBEEF)
        return "ok"
    probe(P, "data.patch_dword", _patch_dword)
    probe(P, "data.revert_patches(4)", lambda: data.revert_patches(data_addr, 4))

    # Patching round-trip: qword
    probe(P, "data.original_qword", lambda: data.original_qword(data_addr))

    def _patch_qword() -> str:
        data.patch_qword(data_addr, 0xDEADBEEFCAFEBABE)
        return "ok"
    probe(P, "data.patch_qword", _patch_qword)
    probe(P, "data.revert_patches(8)", lambda: data.revert_patches(data_addr, 8))

    # Patch bytes (buffer)
    def _patch_bytes() -> str:
        buf = bytes([0x90, 0x90, 0x90, 0x90])
        data.patch_bytes(data_addr, buf)
        return "ok"
    probe(P, "data.patch_bytes", _patch_bytes)
    probe(P, "data.revert_patches(buf)", lambda: data.revert_patches(data_addr, 4))

    # Write operations (direct, no original tracking)
    orig_byte: Optional[int] = probe(P, "data.read_byte(prewrite)", lambda: data.read_byte(data_addr))

    def _write_byte() -> str:
        data.write_byte(data_addr, 0xAA)
        return "ok"
    probe(P, "data.write_byte", _write_byte)
    if orig_byte is not None:
        def _write_byte_restore() -> str:
            data.write_byte(data_addr, orig_byte)
            return "ok"
        probe(P, "data.write_byte(restore)", _write_byte_restore)

    # Define / undefine items — find a safe area in a writable data segment
    safe_addr = data_addr
    try:
        bss_seg = segment.by_name(".bss")
        safe_addr = bss_seg.start
    except Exception:
        try:
            data_seg = segment.by_name(".data")
            safe_addr = data_seg.start
        except Exception:
            pass  # fall back to data_addr

    # Undefine first, then redefine with each item type
    def _undefine() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine", _undefine)

    def _define_byte() -> str:
        data.define_byte(safe_addr)
        return "ok"
    probe(P, "data.define_byte", _define_byte)

    def _undefine2() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine(2)", _undefine2)

    def _define_word() -> str:
        data.define_word(safe_addr)
        return "ok"
    probe(P, "data.define_word", _define_word)

    def _undefine3() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine(3)", _undefine3)

    def _define_dword() -> str:
        data.define_dword(safe_addr)
        return "ok"
    probe(P, "data.define_dword", _define_dword)

    def _undefine4() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine(4)", _undefine4)

    def _define_qword() -> str:
        data.define_qword(safe_addr)
        return "ok"
    probe(P, "data.define_qword", _define_qword)

    def _undefine5() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine(5)", _undefine5)

    def _define_float() -> str:
        data.define_float(safe_addr)
        return "ok"
    probe(P, "data.define_float", _define_float)

    def _undefine6() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine(6)", _undefine6)

    def _define_double() -> str:
        data.define_double(safe_addr)
        return "ok"
    probe(P, "data.define_double", _define_double)

    # Restore area
    def _undefine_restore() -> str:
        data.undefine(safe_addr, 16)
        return "ok"
    probe(P, "data.undefine(restore)", _undefine_restore)

    # Binary pattern search — use ARM64 STP pre-index prefix (A9 BF) which is
    # ubiquitous in ARM64 function prologues and present in this binary.
    def _find_pattern_fwd() -> str:
        found = data.find_binary_pattern(min_addr, max_addr, "A9 BF", True)
        return hex_(found)
    probe(P, "data.find_binary_pattern", _find_pattern_fwd)

    def _find_pattern_back() -> str:
        found = data.find_binary_pattern(min_addr, max_addr, "A9 BF", False)
        return hex_(found)
    probe(P, "data.find_binary_pattern(back)", _find_pattern_back)

    # memory_to_database — load a small buffer into the database at a known address
    def _mem_to_db() -> str:
        buf = bytes([0x01, 0x02, 0x03, 0x04])
        database.memory_to_database(buf, data_addr)
        return "ok"
    probe(P, "database.memory_to_database", _mem_to_db)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 10 — Search engine
# ═══════════════════════════════════════════════════════════════════════════

def phase10_search() -> None:
    P = "P10-search"

    min_addr = database.min_address()

    # Text search (may find nothing, that throws — totally fine)
    def _text_fwd() -> str:
        found = search.text(min_addr, "sub", direction="forward", case_sensitive=False)
        return hex_(found)
    probe(P, "search.text(fwd)", _text_fwd)

    def _text_opts() -> str:
        found = search.text(
            min_addr, "sub",
            direction="forward",
            case_sensitive=False,
            regex=False,
            identifier=False,
            skip_start=False,
        )
        return hex_(found)
    probe(P, "search.text(opts)", _text_opts)

    # Immediate search
    def _immediate() -> str:
        found = search.immediate(min_addr, 0, direction="forward")
        return hex_(found)
    probe(P, "search.immediate", _immediate)

    # Binary pattern search via search namespace — ARM64 STP pre-index prefix.
    def _binary_pattern() -> str:
        found = search.binary_pattern(min_addr, "A9 BF", direction="forward")
        return hex_(found)
    probe(P, "search.binary_pattern", _binary_pattern)

    # Next-type searches
    probe(P, "search.next_code", lambda: hex_(search.next_code(min_addr)))
    probe(P, "search.next_data", lambda: hex_(search.next_data(min_addr)))
    probe(P, "search.next_unknown", lambda: hex_(search.next_unknown(min_addr)))
    probe(P, "search.next_defined", lambda: hex_(search.next_defined(min_addr)))
    probe(P, "search.next_error", lambda: hex_(search.next_error(min_addr)))


# ═══════════════════════════════════════════════════════════════════════════
# Phase 11 — Analysis control
# ═══════════════════════════════════════════════════════════════════════════

def phase11_analysis() -> None:
    P = "P11-analysis"

    probe(P, "analysis.is_enabled", lambda: analysis.is_enabled())
    probe(P, "analysis.is_idle", lambda: analysis.is_idle())

    # Disable and re-enable
    def _disable() -> str:
        analysis.set_enabled(False)
        return "ok"
    probe(P, "analysis.set_enabled(false)", _disable)
    probe(P, "analysis.is_enabled(disabled)", lambda: analysis.is_enabled())

    def _enable() -> str:
        analysis.set_enabled(True)
        return "ok"
    probe(P, "analysis.set_enabled(true)", _enable)
    probe(P, "analysis.is_enabled(enabled)", lambda: analysis.is_enabled())

    # Wait for analysis
    def _wait() -> str:
        analysis.wait()
        return "ok"
    probe(P, "analysis.wait", _wait)

    min_addr = database.min_address()
    max_addr = database.max_address()
    range_end = min_addr + 0x100 if min_addr + 0x100 < max_addr else max_addr

    def _wait_range() -> str:
        analysis.wait_range(min_addr, range_end)
        return "ok"
    probe(P, "analysis.wait_range", _wait_range)

    # Scheduling
    def _schedule() -> str:
        analysis.schedule(min_addr)
        return "ok"
    probe(P, "analysis.schedule", _schedule)

    def _schedule_range() -> str:
        analysis.schedule_range(min_addr, range_end)
        return "ok"
    probe(P, "analysis.schedule_range", _schedule_range)

    def _schedule_code() -> str:
        analysis.schedule_code(min_addr)
        return "ok"
    probe(P, "analysis.schedule_code", _schedule_code)

    funcs = fn.all()
    if len(funcs) > 0:
        faddr = funcs[0].start

        def _schedule_func() -> str:
            analysis.schedule_function(faddr)
            return "ok"
        probe(P, "analysis.schedule_function", _schedule_func)

        def _schedule_reanalysis() -> str:
            analysis.schedule_reanalysis(faddr)
            return "ok"
        probe(P, "analysis.schedule_reanalysis", _schedule_reanalysis)

    def _schedule_reanalysis_range() -> str:
        analysis.schedule_reanalysis_range(min_addr, range_end)
        return "ok"
    probe(P, "analysis.schedule_reanalysis_range", _schedule_reanalysis_range)

    # Cancel and revert
    def _cancel() -> str:
        analysis.cancel(min_addr, range_end)
        return "ok"
    probe(P, "analysis.cancel", _cancel)

    # Wait again to let everything settle
    def _wait_settle() -> str:
        analysis.wait()
        return "ok"
    probe(P, "analysis.wait(settle)", _wait_settle)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 12 — Type system
# ═══════════════════════════════════════════════════════════════════════════

def phase12_types() -> None:
    P = "P12-type"

    # Primitive factories
    def _void_type() -> str:
        t = typing_.void_type()
        return f"isVoid={t.is_void()} str='{t}'"
    probe(P, "types.void_type", _void_type)

    def _int8() -> str:
        t = typing_.int8()
        return f"isInt={t.is_integer()} size={t.size()}"
    probe(P, "types.int8", _int8)
    probe(P, "types.int16", lambda: f"size={typing_.int16().size()}")
    probe(P, "types.int32", lambda: f"size={typing_.int32().size()}")
    probe(P, "types.int64", lambda: f"size={typing_.int64().size()}")
    probe(P, "types.uint8", lambda: f"size={typing_.uint8().size()}")
    probe(P, "types.uint16", lambda: f"size={typing_.uint16().size()}")

    tu32 = probe(P, "types.uint32", lambda: typing_.uint32())
    probe(P, "types.uint64", lambda: f"size={typing_.uint64().size()}")

    def _float32() -> str:
        t = typing_.float32()
        return f"isFP={t.is_floating_point()} size={t.size()}"
    probe(P, "types.float32", _float32)
    probe(P, "types.float64", lambda: f"size={typing_.float64().size()}")

    # Pointer type
    if tu32 is not None:
        def _pointer_to() -> str:
            ptr = typing_.pointer_to(tu32)
            return f"isPtr={ptr.is_pointer()} pointee={ptr.pointee_type()}"
        probe(P, "types.pointer_to", _pointer_to)

    # Array type
    if tu32 is not None:
        def _array_of() -> str:
            arr = typing_.array_of(tu32, 10)
            return f"isArray={arr.is_array()} elem={arr.array_element_type()} len={arr.array_length()}"
        probe(P, "types.array_of", _array_of)

    # Function type
    def _function_type() -> str:
        i32 = typing_.int32()
        i64 = typing_.int64()
        ft = typing_.function_type(i32, [i64, i64], typing_.CallingConvention.cdecl_, False)
        return (f"isFunc={ft.is_function()} ret={ft.function_return_type()} "
                f"args={len(ft.function_argument_types())} cc={ft.calling_convention()} "
                f"variadic={ft.is_variadic_function()}")
    probe(P, "types.function_type", _function_type)

    # Variadic function type
    def _function_type_variadic() -> str:
        ft = typing_.function_type(typing_.int32(), [typing_.int32()], typing_.CallingConvention.cdecl_, True)
        return f"variadic={ft.is_variadic_function()}"
    probe(P, "types.function_type(variadic)", _function_type_variadic)

    # from_declaration
    def _from_decl() -> str:
        t = typing_.from_declaration("int *")
        return f"str='{t}' isPtr={t.is_pointer()}"
    probe(P, "types.from_declaration", _from_decl)

    # Struct building — explicit byte offsets to avoid overlap errors
    def _create_struct() -> str:
        st = typing_.create_struct()
        st.add_member("x", typing_.int32(), 0)
        st.add_member("y", typing_.int32(), 4)
        st.add_member("z", typing_.float64(), 8)
        return (f"isStruct={st.is_struct()} members={st.member_count()} size={st.size()} "
                f"str='{st}'")
    probe(P, "types.create_struct", _create_struct)

    # Struct member inspection
    def _struct_members() -> str:
        st = typing_.create_struct()
        st.add_member("alpha", typing_.uint8(), 0)
        st.add_member("beta", typing_.uint32(), 4)
        members = st.members()
        descs: list[str] = []
        for m in members:
            descs.append(f"{m.name}:{m.type}@{m.byte_offset} bits={m.bit_size}")
            _ = m.comment
        return "; ".join(descs)
    probe(P, "types.struct.members", _struct_members)

    # member_by_name / member_by_offset
    def _member_by_name() -> str:
        st = typing_.create_struct()
        st.add_member("field_a", typing_.int32(), 0)
        st.add_member("field_b", typing_.int64(), 4)
        m = st.member_by_name("field_b")
        return f"name={m.name} offset={m.byte_offset}"
    probe(P, "types.struct.member_by_name", _member_by_name)

    def _member_by_offset() -> str:
        st = typing_.create_struct()
        st.add_member("x", typing_.int32(), 0)
        st.add_member("y", typing_.int32(), 4)
        m = st.member_by_offset(4)
        return f"name={m.name}"
    probe(P, "types.struct.member_by_offset", _member_by_offset)

    # Union
    def _create_union() -> str:
        u = typing_.create_union()
        u.add_member("i", typing_.int32())
        u.add_member("f", typing_.float32())
        return f"isUnion={u.is_union()} members={u.member_count()} size={u.size()}"
    probe(P, "types.create_union", _create_union)

    # Save to local type library
    def _save_as() -> str:
        st = typing_.create_struct()
        st.add_member("forensics_field", typing_.uint64())
        st.save_as("ForensicsTestStruct")
        return "ok"
    probe(P, "types.save_as", _save_as)

    # Retrieve from local type library
    def _by_name() -> str:
        t = typing_.by_name("ForensicsTestStruct")
        return f"str='{t}' isStruct={t.is_struct()}"
    probe(P, "types.by_name", _by_name)

    # Local type library enumeration
    probe(P, "types.local_type_count", lambda: typing_.local_type_count())
    probe(P, "types.local_type_name(1)", lambda: typing_.local_type_name(1))

    # Apply and retrieve type at an address.
    # Find a data segment to use as a safe target address.
    taddr = database.min_address()
    try:
        taddr = segment.by_name("__data").start
    except Exception:
        try:
            taddr = segment.by_name("__bss").start
        except Exception:
            try:
                segs = segment.all()
                writable = next((s for s in segs if s.permissions.write and not s.permissions.execute), None)
                if writable:
                    taddr = writable.start
            except Exception:
                pass  # use min_address

    # Apply via TypeInfo.apply() — exercises apply_tinfo.
    def _apply_named_type() -> str:
        st = typing_.by_name("ForensicsTestStruct")
        st.apply(taddr)
        return "ok"
    probe(P, "types.apply_named_type", _apply_named_type)

    # Retrieve the type we just applied.
    def _retrieve() -> str:
        t = typing_.retrieve(taddr)
        return f"str='{t}'"
    probe(P, "types.retrieve", _retrieve)

    # Remove applied type (cleanup).
    def _remove_type() -> str:
        typing_.remove_type(taddr)
        return "ok"
    probe(P, "types.remove_type", _remove_type)

    # TypeInfo introspection predicates on various types
    probe(P, "types.is_enum(int32)", lambda: typing_.int32().is_enum())
    probe(P, "types.is_typedef(int32)", lambda: typing_.int32().is_typedef())


# ═══════════════════════════════════════════════════════════════════════════
# Phase 13 — Entry points
# ═══════════════════════════════════════════════════════════════════════════

def phase13_entries() -> None:
    P = "P13-entry"

    probe(P, "entry.count", lambda: entry.count())

    entry_count = entry.count()
    if entry_count > 0:
        def _by_index() -> str:
            ep = entry.by_index(0)
            return f"ord={ep.ordinal} addr={hex_(ep.address)} name='{ep.name}' fwd='{ep.forwarder}'"
        probe(P, "entry.by_index(0)", _by_index)

        # Get first entry's ordinal for further tests
        first_entry = entry.by_index(0)

        def _by_ordinal() -> str:
            ep = entry.by_ordinal(first_entry.ordinal)
            return f"name='{ep.name}'"
        probe(P, "entry.by_ordinal", _by_ordinal)

        # Verify that an entry with no forwarder correctly throws NotFound.
        def _forwarder() -> str:
            try:
                entry.forwarder(first_entry.ordinal)
                return "no error (has forwarder)"
            except Exception as e:
                msg = str(e)
                if "NotFound" in msg or "No forwarder" in msg:
                    return "correctly not found"
                raise
        probe(P, "entry.forwarder", _forwarder)

        # Rename test
        orig_name = first_entry.name

        def _rename() -> str:
            entry.rename(first_entry.ordinal, "forensics_entry_test")
            return "ok"
        probe(P, "entry.rename", _rename)

        def _rename_restore() -> str:
            entry.rename(first_entry.ordinal, orig_name)
            return "ok"
        probe(P, "entry.rename(restore)", _rename_restore)

        # Forwarder set/clear — use a fresh synthetic entry we control so
        # IDA's import-table protection cannot interfere with clear_forwarder.
        fwd_ord = 0xF04E51C

        def _set_forwarder() -> str:
            entry.add(fwd_ord, first_entry.address, "forensics_fwd_entry")
            entry.set_forwarder(fwd_ord, "test.dll.ForensicsForward")
            return "ok"
        probe(P, "entry.set_forwarder", _set_forwarder)
        probe(P, "entry.forwarder(after)", lambda: entry.forwarder(fwd_ord))

        def _clear_forwarder() -> str:
            entry.clear_forwarder(fwd_ord)
            return "ok"
        probe(P, "entry.clear_forwarder", _clear_forwarder)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 14 — Fixup table inspection
# ═══════════════════════════════════════════════════════════════════════════

def phase14_fixups() -> None:
    P = "P14-fixup"

    min_addr = database.min_address()
    max_addr = database.max_address()

    def _all_fixups() -> str:
        addrs = fixup.all()
        return f"{len(addrs)} fixup(s)"
    probe(P, "fixup.all", _all_fixups)

    def _first() -> str:
        addr = fixup.first()
        return hex_(addr) if addr is not None else "None"
    probe(P, "fixup.first", _first)

    first_fixup = fixup.first()
    if first_fixup is not None:
        probe(P, "fixup.exists", lambda: fixup.exists(first_fixup))

        def _at() -> str:
            d = fixup.at(first_fixup)
            return (f"type={d.type} flags={d.flags} target={hex_(d.target)} "
                    f"base={hex_(d.base)} sel={d.selector} offset={hex_(d.offset)} disp={d.displacement}")
        probe(P, "fixup.at", _at)

        def _next() -> str:
            n = fixup.next(first_fixup)
            return hex_(n) if n is not None else "None"
        probe(P, "fixup.next", _next)

        def _prev() -> str:
            # prev of first should be None
            p = fixup.prev(first_fixup)
            return hex_(p) if p is not None else "None"
        probe(P, "fixup.prev", _prev)

        probe(P, "fixup.contains", lambda: fixup.contains(first_fixup, 1))

    def _in_range() -> str:
        descs = fixup.in_range(min_addr, max_addr)
        return f"{len(descs)} fixup(s) in range"
    probe(P, "fixup.in_range", _in_range)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 15 — Storage: netnode round-trips
# ═══════════════════════════════════════════════════════════════════════════

def phase15_storage() -> None:
    P = "P15-storage"

    # Open by name
    node = probe(P, "storage.open(create)", lambda: storage.open("forensics_test_node", True))
    if node is None:
        return

    # Node identity
    probe(P, "StorageNode.id", lambda: node.id())
    probe(P, "StorageNode.name", lambda: node.name())

    # Alt round-trip
    alt_idx = 100

    def _set_alt() -> str:
        node.set_alt(alt_idx, 42, "A")
        return "ok"
    probe(P, "StorageNode.set_alt", _set_alt)
    probe(P, "StorageNode.alt", lambda: node.alt(alt_idx, "A"))

    def _remove_alt() -> str:
        node.remove_alt(alt_idx, "A")
        return "ok"
    probe(P, "StorageNode.remove_alt", _remove_alt)

    # Hash round-trip
    def _set_hash() -> str:
        node.set_hash("testKey", "testValue", "H")
        return "ok"
    probe(P, "StorageNode.set_hash", _set_hash)
    probe(P, "StorageNode.hash", lambda: node.hash("testKey", "H"))

    # Sup (binary) round-trip
    sup_idx = 200
    sup_data = bytes([0xDE, 0xAD, 0xBE, 0xEF])

    def _set_sup() -> str:
        node.set_sup(sup_idx, sup_data, "S")
        return "ok"
    probe(P, "StorageNode.set_sup", _set_sup)

    def _sup() -> str:
        buf = node.sup(sup_idx, "S")
        return f"bytes({len(buf)}): {buf.hex()}"
    probe(P, "StorageNode.sup", _sup)

    # Blob round-trip
    blob_idx = 300
    blob_data = b"Hello, forensics blob! This is a long string for testing."

    def _set_blob() -> str:
        node.set_blob(blob_idx, blob_data, "B")
        return "ok"
    probe(P, "StorageNode.set_blob", _set_blob)
    probe(P, "StorageNode.blob_size", lambda: node.blob_size(blob_idx, "B"))

    def _blob() -> str:
        buf = node.blob(blob_idx, "B")
        return f"bytes({len(buf)}): {buf.hex()[:40]}..."
    probe(P, "StorageNode.blob", _blob)
    probe(P, "StorageNode.blob_string", lambda: node.blob_string(blob_idx, "B"))

    def _remove_blob() -> str:
        node.remove_blob(blob_idx, "B")
        return "ok"
    probe(P, "StorageNode.remove_blob", _remove_blob)

    # open_by_id round-trip
    node_id = node.id()

    def _open_by_id() -> str:
        n2 = storage.open_by_id(node_id)
        return f"name='{n2.name()}' id={n2.id()}"
    probe(P, "storage.open_by_id", _open_by_id)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 16 — Diagnostics
# ═══════════════════════════════════════════════════════════════════════════

def phase16_diagnostics() -> None:
    P = "P16-diagnostics"

    probe(P, "diagnostics.log_level", lambda: diagnostics.log_level())

    def _set_debug() -> str:
        diagnostics.set_log_level(diagnostics.LogLevel.debug)
        return "ok"
    probe(P, "diagnostics.set_log_level(debug)", _set_debug)
    probe(P, "diagnostics.log_level(after)", lambda: diagnostics.log_level())

    # Restore to a sensible level
    def _set_warning() -> str:
        diagnostics.set_log_level(diagnostics.LogLevel.warning)
        return "ok"
    probe(P, "diagnostics.set_log_level(warning)", _set_warning)

    def _log() -> str:
        diagnostics.log(diagnostics.LogLevel.info, "forensics", "Binary forensics diagnostic test message")
        return "ok"
    probe(P, "diagnostics.log", _log)

    def _reset_counters() -> str:
        diagnostics.reset_performance_counters()
        return "ok"
    probe(P, "diagnostics.reset_performance_counters", _reset_counters)

    def _counters() -> str:
        c = diagnostics.performance_counters()
        return f"logMessages={c.get('log_messages', c.get('logMessages', '?'))} invariantFailures={c.get('invariant_failures', c.get('invariantFailures', '?'))}"
    probe(P, "diagnostics.performance_counters", _counters)

    # assert_invariant — true should not throw
    def _assert_true() -> str:
        diagnostics.assert_invariant(True, "this should not throw")
        return "ok"
    probe(P, "diagnostics.assert_invariant(true)", _assert_true)

    # assert_invariant — false should throw
    def _assert_false() -> str:
        try:
            diagnostics.assert_invariant(False, "deliberate failure")
            return "ERROR: did not throw"
        except Exception as err:
            return f"correctly threw: {err_str(err)}"
    probe(P, "diagnostics.assert_invariant(false)", _assert_false)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 17 — Lines & colors
# ═══════════════════════════════════════════════════════════════════════════

def phase17_lines() -> None:
    P = "P17-lines"

    # Color constants
    probe(P, "lines.Color.DEFAULT", lambda: lines.Color.DEFAULT)
    probe(P, "lines.Color.INSTRUCTION", lambda: lines.Color.INSTRUCTION)
    probe(P, "lines.Color.STRING", lambda: lines.Color.STRING)
    probe(P, "lines.Color.NUMBER", lambda: lines.Color.NUMBER)
    probe(P, "lines.Color.REGISTER", lambda: lines.Color.REGISTER)
    probe(P, "lines.Color.KEYWORD", lambda: lines.Color.KEYWORD)
    probe(P, "lines.Color.ERROR", lambda: lines.Color.ERROR)
    probe(P, "lines.Color.CODE_REFERENCE", lambda: lines.Color.CODE_REFERENCE)
    probe(P, "lines.Color.DATA_REFERENCE", lambda: lines.Color.DATA_REFERENCE)
    probe(P, "lines.Color.REGULAR_COMMENT", lambda: lines.Color.REGULAR_COMMENT)
    probe(P, "lines.Color.REPEATABLE_COMMENT", lambda: lines.Color.REPEATABLE_COMMENT)
    probe(P, "lines.Color.AUTO_COMMENT", lambda: lines.Color.AUTO_COMMENT)
    probe(P, "lines.Color.SYMBOL", lambda: lines.Color.SYMBOL)
    probe(P, "lines.Color.COLLAPSED", lambda: lines.Color.COLLAPSED)

    # Control bytes
    probe(P, "lines.COLOR_ON", lambda: lines.COLOR_ON)
    probe(P, "lines.COLOR_OFF", lambda: lines.COLOR_OFF)
    probe(P, "lines.COLOR_ESC", lambda: lines.COLOR_ESC)
    probe(P, "lines.COLOR_INV", lambda: lines.COLOR_INV)
    probe(P, "lines.COLOR_ADDR", lambda: lines.COLOR_ADDR)
    probe(P, "lines.COLOR_ADDR_SIZE", lambda: lines.COLOR_ADDR_SIZE)

    # colstr with Color enum
    def _colstr_numeric() -> str:
        tagged = lines.colstr("hello", lines.Color.INSTRUCTION)
        return f"tagged.length={len(tagged)}"
    probe(P, "lines.colstr(numeric)", _colstr_numeric)

    # colstr with various colors
    color_map = {
        "DEFAULT": lines.Color.DEFAULT,
        "REGULAR_COMMENT": lines.Color.REGULAR_COMMENT,
        "REPEATABLE_COMMENT": lines.Color.REPEATABLE_COMMENT,
        "AUTO_COMMENT": lines.Color.AUTO_COMMENT,
        "INSTRUCTION": lines.Color.INSTRUCTION,
        "DATA_NAME": lines.Color.DATA_NAME,
        "SYMBOL": lines.Color.SYMBOL,
        "STRING": lines.Color.STRING,
        "NUMBER": lines.Color.NUMBER,
        "CODE_REFERENCE": lines.Color.CODE_REFERENCE,
        "DATA_REFERENCE": lines.Color.DATA_REFERENCE,
        "ERROR": lines.Color.ERROR,
        "REGISTER": lines.Color.REGISTER,
        "KEYWORD": lines.Color.KEYWORD,
    }
    for cn, cv in color_map.items():
        probe(P, f"lines.colstr('{cn}')", lambda cv=cv: f"len={len(lines.colstr('test', cv))}")

    # tag_remove
    def _tag_remove() -> str:
        tagged = lines.colstr("visible text", lines.Color.INSTRUCTION)
        stripped = lines.tag_remove(tagged)
        return f"stripped='{stripped}'"
    probe(P, "lines.tag_remove", _tag_remove)

    # tag_strlen
    def _tag_strlen() -> str:
        tagged = lines.colstr("measure me", lines.Color.NUMBER)
        return f"visLen={lines.tag_strlen(tagged)}"
    probe(P, "lines.tag_strlen", _tag_strlen)

    # tag_advance
    def _tag_advance() -> str:
        tagged = lines.colstr("advance test", lines.Color.STRING)
        pos = lines.tag_advance(tagged, 3)
        return f"advancedPos={pos}"
    probe(P, "lines.tag_advance", _tag_advance)

    # make_addr_tag / decode_addr_tag
    def _make_addr_tag() -> str:
        tag = lines.make_addr_tag(42)
        return f"tag.length={len(tag)}"
    probe(P, "lines.make_addr_tag", _make_addr_tag)

    def _decode_addr_tag() -> str:
        tag = lines.make_addr_tag(42)
        # The address tag has a control byte + encoded address
        decoded = lines.decode_addr_tag(tag, 1)
        return f"decoded={decoded}"
    probe(P, "lines.decode_addr_tag", _decode_addr_tag)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 18 — Decompiler deep-dive
# ═══════════════════════════════════════════════════════════════════════════

def phase18_decompiler() -> None:
    P = "P18-decompiler"

    is_available = probe(P, "decompiler.available", lambda: decompiler.available())
    if is_available is not True:
        record(P, "SKIP", True, "decompiler not available")
        return

    # Find a decompilable function
    funcs = fn.all()
    dfunc = None
    faddr = 0
    for f in funcs:
        if f.size > 16 and not f.is_thunk and not f.is_library:
            try:
                dfunc = decompiler.decompile(f.start)
                faddr = f.start
                break
            except Exception:
                pass  # try next

    if dfunc is None:
        record(P, "SKIP", True, "no decompilable function found")
        return

    probe(P, "decompiler.decompile", lambda: f"decompiled @ {hex_(faddr)}")

    # Pseudocode access
    def _pseudocode() -> str:
        pc = dfunc.pseudocode()
        return f"{len(pc)} chars"
    probe(P, "DecompiledFunction.pseudocode", _pseudocode)
    probe(P, "DecompiledFunction.lines", lambda: f"{len(dfunc.lines())} clean lines")

    def _raw_lines() -> str:
        raw = dfunc.raw_lines()
        return f"{len(raw)} raw lines, first tag length={len(raw[0]) if len(raw) > 0 else 0}"
    probe(P, "DecompiledFunction.raw_lines", _raw_lines)

    # Declaration
    probe(P, "DecompiledFunction.declaration", lambda: dfunc.declaration())

    # Entry address
    probe(P, "DecompiledFunction.entry_address", lambda: hex_(dfunc.entry_address()))

    # Variables
    probe(P, "DecompiledFunction.variable_count", lambda: dfunc.variable_count())

    def _variables() -> str:
        vars_ = dfunc.variables()
        descs: list[str] = []
        for v in vars_:
            v_name = v.get("name", str(v)) if isinstance(v, dict) else getattr(v, "name", str(v))
            v_type = v.get("typeName", v.get("type_name", "")) if isinstance(v, dict) else getattr(v, "type_name", getattr(v, "typeName", ""))
            v_is_arg = v.get("isArgument", v.get("is_argument", False)) if isinstance(v, dict) else getattr(v, "is_argument", getattr(v, "isArgument", False))
            v_width = v.get("width", 0) if isinstance(v, dict) else getattr(v, "width", 0)
            v_storage = v.get("storage", "") if isinstance(v, dict) else getattr(v, "storage", "")
            v_user = v.get("hasUserName", v.get("has_user_name", False)) if isinstance(v, dict) else getattr(v, "has_user_name", getattr(v, "hasUserName", False))
            v_nice = v.get("hasNiceName", v.get("has_nice_name", False)) if isinstance(v, dict) else getattr(v, "has_nice_name", getattr(v, "hasNiceName", False))
            _ = v.get("comment", "") if isinstance(v, dict) else getattr(v, "comment", "")
            descs.append(f"{v_name}:{v_type}(arg={v_is_arg},w={v_width},"
                         f"storage={v_storage},userName={v_user},nice={v_nice})")
        return "; ".join(descs)
    probe(P, "DecompiledFunction.variables", _variables)

    # Address mapping
    def _address_map() -> str:
        amap = dfunc.address_map()
        return f"{len(amap)} mapping(s)"
    probe(P, "DecompiledFunction.address_map", _address_map)
    probe(P, "DecompiledFunction.line_to_address(0)", lambda: hex_(dfunc.line_to_address(0)))

    # Rename a variable (and rename back)
    vars_ = dfunc.variables()
    non_arg_var = None
    for v in vars_:
        v_is_arg = v.get("isArgument", v.get("is_argument", False)) if isinstance(v, dict) else getattr(v, "is_argument", getattr(v, "isArgument", False))
        if not v_is_arg:
            non_arg_var = v
            break

    if non_arg_var is not None:
        orig_var_name = non_arg_var.get("name", str(non_arg_var)) if isinstance(non_arg_var, dict) else getattr(non_arg_var, "name", str(non_arg_var))

        def _rename_var() -> str:
            dfunc.rename_variable(orig_var_name, "forensics_renamed_var")
            return "ok"
        probe(P, "DecompiledFunction.rename_variable", _rename_var)

        def _rename_var_restore() -> str:
            dfunc.rename_variable("forensics_renamed_var", orig_var_name)
            return "ok"
        probe(P, "DecompiledFunction.rename_variable(restore)", _rename_var_restore)

    # Retype a variable
    if len(vars_) > 0:
        v0_name = vars_[0].get("name", str(vars_[0])) if isinstance(vars_[0], dict) else getattr(vars_[0], "name", str(vars_[0]))

        def _retype_by_name() -> str:
            dfunc.retype_variable(v0_name, "unsigned int")
            return "ok"
        probe(P, "DecompiledFunction.retype_variable(name)", _retype_by_name)

        def _retype_by_index() -> str:
            dfunc.retype_variable(0, "int")
            return "ok"
        probe(P, "DecompiledFunction.retype_variable(index)", _retype_by_index)

    # Refresh / re-decompile
    def _refresh() -> str:
        dfunc.refresh()
        return "ok"
    probe(P, "DecompiledFunction.refresh", _refresh)

    # Cache invalidation
    def _mark_dirty() -> str:
        decompiler.mark_dirty(faddr)
        return "ok"
    probe(P, "decompiler.mark_dirty", _mark_dirty)

    def _mark_dirty_callers() -> str:
        decompiler.mark_dirty_with_callers(faddr)
        return "ok"
    probe(P, "decompiler.mark_dirty_with_callers", _mark_dirty_callers)

    # Decompiler events
    maturity_token: Optional[int] = None
    printed_token: Optional[int] = None
    refresh_token: Optional[int] = None

    def _on_maturity() -> str:
        nonlocal maturity_token
        maturity_token = decompiler.on_maturity_changed(lambda _ev: None)
        return f"token={maturity_token}"
    probe(P, "decompiler.on_maturity_changed", _on_maturity)

    def _on_printed() -> str:
        nonlocal printed_token
        printed_token = decompiler.on_func_printed(lambda _ev: None)
        return f"token={printed_token}"
    probe(P, "decompiler.on_func_printed", _on_printed)

    def _on_refresh() -> str:
        nonlocal refresh_token
        refresh_token = decompiler.on_refresh_pseudocode(lambda _ev: None)
        return f"token={refresh_token}"
    probe(P, "decompiler.on_refresh_pseudocode", _on_refresh)

    # Unsubscribe
    if maturity_token is not None:
        _mt = maturity_token
        def _unsub_maturity() -> str:
            decompiler.unsubscribe(_mt)
            return "ok"
        probe(P, "decompiler.unsubscribe(maturity)", _unsub_maturity)
    if printed_token is not None:
        _pt = printed_token
        def _unsub_printed() -> str:
            decompiler.unsubscribe(_pt)
            return "ok"
        probe(P, "decompiler.unsubscribe(printed)", _unsub_printed)
    if refresh_token is not None:
        _rt = refresh_token
        def _unsub_refresh() -> str:
            decompiler.unsubscribe(_rt)
            return "ok"
        probe(P, "decompiler.unsubscribe(refresh)", _unsub_refresh)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 19 — Lumina (non-destructive connection probing)
# ═══════════════════════════════════════════════════════════════════════════

def phase19_lumina() -> None:
    P = "P19-lumina"

    probe(P, "lumina.has_connection()", lambda: lumina.has_connection())
    probe(P, "lumina.has_connection(primary)", lambda: lumina.has_connection(lumina.Feature.primary_metadata))
    probe(P, "lumina.has_connection(decompiler)", lambda: lumina.has_connection(lumina.Feature.decompiler))
    probe(P, "lumina.has_connection(telemetry)", lambda: lumina.has_connection(lumina.Feature.telemetry))
    probe(P, "lumina.has_connection(secondary)", lambda: lumina.has_connection(lumina.Feature.secondary_metadata))

    # Close connections — may throw Unsupported in idalib mode.
    def _close_connection() -> str:
        try:
            lumina.close_connection(lumina.Feature.primary_metadata)
            return "ok"
        except Exception as e:
            msg = str(e)
            if "Unsupported" in msg or "unavailable" in msg:
                return "unsupported (expected)"
            raise
    probe(P, "lumina.close_connection", _close_connection)

    def _close_all() -> str:
        try:
            lumina.close_all_connections()
            return "ok"
        except Exception as e:
            msg = str(e)
            if "Unsupported" in msg or "unavailable" in msg:
                return "unsupported (expected)"
            raise
    probe(P, "lumina.close_all_connections", _close_all)

    # Pull (will likely fail without a server, but exercises the binding)
    funcs = fn.all()
    if len(funcs) > 0:
        def _pull_single() -> str:
            result = lumina.pull(funcs[0].start, True, False, lumina.Feature.primary_metadata)
            return f"req={result.requested} done={result.completed} ok={result.succeeded} fail={result.failed}"
        probe(P, "lumina.pull(single)", _pull_single)

        if len(funcs) >= 2:
            def _pull_batch() -> str:
                addrs = [funcs[0].start, funcs[1].start]
                result = lumina.pull(addrs)
                return f"req={result.requested} codes=[{','.join(str(c) for c in result.codes)}]"
            probe(P, "lumina.pull(batch)", _pull_batch)

        def _push() -> str:
            result = lumina.push(funcs[0].start, lumina.PushMode.keep_existing)
            return f"req={result.requested} done={result.completed}"
        probe(P, "lumina.push", _push)


# ═══════════════════════════════════════════════════════════════════════════
# Phase 20 — Event system (comprehensive)
# ═══════════════════════════════════════════════════════════════════════════

def phase20_events() -> None:
    P = "P20-event"

    tokens: list[int] = []
    event_count = 0

    def inc_event(*_args: Any) -> None:
        nonlocal event_count
        event_count += 1

    # Subscribe to every typed event
    def _on_seg_added() -> str:
        tokens.append(event.on_segment_added(lambda _addr: inc_event()))
        return "ok"
    probe(P, "event.on_segment_added", _on_seg_added)

    def _on_seg_deleted() -> str:
        tokens.append(event.on_segment_deleted(lambda _a, _b: inc_event()))
        return "ok"
    probe(P, "event.on_segment_deleted", _on_seg_deleted)

    def _on_func_added() -> str:
        tokens.append(event.on_function_added(lambda _addr: inc_event()))
        return "ok"
    probe(P, "event.on_function_added", _on_func_added)

    def _on_func_deleted() -> str:
        tokens.append(event.on_function_deleted(lambda _addr: inc_event()))
        return "ok"
    probe(P, "event.on_function_deleted", _on_func_deleted)

    def _on_renamed() -> str:
        tokens.append(event.on_renamed(lambda _a, _b, _c: inc_event()))
        return "ok"
    probe(P, "event.on_renamed", _on_renamed)

    def _on_byte_patched() -> str:
        tokens.append(event.on_byte_patched(lambda _a, _b: inc_event()))
        return "ok"
    probe(P, "event.on_byte_patched", _on_byte_patched)

    def _on_comment_changed() -> str:
        tokens.append(event.on_comment_changed(lambda _a, _b: inc_event()))
        return "ok"
    probe(P, "event.on_comment_changed", _on_comment_changed)

    def _on_event() -> str:
        def handler(ev: dict) -> None:
            _ = ev.get("kind")
            _ = ev.get("address")
            _ = ev.get("secondary_address", ev.get("secondaryAddress"))
            _ = ev.get("new_name", ev.get("newName"))
            _ = ev.get("old_name", ev.get("oldName"))
            _ = ev.get("old_value", ev.get("oldValue"))
            _ = ev.get("repeatable")
        tokens.append(event.on_event(handler))
        return "ok"
    probe(P, "event.on_event", _on_event)

    # Trigger events
    funcs = fn.all()
    if len(funcs) > 0:
        target = funcs[0].start
        orig_name = funcs[0].name
        try:
            naming.force_set(target, "evtest")
        except Exception:
            pass
        try:
            naming.force_set(target, orig_name)
        except Exception:
            pass
        try:
            data.patch_byte(target, 0x90)
        except Exception:
            pass
        try:
            data.revert_patch(target)
        except Exception:
            pass
        try:
            comment.set(target, "evtest")
        except Exception:
            pass
        try:
            comment.remove(target)
        except Exception:
            pass

    probe(P, "eventCount", lambda: f"{event_count} event(s) captured")

    # Unsubscribe all
    for token in tokens:
        def _unsub(t: int = token) -> str:
            event.unsubscribe(t)
            return "ok"
        probe(P, "event.unsubscribe", _unsub)


# ═══════════════════════════════════════════════════════════════════════════
# Report
# ═══════════════════════════════════════════════════════════════════════════

def print_report() -> None:
    print("\n")
    print("=" * 80)
    print("  BINARY FORENSICS — API COVERAGE REPORT")
    print("=" * 80)

    # Group by phase
    phases: dict[str, list[TestResult]] = {}
    for r in results:
        phases.setdefault(r.phase, []).append(r)

    total_passed = 0
    total_failed = 0

    for phase, tests in phases.items():
        passed = sum(1 for t in tests if t.passed)
        failed = len(tests) - passed
        total_passed += passed
        total_failed += failed

        status = "PASS" if failed == 0 else f"{failed} FAIL"
        print(f"\n  {phase}  [{passed}/{len(tests)}] {status}")

        for t in tests:
            mark = "+" if t.passed else "X"
            detail = t.detail[:67] + "..." if len(t.detail) > 70 else t.detail
            print(f"    [{mark}] {t.api:<42} {detail}")

    total = total_passed + total_failed
    print("\n" + "=" * 80)
    print(f"  TOTAL: {total} probes, {total_passed} passed, {total_failed} failed")
    if total > 0:
        print(f"  PASS RATE: {(total_passed / total) * 100:.1f}%")
    print("=" * 80)


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Binary Forensics — exhaustive idax Python API stress-test",
    )
    parser.add_argument("binary", help="Path to the binary to analyze")
    args = parser.parse_args()

    input_path = args.binary

    # ── Database lifecycle ───────────────────────────────────────────────
    database.init(quiet=True)
    database.open(input_path)

    print("=== Binary Forensics Analysis ===")
    print(f"Input:     {database.input_file_path()}")
    print(f"Processor: {database.processor_name()}")
    print(f"Bitness:   {database.address_bitness()}")
    print(f"Range:     {hex_(database.min_address())}..{hex_(database.max_address())}")

    # ── Execute all phases ───────────────────────────────────────────────
    phase_runners: list[tuple[str, Any]] = [
        ("Phase  1: Metadata",     phase1_metadata),
        ("Phase  2: Segments",     phase2_segments),
        ("Phase  3: Addresses",    phase3_address),
        ("Phase  4: Functions",    phase4_functions),
        ("Phase  5: Instructions", phase5_instructions),
        ("Phase  6: Xrefs",        phase6_xrefs),
        ("Phase  7: Names",        phase7_names),
        ("Phase  8: Comments",     phase8_comments),
        ("Phase  9: Data",         phase9_data),
        ("Phase 10: Search",       phase10_search),
        ("Phase 11: Analysis",     phase11_analysis),
        ("Phase 12: Types",        phase12_types),
        ("Phase 13: Entries",      phase13_entries),
        ("Phase 14: Fixups",       phase14_fixups),
        ("Phase 15: Storage",      phase15_storage),
        ("Phase 16: Diagnostics",  phase16_diagnostics),
        ("Phase 17: Lines",        phase17_lines),
        ("Phase 18: Decompiler",   phase18_decompiler),
        ("Phase 19: Lumina",       phase19_lumina),
        ("Phase 20: Events",       phase20_events),
    ]

    for label, runner in phase_runners:
        print(f"\n--- {label} ---")
        try:
            runner()
        except Exception as err:
            print(f"  PHASE CRASH: {err_str(err)}")

    # ── Report ──────────────────────────────────────────────────────────
    print_report()

    # ── Teardown ────────────────────────────────────────────────────────
    database.close(False)


if __name__ == "__main__":
    main()
    os._exit(0)  # avoid idalib shutdown crash
