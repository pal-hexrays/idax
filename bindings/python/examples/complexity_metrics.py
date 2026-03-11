#!/usr/bin/env python3
"""
Complexity Metrics -- headless idalib port of decompiler_plugin.cpp.

Computes McCabe cyclomatic complexity for every decompilable function,
identifies the most complex ones, and generates a ranked report.

Since the Python bindings do not expose the ctree visitor API, we
approximate complexity by analysing pseudocode text:
  - Counting control-flow keywords (if, for, while, switch, case, ternary,
    short-circuit operators) to estimate decision points.
  - Counting expression patterns (calls, assignments, comparisons, member
    accesses) for code-quality heuristics.
  - Tracking brace nesting depth as a proxy for structural complexity.

Features demonstrated:
  - database lifecycle (init / open / close)
  - function enumeration and filtering
  - decompiler: pseudocode, variables, line-to-address mapping
  - variable renaming within decompiled output
  - comment annotation (disassembly repeatable comments)
  - function callers / callees for call-graph summary

Usage:
  python examples/complexity_metrics.py <path-to-binary-or-idb>
"""
from __future__ import annotations

import re
import os
import sys
from dataclasses import dataclass
from typing import Optional

import idax


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

# Minimum function size in bytes to consider for analysis.
MIN_FUNCTION_SIZE: int = 32

# Maximum number of functions shown in the ranked report.
TOP_N: int = 20

# Maximum number of single-letter variables to rename per function.
MAX_VARIABLE_RENAMES: int = 3

# Maximum number of pseudocode lines to show in the address mapping.
MAX_ADDRESS_MAP_LINES: int = 5

# Maximum number of callers/callees to display per function.
MAX_CALL_GRAPH_ENTRIES: int = 5


# ═══════════════════════════════════════════════════════════════════════════
# Pseudocode-based complexity heuristics
# ═══════════════════════════════════════════════════════════════════════════

# Regular expressions matching control-flow keywords that contribute to
# McCabe cyclomatic complexity.  Each match represents one decision point.
#
# The final cyclomatic complexity is `(total decision points) + 1`.
DECISION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bif\s*\("),
    re.compile(r"\belse\b"),
    re.compile(r"\bfor\s*\("),
    re.compile(r"\bwhile\s*\("),
    re.compile(r"\bdo\s*\{"),
    re.compile(r"\bswitch\s*\("),
    re.compile(r"\bcase\s+"),
    re.compile(r"\bcatch\s*\("),
    re.compile(r"\?\s*"),       # ternary
    re.compile(r"&&"),          # short-circuit AND
    re.compile(r"\|\|"),        # short-circuit OR
]

# Regular expressions for expression-pattern heuristics.
CALL_PATTERN: re.Pattern[str] = re.compile(r"\w+\s*\(")
ASSIGN_PATTERN: re.Pattern[str] = re.compile(r"[^!=<>]=[^=]")
COMPARE_PATTERN: re.Pattern[str] = re.compile(r"[!=<>]=")
MEMBER_PATTERN: re.Pattern[str] = re.compile(r"[.>]\w+")


# ═══════════════════════════════════════════════════════════════════════════
# FunctionMetrics -- typed metrics record
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class FunctionMetrics:
    """Comprehensive metrics for a single decompiled function."""
    address: int
    name: str
    line_count: int
    variable_count: int
    decision_points: int
    cyclomatic_complexity: int
    calls: int
    assignments: int
    comparisons: int
    member_accesses: int
    max_nesting_depth: int
    # Retained handle for post-analysis annotation.
    dfunc: idax.decompiler.DecompiledFunction


@dataclass
class AggregateStats:
    """Aggregate statistics across all analysed functions."""
    total_functions: int
    average_complexity: float
    max_complexity: int
    skipped: int


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers
# ═══════════════════════════════════════════════════════════════════════════

def count_matches(text: str, pattern: re.Pattern[str]) -> int:
    """Count non-overlapping matches of `pattern` within `text`."""
    return len(pattern.findall(text))


def compute_max_nesting(pseudocode: str) -> int:
    """
    Compute the maximum brace-nesting depth in a pseudocode string.

    This is an imperfect but useful proxy for structural complexity:
    deeply nested code is harder to follow and typically correlates with
    high cyclomatic complexity.
    """
    max_depth: int = 0
    current_depth: int = 0

    for ch in pseudocode:
        if ch == "{":
            current_depth += 1
            if current_depth > max_depth:
                max_depth = current_depth
        elif ch == "}":
            if current_depth > 0:
                current_depth -= 1

    return max_depth


def fmt_addr(addr: int) -> str:
    """Format an address as a zero-prefixed hex string."""
    return f"0x{addr:x}"


def is_idax_error(err: BaseException) -> bool:
    """Check whether an exception is an IdaxError."""
    return isinstance(err, idax.IdaxError)


def error_message(err: BaseException) -> str:
    """Extract a human-readable message from an error value."""
    if isinstance(err, idax.IdaxError):
        return f"[{err.category}] {err}"
    return str(err)


# ═══════════════════════════════════════════════════════════════════════════
# Core analysis
# ═══════════════════════════════════════════════════════════════════════════

def analyze_function(func_addr: int, func_name: str) -> Optional[FunctionMetrics]:
    """
    Decompile and analyse a single function, producing a full metrics record.

    Returns None if the function cannot be decompiled (e.g. obfuscated or
    data-only regions mis-classified as code).
    """
    try:
        dfunc = idax.decompiler.decompile(func_addr)
    except Exception:
        return None

    try:
        pseudocode_lines: list[str] = dfunc.lines()
    except Exception:
        pseudocode_lines = []

    try:
        variable_count: int = dfunc.variable_count()
    except Exception:
        variable_count = 0

    pseudocode: str = "\n".join(pseudocode_lines)

    # Count decision points from pseudocode keywords.
    decision_points: int = 0
    for pattern in DECISION_PATTERNS:
        decision_points += count_matches(pseudocode, pattern)

    # Expression-pattern counts.
    calls: int = count_matches(pseudocode, CALL_PATTERN)
    assignments: int = count_matches(pseudocode, ASSIGN_PATTERN)
    comparisons: int = count_matches(pseudocode, COMPARE_PATTERN)
    member_accesses: int = count_matches(pseudocode, MEMBER_PATTERN)

    # Nesting depth from brace counting.
    max_nesting_depth: int = compute_max_nesting(pseudocode)

    return FunctionMetrics(
        address=func_addr,
        name=func_name,
        line_count=len(pseudocode_lines),
        variable_count=variable_count,
        decision_points=decision_points,
        cyclomatic_complexity=decision_points + 1,
        calls=calls,
        assignments=assignments,
        comparisons=comparisons,
        member_accesses=member_accesses,
        max_nesting_depth=max_nesting_depth,
        dfunc=dfunc,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Annotation: enrich the most complex function
# ═══════════════════════════════════════════════════════════════════════════

def annotate_complex_function(metrics: FunctionMetrics) -> None:
    """
    Annotate the highest-complexity function by:
      1. Setting a repeatable comment with the complexity summary.
      2. Renaming single-letter non-argument variables.
      3. Printing a pseudocode-to-address mapping for the first few lines.
      4. Reporting the total address mapping count.
    """
    dfunc = metrics.dfunc
    address = metrics.address
    func_name = metrics.name

    # 1. Repeatable comment with complexity summary.
    try:
        idax.comment.set(
            address,
            f"[Complexity] Cyclomatic: {metrics.cyclomatic_complexity} | "
            f"Lines: {metrics.line_count} | Calls: {metrics.calls} | "
            f"Nesting: {metrics.max_nesting_depth}",
            True,
        )
    except Exception as err:
        print(f"  [warn] Could not set disassembly comment: {error_message(err)}")

    # 2. Rename single-letter non-argument variables.
    try:
        variables = dfunc.variables()
        renamed: int = 0

        for v in variables:
            if v["is_argument"]:
                continue
            if len(v["name"]) != 1:
                continue

            if "int" in v["type_name"]:
                new_name = f"local_int_{renamed}"
            elif "char" in v["type_name"]:
                new_name = f"local_str_{renamed}"
            else:
                new_name = f"local_{renamed}"

            try:
                dfunc.rename_variable(v["name"], new_name)
                renamed += 1
                if renamed >= MAX_VARIABLE_RENAMES:
                    break
            except Exception:
                # Rename may fail (duplicate name, reserved, etc.) -- skip.
                pass

        if renamed > 0:
            print(f"  Renamed {renamed} single-letter variable(s) in '{func_name}'")
    except Exception as err:
        print(f"  [warn] Could not rename variables: {error_message(err)}")

    # 3. Pseudocode line-to-address mapping (first N lines).
    try:
        lines: list[str] = dfunc.lines()
        if len(lines) > 0:
            print(f"\n  Address mapping for '{func_name}' (first {MAX_ADDRESS_MAP_LINES} lines):")
            count = min(MAX_ADDRESS_MAP_LINES, len(lines))

            for i in range(count):
                try:
                    addr: int = dfunc.line_to_address(i)
                    line_text: str = lines[i][:60]
                    print(f"    Line {i}: {fmt_addr(addr)}  |  {line_text}")
                except Exception:
                    # Not all lines map to an address (declarations, braces, etc.).
                    pass
    except Exception as err:
        print(f"  [warn] Could not generate address mapping: {error_message(err)}")

    # 4. Total address mapping count.
    try:
        amap = dfunc.address_map()
        print(f"  Total address mappings: {len(amap)}")
    except Exception:
        pass  # Not critical.


# ═══════════════════════════════════════════════════════════════════════════
# Call-graph summary
# ═══════════════════════════════════════════════════════════════════════════

def report_call_graph(func_addr: int, func_name: str) -> None:
    """
    Report callers and callees for a function.

    This replaces the C++ plugin's ida::graph::flowchart() analysis, which
    is not available in the Python bindings.  The call-graph view is often
    more useful in practice for prioritising review effort.
    """
    try:
        callers: list[int] = idax.function.callers(func_addr)
        callees: list[int] = idax.function.callees(func_addr)

        print(
            f"\n  Call graph for '{func_name}': "
            f"{len(callers)} caller(s), {len(callees)} callee(s)"
        )

        if len(callers) > 0:
            print("    Callers:")
            shown = callers[:MAX_CALL_GRAPH_ENTRIES]
            for caller_addr in shown:
                try:
                    caller_name: str = idax.function.name_at(caller_addr)
                    print(f"      {caller_name} ({fmt_addr(caller_addr)})")
                except Exception:
                    print(f"      {fmt_addr(caller_addr)}")
            if len(callers) > MAX_CALL_GRAPH_ENTRIES:
                print(f"      ... and {len(callers) - MAX_CALL_GRAPH_ENTRIES} more")

        if len(callees) > 0:
            print("    Callees:")
            shown = callees[:MAX_CALL_GRAPH_ENTRIES]
            for callee_addr in shown:
                try:
                    callee_name: str = idax.function.name_at(callee_addr)
                    print(f"      {callee_name} ({fmt_addr(callee_addr)})")
                except Exception:
                    print(f"      {fmt_addr(callee_addr)}")
            if len(callees) > MAX_CALL_GRAPH_ENTRIES:
                print(f"      ... and {len(callees) - MAX_CALL_GRAPH_ENTRIES} more")

    except Exception as err:
        print(f"  [warn] Could not report call graph: {error_message(err)}")


# ═══════════════════════════════════════════════════════════════════════════
# Aggregate statistics
# ═══════════════════════════════════════════════════════════════════════════

def compute_aggregate_stats(
    metrics: list[FunctionMetrics],
    skipped: int,
) -> AggregateStats:
    total_complexity: int = 0
    max_complexity: int = 0

    for m in metrics:
        total_complexity += m.cyclomatic_complexity
        if m.cyclomatic_complexity > max_complexity:
            max_complexity = m.cyclomatic_complexity

    return AggregateStats(
        total_functions=len(metrics),
        average_complexity=total_complexity / len(metrics) if len(metrics) > 0 else 0.0,
        max_complexity=max_complexity,
        skipped=skipped,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Report rendering
# ═══════════════════════════════════════════════════════════════════════════

def print_ranked_table(metrics: list[FunctionMetrics]) -> None:
    print("")
    print("  Rank | Complexity | Lines | Calls | Nesting | Function")
    print("  -----+------------+-------+-------+---------+---------")

    count = min(len(metrics), TOP_N)
    for i in range(count):
        m = metrics[i]
        rank = str(i + 1).rjust(4)
        cmplx = str(m.cyclomatic_complexity).rjust(10)
        lines = str(m.line_count).rjust(5)
        calls = str(m.calls).rjust(5)
        nesting = str(m.max_nesting_depth).rjust(7)

        print(
            f"  {rank} | {cmplx} | {lines} | {calls} | {nesting} | "
            f"{m.name} ({fmt_addr(m.address)})"
        )


def print_aggregate_stats(stats: AggregateStats) -> None:
    print(
        f"\n[Complexity] Average: {stats.average_complexity:.1f}, "
        f"Max: {stats.max_complexity}, "
        f"Total functions: {stats.total_functions}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python examples/complexity_metrics.py <path-to-binary-or-idb>",
              file=sys.stderr)
        sys.exit(1)

    input_path: str = sys.argv[1]

    # ── Database lifecycle ───────────────────────────────────────────────
    idax.database.init(quiet=True)
    idax.database.open(input_path)

    print("=== Complexity Metrics Analysis ===")
    print(f"Input:     {idax.database.input_file_path()}")
    print(f"Processor: {idax.database.processor_name()}")
    print(f"Bitness:   {idax.database.address_bitness()}")
    print(f"MD5:       {idax.database.input_md5()}")

    # ── Decompiler availability check ───────────────────────────────────
    if not idax.decompiler.available():
        print("\n[Complexity] Hex-Rays decompiler is not available.")
        print("[Complexity] Install the decompiler to use this script.")
        idax.database.close()
        return

    # ── Analyse all non-trivial functions ────────────────────────────────
    all_functions = idax.function.all()
    all_metrics: list[FunctionMetrics] = []
    skipped: int = 0

    for f in all_functions:
        # Skip tiny functions (thunks, stubs) and library code.
        if f.size < MIN_FUNCTION_SIZE or f.is_library or f.is_thunk:
            skipped += 1
            continue

        metrics = analyze_function(f.start, f.name)
        if metrics is not None:
            all_metrics.append(metrics)

    print(f"\n[Complexity] Analysed {len(all_metrics)} function(s) ({skipped} skipped)")

    if len(all_metrics) == 0:
        idax.database.close()
        return

    # ── Sort by cyclomatic complexity, descending ───────────────────────
    all_metrics.sort(key=lambda m: m.cyclomatic_complexity, reverse=True)

    # ── Ranked report ───────────────────────────────────────────────────
    print_ranked_table(all_metrics)

    # ── Aggregate statistics ────────────────────────────────────────────
    stats = compute_aggregate_stats(all_metrics, skipped)
    print_aggregate_stats(stats)

    # ── Annotate the most complex function ──────────────────────────────
    top_func = all_metrics[0]
    print(f"\n[Complexity] Annotating top function: '{top_func.name}'")
    annotate_complex_function(top_func)

    # ── Call-graph analysis ─────────────────────────────────────────────
    report_call_graph(top_func.address, top_func.name)

    # ── Mark the top function in the disassembly ────────────────────────
    try:
        idax.comment.set(
            top_func.address,
            f"Highest complexity: {top_func.cyclomatic_complexity} (review priority #1)",
            True,
        )
    except Exception:
        pass  # Non-critical.

    print("\n=== Complexity Analysis Complete ===")

    # ── Teardown ────────────────────────────────────────────────────────
    # Pass False to discard annotation changes (pass True to persist).
    idax.database.close(False)


if __name__ == "__main__":
    main()
    os._exit(0)  # avoid idalib shutdown crash
