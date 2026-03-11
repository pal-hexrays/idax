#!/usr/bin/env python3
"""
Change Tracker -- headless idalib port of event_monitor_plugin.cpp.

Records all IDB events during a scripted analysis session, persists a
summary into netnode storage, and generates a change impact report.

In the original IDA plugin the change tracker used a GUI chooser, a
labelled graph, and a periodic timer to display live changes.  In headless
idalib mode we instead:
  - Subscribe to all available IDB event types (typed + generic).
  - Perform scripted database modifications to generate events.
  - Print a live log of each change as it happens.
  - Persist the audit trail to a netnode via the storage API.
  - Generate a comprehensive summary report at the end.

Features demonstrated:
  - database lifecycle (init / open / close)
  - event subscriptions (typed handlers + generic on_event)
  - event unsubscription via tokens
  - function, segment, name, data, comment APIs (to trigger events)
  - storage (netnode persistence with alt, hash, and read-back)

Usage:
  python examples/change_tracker.py <path-to-binary-or-idb>
"""
from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

import idax


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

# Netnode name used to persist the change audit trail across sessions.
# Matches the C++ plugin's `ida::storage::Node::open("idax_change_tracker")`.
STORAGE_NODE_NAME: str = "idax_change_tracker"

# Netnode alt-value index for the total change count.
# Index 100 avoids the idalib index-0 crash documented in the project findings.
STORAGE_ALT_INDEX: int = 100

# Netnode tag characters (must match the C++ plugin).
ALT_TAG: str = "A"
HASH_TAG: str = "H"


# ═══════════════════════════════════════════════════════════════════════════
# Domain types
# ═══════════════════════════════════════════════════════════════════════════

# Broad category of the event source.
# EventDomain: "IDB" | "UI" | "DBG"

# Fine-grained event classification.
# EventKind: "segment_add" | "segment_del" | "func_add" | "func_del"
#          | "rename" | "patch" | "comment" | "generic"


@dataclass
class ChangeRecord:
    """A single recorded change event."""
    timestamp_ms: int
    domain: str
    kind: str
    description: str
    address: Optional[int] = None


@dataclass
class AddressClassification:
    """Classification of affected addresses."""
    total: int
    in_functions: int
    in_segments: int


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
        return f"[{err.category}] {err}"
    return str(err)


# ═══════════════════════════════════════════════════════════════════════════
# ChangeLog
# ═══════════════════════════════════════════════════════════════════════════

class ChangeLog:
    def __init__(self) -> None:
        self._records: list[ChangeRecord] = []
        self._start_time: float = time.time()

    def add(
        self,
        domain: str,
        kind: str,
        description: str,
        address: Optional[int] = None,
    ) -> None:
        """Record a change event.  Immediately prints a live log line."""
        elapsed = int((time.time() - self._start_time) * 1000)

        self._records.append(ChangeRecord(
            timestamp_ms=elapsed,
            domain=domain,
            kind=kind,
            description=description,
            address=address,
        ))

        addr_str = f" @ {fmt_addr(address)}" if address is not None else ""
        print(f"  [{elapsed}ms] [{domain}] {kind}: {description}{addr_str}")

    @property
    def size(self) -> int:
        """Number of recorded events."""
        return len(self._records)

    @property
    def records(self) -> list[ChangeRecord]:
        """Snapshot of all records."""
        return list(self._records)

    def domain_counts(self) -> dict[str, int]:
        """Per-domain event count breakdown."""
        counts: dict[str, int] = {}
        for r in self._records:
            counts[r.domain] = counts.get(r.domain, 0) + 1
        return counts

    def kind_counts(self) -> dict[str, int]:
        """Per-kind event count breakdown."""
        counts: dict[str, int] = {}
        for r in self._records:
            counts[r.kind] = counts.get(r.kind, 0) + 1
        return counts

    def affected_addresses(self) -> set[int]:
        """Set of unique affected addresses."""
        return {r.address for r in self._records if r.address is not None}


change_log = ChangeLog()


# ═══════════════════════════════════════════════════════════════════════════
# Event subscription management
# ═══════════════════════════════════════════════════════════════════════════

def start_tracking() -> list[int]:
    """
    Subscribe to all available IDB event types.

    Each subscription returns a token (int) used for later unsubscription.
    Subscriptions that fail (e.g. because the event type is not supported
    in the current idalib build) are silently skipped.
    """
    tokens: list[int] = []

    print("[ChangeTracker] Subscribing to IDB events...")

    # ── Segment events ──────────────────────────────────────────────────

    try:
        def on_seg_added(address: int) -> None:
            change_log.add("IDB", "segment_add",
                           f"New segment at {fmt_addr(address)}", address)
        tokens.append(idax.event.on_segment_added(on_seg_added))
    except Exception:
        pass  # Event type may not be available in this build.

    try:
        def on_seg_deleted(start: int, end: int) -> None:
            change_log.add("IDB", "segment_del",
                           f"Removed segment {fmt_addr(start)}-{fmt_addr(end)}", start)
        tokens.append(idax.event.on_segment_deleted(on_seg_deleted))
    except Exception:
        pass  # Silently skip.

    # ── Function events ─────────────────────────────────────────────────

    try:
        def on_func_added(address: int) -> None:
            change_log.add("IDB", "func_add",
                           f"New function at {fmt_addr(address)}", address)
        tokens.append(idax.event.on_function_added(on_func_added))
    except Exception:
        pass  # Silently skip.

    try:
        def on_func_deleted(address: int) -> None:
            change_log.add("IDB", "func_del",
                           f"Removed function at {fmt_addr(address)}", address)
        tokens.append(idax.event.on_function_deleted(on_func_deleted))
    except Exception:
        pass  # Silently skip.

    # ── Rename events ───────────────────────────────────────────────────

    try:
        def on_renamed(address: int, new_name: str, old_name: str) -> None:
            change_log.add("IDB", "rename",
                           f"'{old_name}' -> '{new_name}'", address)
        tokens.append(idax.event.on_renamed(on_renamed))
    except Exception:
        pass  # Silently skip.

    # ── Byte patch events ───────────────────────────────────────────────

    try:
        def on_byte_patched(address: int, old_value: int) -> None:
            change_log.add("IDB", "patch",
                           f"byte patched (was 0x{old_value:x})", address)
        tokens.append(idax.event.on_byte_patched(on_byte_patched))
    except Exception:
        pass  # Silently skip.

    # ── Comment change events ───────────────────────────────────────────

    try:
        def on_comment_changed(address: int, repeatable: bool) -> None:
            kind = "Repeatable" if repeatable else "Regular"
            change_log.add("IDB", "comment",
                           f"{kind} comment changed", address)
        tokens.append(idax.event.on_comment_changed(on_comment_changed))
    except Exception:
        pass  # Silently skip.

    # ── Generic catch-all handler ───────────────────────────────────────
    # Fires for every event, including those already handled above.
    # Useful for total event counting or feeding a synchronisation service.

    try:
        def on_event(_ev: dict) -> None:
            # Deliberately empty -- typed handlers above do the logging.
            # This demonstrates subscribing to the generic event stream.
            pass
        tokens.append(idax.event.on_event(on_event))
    except Exception:
        pass  # Silently skip.

    print(f"[ChangeTracker] Subscribed with {len(tokens)} handler(s)\n")
    return tokens


def stop_tracking(tokens: list[int]) -> None:
    """
    Unsubscribe all event tokens.

    Tokens that have already been invalidated (e.g. by database close) are
    silently skipped.
    """
    for token in tokens:
        try:
            idax.event.unsubscribe(token)
        except Exception:
            pass  # Token may already be invalid.


# ═══════════════════════════════════════════════════════════════════════════
# Netnode persistence
# ═══════════════════════════════════════════════════════════════════════════

def persist_summary() -> None:
    """
    Persist the change log summary to a netnode.

    Stores:
      - Total change count as an alt value.
      - Human-readable total as a hash value.
      - Per-domain breakdown as hash values keyed by `domain_<NAME>`.

    Also performs a read-back verification to demonstrate round-trip storage.
    """
    print("\n[ChangeTracker] Persisting summary to netnode storage...")

    try:
        node = idax.storage.open(STORAGE_NODE_NAME, create=True)

        # Total change count (integer).
        node.set_alt(STORAGE_ALT_INDEX, change_log.size, ALT_TAG)

        # Human-readable total (string).
        node.set_hash("last_session_changes", str(change_log.size), HASH_TAG)

        # Per-domain breakdown.
        domains = change_log.domain_counts()
        for domain, count in domains.items():
            node.set_hash(f"domain_{domain}", str(count), HASH_TAG)

        print(f"  Stored {change_log.size} change(s) to netnode '{STORAGE_NODE_NAME}'")

        # Verification: read back the alt value.
        read_back = node.alt(STORAGE_ALT_INDEX, ALT_TAG)
        print(f"  Verification read-back: {read_back} change(s)")
    except Exception as err:
        print(f"  [warn] Could not persist summary: {error_message(err)}")


# ═══════════════════════════════════════════════════════════════════════════
# Scripted modifications -- generate events in headless mode
# ═══════════════════════════════════════════════════════════════════════════

def perform_scripted_modifications() -> None:
    """
    Perform a series of controlled database modifications to exercise the
    event system and demonstrate the bindings.

    In the interactive plugin the user's actions generate events.  In headless
    mode we simulate a realistic analysis session: renaming, commenting,
    patching, and reverting.
    """
    print("[ChangeTracker] Performing scripted modifications to generate events...\n")

    funcs = idax.function.all()
    if len(funcs) == 0:
        print("  No functions found -- skipping modifications.")
        return

    first_func = funcs[0]
    original_name: str = first_func.name

    # 1. Rename a function (and rename it back).
    print(f"  --- Rename test on '{original_name}' ---")
    try:
        idax.name.force_set(first_func.start, "idax_tracker_test_rename")
        idax.name.force_set(first_func.start, original_name)
    except Exception as err:
        print(f"  [warn] Rename test failed: {error_message(err)}")

    # 2. Add and remove a regular comment.
    print(f"  --- Comment test on {fmt_addr(first_func.start)} ---")
    try:
        idax.comment.set(first_func.start, "Change Tracker test comment")
        idax.comment.remove(first_func.start)
    except Exception as err:
        print(f"  [warn] Comment test failed: {error_message(err)}")

    # 3. Patch a byte and revert it.
    print(f"  --- Patch test on {fmt_addr(first_func.start)} ---")
    try:
        original_byte: int = idax.data.read_byte(first_func.start)
        patched_byte: int = (original_byte ^ 0xFF) & 0xFF
        idax.data.patch_byte(first_func.start, patched_byte)
        idax.data.revert_patch(first_func.start)
    except Exception as err:
        print(f"  [warn] Patch test failed: {error_message(err)}")

    # 4. Add and remove a repeatable comment on a second function.
    if len(funcs) >= 2:
        second_func = funcs[1]
        print(f"  --- Repeatable comment test on '{second_func.name}' ---")
        try:
            idax.comment.set(second_func.start, "Repeatable tracker annotation", True)
            idax.comment.remove(second_func.start, True)
        except Exception as err:
            print(f"  [warn] Repeatable comment test failed: {error_message(err)}")

    print("")


# ═══════════════════════════════════════════════════════════════════════════
# Address classification
# ═══════════════════════════════════════════════════════════════════════════

def classify_addresses(addresses: set[int]) -> AddressClassification:
    """
    Classify affected addresses: how many fall within known functions or
    segments.  This replaces the C++ plugin's graph-based impact visualisation.
    """
    in_functions: int = 0
    in_segments: int = 0

    for addr in addresses:
        try:
            idax.function.at(addr)
            in_functions += 1
        except Exception:
            pass  # not a function
        try:
            idax.segment.at(addr)
            in_segments += 1
        except Exception:
            pass  # not in a segment

    return AddressClassification(
        total=len(addresses),
        in_functions=in_functions,
        in_segments=in_segments,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Report rendering
# ═══════════════════════════════════════════════════════════════════════════

def generate_report() -> None:
    print("=== Change Tracker Summary ===\n")
    print(f"  Total changes recorded: {change_log.size}")

    if change_log.size == 0:
        print("  No changes were captured.")
        return

    # ── Per-domain breakdown ────────────────────────────────────────────
    domains = change_log.domain_counts()
    print("\n  By domain:")
    for domain, count in domains.items():
        print(f"    {domain}: {count} event(s)")

    # ── Per-kind breakdown (sorted descending) ──────────────────────────
    kinds = change_log.kind_counts()
    sorted_kinds = sorted(kinds.items(), key=lambda kv: kv[1], reverse=True)

    print("\n  By kind:")
    for kind, count in sorted_kinds:
        print(f"    {kind}: {count}")

    # ── Affected addresses ──────────────────────────────────────────────
    affected = change_log.affected_addresses()
    classification = classify_addresses(affected)

    print(f"\n  Unique addresses affected: {classification.total}")
    if classification.total > 0:
        print(f"    In functions: {classification.in_functions}")
        print(f"    In segments:  {classification.in_segments}")

    # ── Timeline ────────────────────────────────────────────────────────
    records = change_log.records
    first = records[0]
    last = records[-1]

    print(f"\n  Timeline: {first.timestamp_ms}ms - {last.timestamp_ms}ms")
    print(f"    First: [{first.domain}] {first.kind} -- {first.description}")
    print(f"    Last:  [{last.domain}] {last.kind} -- {last.description}")

    # ── Full change log table ───────────────────────────────────────────
    print("\n  Full log:")
    print("  Time(ms) | Domain | Kind             | Description")
    print("  ---------+--------+------------------+------------")

    for r in records:
        time_str = str(r.timestamp_ms).rjust(8)
        domain_str = r.domain.ljust(6)
        kind_str = r.kind.ljust(16)
        print(f"  {time_str} | {domain_str} | {kind_str} | {r.description}")


# ═══════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python examples/change_tracker.py <path-to-binary-or-idb>",
              file=sys.stderr)
        sys.exit(1)

    input_path: str = sys.argv[1]

    # ── Database lifecycle ───────────────────────────────────────────────
    idax.database.init(quiet=True)
    idax.database.open(input_path)

    print("=== Change Tracker ===")
    print(f"Input:     {idax.database.input_file_path()}")
    print(f"Processor: {idax.database.processor_name()}")
    print(f"Bitness:   {idax.database.address_bitness()}")
    print(f"Functions: {idax.function.count()}")
    print(f"Segments:  {idax.segment.count()}\n")

    # ── Start event tracking ────────────────────────────────────────────
    tokens = start_tracking()

    # ── Perform modifications that generate events ──────────────────────
    perform_scripted_modifications()

    # ── Stop tracking and clean up subscriptions ────────────────────────
    print(f"[ChangeTracker] Stopping. {change_log.size} total change(s) recorded.")
    stop_tracking(tokens)

    # ── Persist summary to netnode storage ───────────────────────────────
    persist_summary()

    # ── Summary report ──────────────────────────────────────────────────
    print("")
    generate_report()

    print("\n=== Change Tracker Complete ===")

    # ── Teardown ────────────────────────────────────────────────────────
    # Pass False to discard test modifications (rename-backs, comment
    # removals, etc.).
    idax.database.close(False)


if __name__ == "__main__":
    main()
    os._exit(0)  # avoid idalib shutdown crash
