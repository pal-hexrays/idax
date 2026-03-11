#!/usr/bin/env python3
"""
Headless Python adaptation of examples/tools/idalib_lumina_port.cpp.

Usage:
    python examples/idalib_lumina_port.py <binary-or-idb>
"""

from __future__ import annotations

import os
import sys

import idax


def hex_addr(address: int) -> str:
    return f"0x{address:x}"


def is_idax_error(err: BaseException) -> bool:
    return isinstance(err, idax.IdaxError)


def error_message(err: BaseException) -> str:
    if isinstance(err, idax.IdaxError):
        context = f" ({err.context})" if err.context else ""
        return f"[{err.category}] {err}{context}"
    return str(err)


def resolve_target_function() -> int:
    try:
        return idax.name.resolve("main", idax.BAD_ADDRESS)
    except Exception:
        return idax.function.by_index(0).start


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: python examples/idalib_lumina_port.py <binary-or-idb>",
            file=sys.stderr,
        )
        sys.exit(1)

    input_path = sys.argv[1]

    try:
        idax.database.init(quiet=True)
        idax.database.open(input_path, True)
        idax.analysis.wait()

        target: int = resolve_target_function()

        pull = idax.lumina.pull(
            target,
            auto_apply=True,
            skip_frequency_update=False,
            feature=idax.lumina.Feature.primary_metadata,
        )
        push = idax.lumina.push(
            target,
            mode=idax.lumina.PushMode.prefer_better_or_different,
            feature=idax.lumina.Feature.primary_metadata,
        )

        print(f"target={hex_addr(target)}")
        print(
            f"pull: requested={pull.requested} completed={pull.completed} "
            f"succeeded={pull.succeeded} failed={pull.failed}"
        )
        print(
            f"push: requested={push.requested} completed={push.completed} "
            f"succeeded={push.succeeded} failed={push.failed}"
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
