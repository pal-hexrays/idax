#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Load .env if present ────────────────────────────────────────────────
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    set -a
    source "$SCRIPT_DIR/.env"
    set +a
fi

# ── Verify required environment ─────────────────────────────────────────
if [[ -z "${IDASDK:-}" ]]; then
    echo "Error: IDASDK is not set. Export it or add it to .env" >&2
    exit 1
fi

# ── Parse arguments ─────────────────────────────────────────────────────
BUILD_DIR="build"
TARGETS=()

usage() {
    echo "Usage: $0 [options] [targets...]"
    echo ""
    echo "Targets (default: all):"
    echo "  core       Build libidax.a only"
    echo "  node       Build Node.js bindings"
    echo "  rust       Build Rust bindings"
    echo "  python     Build Python bindings"
    echo "  all        Build everything (default)"
    echo ""
    echo "Options:"
    echo "  -B DIR     Set build directory (default: build)"
    echo "  -h         Show this help"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -B)
            BUILD_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        core|node|rust|python|all)
            TARGETS+=("$1")
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

# Default to building everything
if [[ ${#TARGETS[@]} -eq 0 ]]; then
    TARGETS=(all)
fi

should_build() {
    local target="$1"
    for t in "${TARGETS[@]}"; do
        if [[ "$t" == "all" || "$t" == "$target" ]]; then
            return 0
        fi
    done
    return 1
}

# ── Build libidax.a (core C++ library) ──────────────────────────────────
if should_build core; then
    echo "══ Building libidax.a ══"
    cmake -B "$BUILD_DIR" -DIDAX_BUILD_TESTS=ON -DIDAX_BUILD_EXAMPLES=ON
    cmake --build "$BUILD_DIR"
    echo ""
fi

# ── Build Node.js bindings ──────────────────────────────────────────────
if should_build node; then
    echo "══ Building Node.js bindings ══"
    cd "$SCRIPT_DIR/bindings/node"
    npm install --ignore-scripts
    npm run build
    cd "$SCRIPT_DIR"
    echo ""
fi

# ── Build Rust bindings ─────────────────────────────────────────────────
if should_build rust; then
    echo "══ Building Rust bindings ══"
    cd "$SCRIPT_DIR/bindings/rust"
    cargo build
    cd "$SCRIPT_DIR"
    echo ""
fi

# ── Build Python bindings ──────────────────────────────────────────────
if should_build python; then
    echo "══ Building Python bindings ══"
    cd "$SCRIPT_DIR/bindings/python"
    uv pip install --no-build-isolation -e .
    cd "$SCRIPT_DIR"
    echo ""
fi

echo "Done."
