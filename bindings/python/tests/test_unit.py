"""
Comprehensive unit tests for the idax Python bindings.

These tests validate:
- Module loading and structure
- Namespace exports completeness
- BAD_ADDRESS sentinel value
- Function presence on every namespace
- Pure Python logic (no IDA runtime needed for structural tests)

Integration tests (requiring IDADIR and a real binary) are in test_integration.py
"""

import pytest

# ── Helpers ──────────────────────────────────────────────────────────────

_idax = None
_load_error = None

try:
    import idax
    _idax = idax._idax
except Exception as e:
    _load_error = e


def skip_if_not_built():
    if _load_error is not None:
        pytest.skip(f"Native addon not built: {_load_error}")


# ── Module Loading ──────────────────────────────────────────────────────


class TestModuleLoading:
    def test_should_load_native_addon_without_errors(self):
        if _load_error is not None:
            pytest.skip(f"Native addon not built: {_load_error}")
        assert _idax is not None

    def test_should_export_bad_address_as_int_sentinel(self):
        skip_if_not_built()
        assert isinstance(idax.BAD_ADDRESS, int)
        assert idax.BAD_ADDRESS == 0xFFFFFFFFFFFFFFFF


# ── Namespace Exports ───────────────────────────────────────────────────

EXPECTED_NAMESPACES = [
    "database", "address", "segment", "function", "instruction",
    "name", "xref", "comment", "data", "search", "analysis",
    "types", "entry", "fixup", "event", "storage", "diagnostics",
    "lumina", "lines", "decompiler",
]


class TestNamespaceExports:
    @pytest.mark.parametrize("ns", EXPECTED_NAMESPACES)
    def test_should_export_namespace(self, ns):
        skip_if_not_built()
        obj = getattr(_idax, ns, None)
        assert obj is not None, f"Namespace '{ns}' not found"


# ── Database Namespace Functions ─────────────────────────────────────────

DATABASE_FUNCTIONS = [
    "init", "open", "save", "close",
    "input_file_path", "file_type_name", "input_md5",
    "compiler_info", "import_modules", "image_base",
    "processor_id", "processor_name", "address_bitness", "set_address_bitness",
    "is_big_endian", "abi_name",
    "min_address", "max_address", "address_bounds", "address_span",
]


class TestDatabaseNamespace:
    @pytest.mark.parametrize("fn", DATABASE_FUNCTIONS)
    def test_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.database, fn, None)), \
            f"database.{fn} not found or not callable"


# ── Address Namespace Functions ──────────────────────────────────────────

ADDRESS_FUNCTIONS = [
    "item_start", "item_end", "item_size",
    "next_head", "prev_head", "next_defined", "prev_defined",
    "next_not_tail", "prev_not_tail", "next_mapped", "prev_mapped",
    "is_mapped", "is_loaded", "is_code", "is_data", "is_unknown",
    "is_head", "is_tail",
    "find_first", "find_next",
    "items", "code_items", "data_items", "unknown_bytes",
]


class TestAddressNamespace:
    @pytest.mark.parametrize("fn", ADDRESS_FUNCTIONS)
    def test_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.address, fn, None)), \
            f"address.{fn} not found or not callable"


# ── Segment Namespace Functions ─────────────────────────────────────────

SEGMENT_FUNCTIONS = [
    "create", "remove", "at", "by_name", "by_index", "count",
    "set_name", "set_class", "set_type", "set_permissions", "set_bitness",
    "comment", "set_comment", "resize", "move",
    "all", "first", "last", "next", "prev",
]


class TestSegmentNamespace:
    @pytest.mark.parametrize("fn", SEGMENT_FUNCTIONS)
    def test_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.segment, fn, None)), \
            f"segment.{fn} not found or not callable"


# ── Function Namespace Functions ────────────────────────────────────────

FUNCTION_FUNCTIONS = [
    "create", "remove", "at", "by_index", "count", "name_at",
    "set_start", "set_end", "update", "reanalyze",
    "comment", "set_comment",
    "callers", "callees", "chunks", "tail_chunks",
    "frame", "all",
    "item_addresses", "code_addresses",
]


class TestFunctionNamespace:
    @pytest.mark.parametrize("fn", FUNCTION_FUNCTIONS)
    def test_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.function, fn, None)), \
            f"function.{fn} not found or not callable"


# ── Instruction Namespace Functions ─────────────────────────────────────

INSTRUCTION_FUNCTIONS = [
    "decode", "create", "text",
    "set_operand_hex", "set_operand_decimal",
    "operand_text", "operand_byte_width",
    "code_refs_from", "data_refs_from", "call_targets",
    "is_call", "is_return", "is_jump",
    "next", "prev",
]


class TestInstructionNamespace:
    @pytest.mark.parametrize("fn", INSTRUCTION_FUNCTIONS)
    def test_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.instruction, fn, None)), \
            f"instruction.{fn} not found or not callable"


# ── Name, Comment, XRef Namespace Functions ──────────────────────────────

NAME_FUNCTIONS = ["set", "force_set", "remove", "get", "demangled", "resolve", "all"]
COMMENT_FUNCTIONS = ["get", "set", "append", "remove", "add_anterior", "add_posterior", "render"]
XREF_FUNCTIONS = ["add_code", "add_data", "remove_code", "remove_data", "refs_from", "refs_to", "is_call", "is_jump"]


class TestNameCommentXrefNamespace:
    @pytest.mark.parametrize("fn", NAME_FUNCTIONS)
    def test_name_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.name, fn, None)), \
            f"name.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", COMMENT_FUNCTIONS)
    def test_comment_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.comment, fn, None)), \
            f"comment.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", XREF_FUNCTIONS)
    def test_xref_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.xref, fn, None)), \
            f"xref.{fn} not found or not callable"


# ── Data Namespace Functions ────────────────────────────────────────────

DATA_FUNCTIONS = [
    "read_byte", "read_word", "read_dword", "read_qword", "read_bytes",
    "write_byte", "write_word", "write_dword", "write_qword", "write_bytes",
    "patch_byte", "patch_word", "patch_dword",
    "revert_patch", "original_byte",
    "define_byte", "define_word", "define_dword",
    "undefine", "find_binary_pattern",
]


class TestDataNamespace:
    @pytest.mark.parametrize("fn", DATA_FUNCTIONS)
    def test_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.data, fn, None)), \
            f"data.{fn} not found or not callable"


# ── Search, Analysis, Entry, Fixup, Event ───────────────────────────────

SEARCH_FUNCTIONS = ["text", "immediate", "binary_pattern", "next_code", "next_data"]
ANALYSIS_FUNCTIONS = ["is_enabled", "set_enabled", "is_idle", "wait", "schedule"]
ENTRY_FUNCTIONS = ["count", "by_index", "by_ordinal", "add", "rename"]
FIXUP_FUNCTIONS = ["at", "exists", "remove", "first"]
EVENT_FUNCTIONS = ["on_segment_added", "on_function_added", "on_renamed", "on_byte_patched", "unsubscribe"]


class TestSearchAnalysisEntryFixupEvent:
    @pytest.mark.parametrize("fn", SEARCH_FUNCTIONS)
    def test_search_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.search, fn, None)), \
            f"search.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", ANALYSIS_FUNCTIONS)
    def test_analysis_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.analysis, fn, None)), \
            f"analysis.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", ENTRY_FUNCTIONS)
    def test_entry_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.entry, fn, None)), \
            f"entry.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", FIXUP_FUNCTIONS)
    def test_fixup_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.fixup, fn, None)), \
            f"fixup.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", EVENT_FUNCTIONS)
    def test_event_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.event, fn, None)), \
            f"event.{fn} not found or not callable"


# ── Type, Storage, Decompiler, Lines, Diagnostics, Lumina ────────────────

TYPE_FUNCTIONS = [
    "void_type", "int8", "int16", "int32", "int64",
    "uint8", "uint16", "uint32", "uint64",
    "float32", "float64", "pointer_to", "array_of",
    "from_declaration", "create_struct", "create_union",
]
STORAGE_FUNCTIONS = ["open", "open_by_id"]
DECOMPILER_FUNCTIONS = [
    "available", "decompile", "unsubscribe",
    "mark_dirty", "mark_dirty_with_callers",
    "register_microcode_filter", "unregister_microcode_filter",
]
LINES_FUNCTIONS = ["colstr", "tag_remove", "tag_advance", "tag_strlen", "make_addr_tag", "decode_addr_tag"]
DIAGNOSTICS_FUNCTIONS = ["set_log_level", "log_level", "log", "assert_invariant", "reset_performance_counters", "performance_counters"]
LUMINA_FUNCTIONS = ["has_connection", "close_connection", "close_all_connections", "pull", "push"]


class TestTypeStorageDecompilerLinesDiagnosticsLumina:
    @pytest.mark.parametrize("fn", TYPE_FUNCTIONS)
    def test_type_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.types, fn, None)), \
            f"types.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", STORAGE_FUNCTIONS)
    def test_storage_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.storage, fn, None)), \
            f"storage.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", DECOMPILER_FUNCTIONS)
    def test_decompiler_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.decompiler, fn, None)), \
            f"decompiler.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", LINES_FUNCTIONS)
    def test_lines_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.lines, fn, None)), \
            f"lines.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", DIAGNOSTICS_FUNCTIONS)
    def test_diagnostics_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.diagnostics, fn, None)), \
            f"diagnostics.{fn} not found or not callable"

    @pytest.mark.parametrize("fn", LUMINA_FUNCTIONS)
    def test_lumina_function_presence(self, fn):
        skip_if_not_built()
        assert callable(getattr(_idax.lumina, fn, None)), \
            f"lumina.{fn} not found or not callable"


# ── BadAddress Semantics ────────────────────────────────────────────────


class TestBadAddressSemantics:
    def test_should_be_maximum_64bit_unsigned_value(self):
        skip_if_not_built()
        assert idax.BAD_ADDRESS == 0xFFFFFFFFFFFFFFFF
        assert idax.BAD_ADDRESS == (1 << 64) - 1

    def test_should_be_an_int(self):
        skip_if_not_built()
        assert isinstance(idax.BAD_ADDRESS, int)

    def test_should_wrap_to_zero_on_increment(self):
        skip_if_not_built()
        # Python ints don't wrap, but we test the sentinel mask behavior
        wrapped = (idax.BAD_ADDRESS + 1) & 0xFFFFFFFFFFFFFFFF
        assert wrapped == 0
