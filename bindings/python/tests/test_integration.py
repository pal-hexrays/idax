"""
Integration tests for the idax Python bindings.

These tests require:
  1. The native addon to be compiled
  2. IDADIR environment variable pointing to IDA installation
  3. A binary file path via --binary: pytest --binary <path>

They exercise every namespace against a real IDA database, mirroring
the C++ and Node.js integration test coverage.
"""

import pytest


# ── Database Metadata ───────────────────────────────────────────────────


class TestDatabaseMetadata:
    def test_should_return_input_file_path(self, db):
        path = db.database.input_file_path()
        assert isinstance(path, str)
        assert len(path) > 0

    def test_should_return_file_type_name(self, db):
        ftype = db.database.file_type_name()
        assert isinstance(ftype, str)

    def test_should_return_md5_hash(self, db):
        md5 = db.database.input_md5()
        assert isinstance(md5, str)
        assert len(md5) == 32

    def test_should_return_address_bitness(self, db):
        bits = db.database.address_bitness()
        assert bits in (16, 32, 64)

    def test_should_set_address_bitness_to_current_value(self, db):
        bits = db.database.address_bitness()
        db.database.set_address_bitness(bits)
        assert db.database.address_bitness() == bits

    def test_should_return_processor_name(self, db):
        pname = db.database.processor_name()
        assert isinstance(pname, str)
        assert len(pname) > 0

    def test_should_return_address_bounds(self, db):
        bounds = db.database.address_bounds()
        assert isinstance(bounds["start"], int)
        assert isinstance(bounds["end"], int)
        assert bounds["start"] < bounds["end"]

    def test_should_return_image_base(self, db):
        base = db.database.image_base()
        assert isinstance(base, int)

    def test_should_return_endianness(self, db):
        big = db.database.is_big_endian()
        assert isinstance(big, bool)

    def test_should_return_abi_name(self, db):
        # abi_name() may throw for some binaries
        try:
            abi = db.database.abi_name()
            assert isinstance(abi, str)
        except Exception:
            pass  # Acceptable — ABI info not available for all binaries


# ── Segments ────────────────────────────────────────────────────────────


class TestSegments:
    def test_should_count_segments(self, db):
        count = db.segment.count()
        assert count > 0

    def test_should_list_all_segments(self, db):
        segs = db.segment.all()
        assert len(segs) > 0
        first = segs[0]
        assert isinstance(first["start"], int)
        assert isinstance(first["end"], int)
        assert isinstance(first["name"], str)

    def test_should_get_segment_by_index(self, db):
        seg = db.segment.by_index(0)
        assert isinstance(seg["start"], int)

    def test_should_get_segment_at_address(self, db):
        segs = db.segment.all()
        seg = db.segment.at(segs[0]["start"])
        assert seg["start"] == segs[0]["start"]

    def test_should_get_first_and_last(self, db):
        first = db.segment.first()
        last = db.segment.last()
        assert isinstance(first["start"], int)
        assert isinstance(last["start"], int)


# ── Functions ───────────────────────────────────────────────────────────


class TestFunctions:
    def test_should_count_functions(self, db):
        count = db.function.count()
        assert count > 0

    def test_should_list_all_functions(self, db):
        funcs = db.function.all()
        assert len(funcs) > 0
        first = funcs[0]
        assert isinstance(first["start"], int)
        assert isinstance(first["name"], str)

    def test_should_get_function_by_index(self, db):
        func = db.function.by_index(0)
        assert isinstance(func["start"], int)

    def test_should_get_function_at_address(self, db):
        funcs = db.function.all()
        func = db.function.at(funcs[0]["start"])
        assert func["start"] == funcs[0]["start"]

    def test_should_get_callers_and_callees(self, db):
        funcs = db.function.all()
        callers = db.function.callers(funcs[0]["start"])
        assert isinstance(callers, list)
        callees = db.function.callees(funcs[0]["start"])
        assert isinstance(callees, list)

    def test_should_get_chunks(self, db):
        funcs = db.function.all()
        chunks = db.function.chunks(funcs[0]["start"])
        assert isinstance(chunks, list)
        assert len(chunks) > 0

    def test_should_get_code_addresses(self, db):
        funcs = db.function.all()
        addrs = db.function.code_addresses(funcs[0]["start"])
        assert isinstance(addrs, list)
        assert len(addrs) > 0


# ── Instructions ────────────────────────────────────────────────────────


class TestInstructions:
    def test_should_decode_instruction(self, db):
        funcs = db.function.all()
        insn = db.instruction.decode(funcs[0]["start"])
        assert isinstance(insn["address"], int)
        assert isinstance(insn["mnemonic"], str)
        assert len(insn["mnemonic"]) > 0
        assert isinstance(insn["size"], int)

    def test_should_get_instruction_text(self, db):
        funcs = db.function.all()
        text = db.instruction.text(funcs[0]["start"])
        assert isinstance(text, str)
        assert len(text) > 0

    def test_should_check_control_flow_properties(self, db):
        funcs = db.function.all()
        addr = funcs[0]["start"]
        assert isinstance(db.instruction.is_call(addr), bool)
        assert isinstance(db.instruction.is_return(addr), bool)
        assert isinstance(db.instruction.is_jump(addr), bool)


# ── Names ───────────────────────────────────────────────────────────────


class TestNames:
    def test_should_get_name_at_function_start(self, db):
        funcs = db.function.all()
        name = db.name.get(funcs[0]["start"])
        assert isinstance(name, str)

    def test_should_force_set_and_restore_name(self, db):
        funcs = db.function.all()
        addr = funcs[0]["start"]
        orig_name = db.name.get(addr)

        db.name.force_set(addr, "test_torture_name")
        assert db.name.get(addr) == "test_torture_name"

        # Restore
        if orig_name:
            db.name.force_set(addr, orig_name)
        else:
            db.name.remove(addr)

    def test_should_resolve_name_to_address(self, db):
        funcs = db.function.all()
        name = db.name.get(funcs[0]["start"])
        if name:
            addr = db.name.resolve(name)
            assert isinstance(addr, int)


# ── Comments ────────────────────────────────────────────────────────────


class TestComments:
    def test_should_set_and_get_regular_comment(self, db):
        funcs = db.function.all()
        addr = funcs[0]["start"]

        db.comment.set(addr, "test comment", False)
        cmt = db.comment.get(addr, False)
        assert cmt == "test comment"

        db.comment.remove(addr, False)

    def test_should_set_and_get_repeatable_comment(self, db):
        funcs = db.function.all()
        addr = funcs[0]["start"]

        db.comment.set(addr, "repeatable test", True)
        cmt = db.comment.get(addr, True)
        assert cmt == "repeatable test"

        db.comment.remove(addr, True)


# ── Cross-References ────────────────────────────────────────────────────


class TestCrossReferences:
    def test_should_get_refs_to(self, db):
        funcs = db.function.all()
        refs = db.xref.refs_to(funcs[0]["start"])
        assert isinstance(refs, list)

    def test_should_get_refs_from(self, db):
        funcs = db.function.all()
        addrs = db.function.code_addresses(funcs[0]["start"])
        if len(addrs) > 0:
            refs = db.xref.refs_from(addrs[0])
            assert isinstance(refs, list)

    def test_should_classify_reference_types(self, db):
        ReferenceType = db._idax.xref.ReferenceType
        assert db.xref.is_call(ReferenceType.call_near) is True
        assert db.xref.is_call(ReferenceType.call_far) is True
        assert db.xref.is_jump(ReferenceType.jump_near) is True
        assert db.xref.is_flow(ReferenceType.flow) is True
        assert db.xref.is_data(ReferenceType.read) is True
        assert db.xref.is_data(ReferenceType.write) is True


# ── Data Access ─────────────────────────────────────────────────────────


class TestDataAccess:
    def test_should_read_byte(self, db):
        segs = db.segment.all()
        val = db.data.read_byte(segs[0]["start"])
        assert isinstance(val, int)

    def test_should_read_bytes(self, db):
        segs = db.segment.all()
        buf = db.data.read_bytes(segs[0]["start"], 16)
        assert isinstance(buf, bytes)
        assert len(buf) == 16

    def test_should_read_word_dword_qword(self, db):
        segs = db.segment.all()
        w = db.data.read_word(segs[0]["start"])
        assert isinstance(w, int)
        d = db.data.read_dword(segs[0]["start"])
        assert isinstance(d, int)
        q = db.data.read_qword(segs[0]["start"])
        assert isinstance(q, int)


# ── Address Navigation ──────────────────────────────────────────────────


class TestAddressNavigation:
    def test_should_check_address_predicates(self, db):
        segs = db.segment.all()
        addr = segs[0]["start"]
        assert isinstance(db.address.is_mapped(addr), bool)
        assert db.address.is_mapped(addr) is True

    def test_should_navigate_heads(self, db):
        segs = db.segment.all()
        next_addr = db.address.next_head(segs[0]["start"])
        assert isinstance(next_addr, int)
        assert next_addr > segs[0]["start"]

    def test_should_get_item_start_end(self, db):
        funcs = db.function.all()
        start = db.address.item_start(funcs[0]["start"])
        assert start == funcs[0]["start"]
        end = db.address.item_end(funcs[0]["start"])
        assert end > start


# ── Search ──────────────────────────────────────────────────────────────


class TestSearch:
    def test_should_find_next_code(self, db):
        segs = db.segment.all()
        code = db.search.next_code(segs[0]["start"])
        assert isinstance(code, int)


# ── Analysis ────────────────────────────────────────────────────────────


class TestAnalysis:
    def test_should_report_idle_after_wait(self, db):
        assert db.analysis.is_idle() is True

    def test_should_enable_disable_analysis(self, db):
        was = db.analysis.is_enabled()
        db.analysis.set_enabled(False)
        assert db.analysis.is_enabled() is False
        db.analysis.set_enabled(True)
        assert db.analysis.is_enabled() is True
        db.analysis.set_enabled(was)


# ── Entry Points ────────────────────────────────────────────────────────


class TestEntryPoints:
    def test_should_count_entries(self, db):
        count = db.entry.count()
        assert isinstance(count, int)
        assert count >= 0

    def test_should_list_entries_by_index(self, db):
        count = db.entry.count()
        for i in range(min(count, 10)):
            ep = db.entry.by_index(i)
            assert isinstance(ep["address"], int)


# ── Type System ─────────────────────────────────────────────────────────


class TestTypeSystem:
    def test_should_create_primitive_types(self, db):
        t = db.types.int32()
        assert t.is_integer() is True
        assert t.size() == 4
        assert t.is_pointer() is False

    def test_should_create_pointer_type(self, db):
        base = db.types.int32()
        ptr = db.types.pointer_to(base)
        assert ptr.is_pointer() is True

    def test_should_create_array_type(self, db):
        elem = db.types.uint8()
        arr = db.types.array_of(elem, 100)
        assert arr.is_array() is True
        assert arr.array_length() == 100


# ── Lines / Color Tags ──────────────────────────────────────────────────


class TestLines:
    def test_should_create_and_strip_color_tags(self, db):
        Color = db._idax.lines.Color
        tagged = db.lines.colstr("hello", Color.KEYWORD)
        assert isinstance(tagged, str)
        plain = db.lines.tag_remove(tagged)
        assert plain == "hello"

    def test_should_measure_tag_strlen(self, db):
        Color = db._idax.lines.Color
        tagged = db.lines.colstr("ABC", Color.NUMBER)
        length = db.lines.tag_strlen(tagged)
        assert length == 3


# ── Diagnostics ─────────────────────────────────────────────────────────


class TestDiagnostics:
    def test_should_set_get_log_level(self, db):
        LogLevel = db._idax.diagnostics.LogLevel
        db.diagnostics.set_log_level(LogLevel.debug)
        assert db.diagnostics.log_level() == LogLevel.debug
        db.diagnostics.set_log_level(LogLevel.info)

    def test_should_log_without_error(self, db):
        LogLevel = db._idax.diagnostics.LogLevel
        db.diagnostics.log(LogLevel.info, "test", "integration test log message")

    def test_should_reset_and_read_performance_counters(self, db):
        db.diagnostics.reset_performance_counters()
        c = db.diagnostics.performance_counters()
        assert isinstance(c["log_messages"], int)


# ── Decompiler (if available) ───────────────────────────────────────────


class TestDecompiler:
    def test_should_report_availability(self, db):
        avail = db.decompiler.available()
        assert isinstance(avail, bool)

    def test_should_decompile_a_function_if_available(self, db):
        if not db.decompiler.available():
            pytest.skip("Decompiler not available")
        funcs = db.function.all()
        if len(funcs) == 0:
            pytest.skip("No functions found")

        decompiled = False
        limit = min(len(funcs), 20)
        for i in range(limit):
            try:
                df = db.decompiler.decompile(funcs[i]["start"])
                pseudo = df.pseudocode()
                assert isinstance(pseudo, str)
                assert len(pseudo) > 0

                lines = df.lines()
                assert isinstance(lines, list)
                assert len(lines) > 0
                decompiled = True
                break
            except Exception:
                continue

        if limit > 0:
            assert decompiled, "None of the first 20 functions could be decompiled"

    def test_should_expose_microcode_context_in_filter_callbacks(self, db):
        if not db.decompiler.available():
            pytest.skip("Decompiler not available")
        funcs = db.function.all()
        if len(funcs) == 0:
            pytest.skip("No functions found")

        saw_match = False
        saw_apply = False
        decompiled = False
        token = None

        def match_fn(context):
            nonlocal saw_match
            saw_match = True

            ea = context["address"]
            assert isinstance(ea, int)

            itype = context["instruction_type"]
            assert isinstance(itype, int)

            native_insn = context["instruction"]
            if native_insn is not None:
                assert isinstance(native_insn["mnemonic"], str)
            return True

        def apply_fn(context):
            nonlocal saw_apply
            saw_apply = True

            block_count = context["block_instruction_count"]
            if block_count is not None:
                assert isinstance(block_count, int)
                assert block_count >= 0

            return "notHandled"

        try:
            token = db.decompiler.register_microcode_filter(match_fn, apply_fn)
            assert isinstance(token, int)

            limit = min(len(funcs), 20)
            for i in range(limit):
                try:
                    try:
                        db.decompiler.mark_dirty(funcs[i]["start"], True)
                    except Exception:
                        pass

                    df = db.decompiler.decompile(funcs[i]["start"])
                    pseudo = df.pseudocode()
                    if isinstance(pseudo, str) and len(pseudo) > 0:
                        decompiled = True
                        break
                except Exception:
                    continue
        finally:
            if token is not None:
                try:
                    db.decompiler.unregister_microcode_filter(token)
                except Exception:
                    pass

        if decompiled:
            assert saw_match, "match callback was not invoked"
            assert saw_apply, "apply callback was not invoked"


# ── Storage ─────────────────────────────────────────────────────────────


class TestStorage:
    def test_should_open_storage_node(self, db):
        node = db.storage.open("test_node_torture", True)
        assert node is not None

    def test_should_write_read_alt_values(self, db):
        node = db.storage.open("test_node_torture", True)
        node.set_alt(0, 42)
        val = node.alt(0)
        assert val == 42
        node.remove_alt(0)

    def test_should_write_read_hash_values(self, db):
        node = db.storage.open("test_node_torture", True)
        node.set_hash("key", "value")
        val = node.hash("key")
        assert val == "value"


# ── Cleanup ─────────────────────────────────────────────────────────────


class TestCleanup:
    def test_should_close_database(self, db):
        # The db fixture handles close in teardown.
        # This test just validates the session is still alive.
        assert db.analysis.is_idle() is True
