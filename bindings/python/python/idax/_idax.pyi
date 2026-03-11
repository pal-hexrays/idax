"""Type stubs for the idax native extension module."""

from __future__ import annotations

from typing import Callable, overload

BAD_ADDRESS: int

# =============================================================================
# Error type
# =============================================================================

class IdaxError(RuntimeError):
    category: str
    code: int
    context: str

# =============================================================================
# database submodule
# =============================================================================

class database:
    # ── Enums ────────────────────────────────────────────────────────────
    class OpenMode:
        analyze: database.OpenMode
        skip_analysis: database.OpenMode

    class LoadIntent:
        auto_detect: database.LoadIntent
        binary: database.LoadIntent
        non_binary: database.LoadIntent

    # ── Value types ──────────────────────────────────────────────────────
    class PluginLoadPolicy:
        disable_user_plugins: bool
        allowlist_patterns: list[str]
        def __init__(
            self,
            disable_user_plugins: bool = ...,
            allowlist_patterns: list[str] = ...,
        ) -> None: ...

    class RuntimeOptions:
        quiet: bool
        plugin_policy: database.PluginLoadPolicy
        def __init__(
            self,
            quiet: bool = ...,
            plugin_policy: database.PluginLoadPolicy | None = ...,
        ) -> None: ...

    class CompilerInfo:
        id: int
        uncertain: bool
        name: str
        abbreviation: str

    class ImportSymbol:
        address: int
        name: str
        ordinal: int

    class ImportModule:
        index: int
        name: str
        symbols: list[database.ImportSymbol]

    # ── Lifecycle ────────────────────────────────────────────────────────
    @staticmethod
    def init(
        quiet: bool = ...,
        plugin_policy: database.PluginLoadPolicy | None = ...,
    ) -> None: ...
    @staticmethod
    def open(
        path: str,
        auto_analysis: bool | None = ...,
        *,
        mode: database.OpenMode | None = ...,
        intent: database.LoadIntent | None = ...,
    ) -> None: ...
    @staticmethod
    def open_binary(path: str, mode: database.OpenMode = ...) -> None: ...
    @staticmethod
    def open_non_binary(path: str, mode: database.OpenMode = ...) -> None: ...
    @staticmethod
    def save() -> None: ...
    @staticmethod
    def close(save_before: bool = ...) -> None: ...
    @staticmethod
    def file_to_database(
        file_path: str,
        file_offset: int,
        ea: int,
        size: int,
        patchable: bool = ...,
        remote: bool = ...,
    ) -> None: ...
    @staticmethod
    def memory_to_database(
        data: bytes, ea: int, file_offset: int = ...
    ) -> None: ...

    # ── Metadata ─────────────────────────────────────────────────────────
    @staticmethod
    def input_file_path() -> str: ...
    @staticmethod
    def file_type_name() -> str: ...
    @staticmethod
    def loader_format_name() -> str: ...
    @staticmethod
    def input_md5() -> str: ...
    @staticmethod
    def compiler_info() -> database.CompilerInfo: ...
    @staticmethod
    def import_modules() -> list[database.ImportModule]: ...
    @staticmethod
    def image_base() -> int: ...
    @staticmethod
    def min_address() -> int: ...
    @staticmethod
    def max_address() -> int: ...
    @staticmethod
    def address_bounds() -> dict[str, int]: ...
    @staticmethod
    def address_span() -> int: ...
    @staticmethod
    def processor_id() -> int: ...
    @staticmethod
    def processor() -> int: ...
    @staticmethod
    def processor_name() -> str: ...
    @staticmethod
    def address_bitness() -> int: ...
    @staticmethod
    def set_address_bitness(bits: int) -> None: ...
    @staticmethod
    def is_big_endian() -> bool: ...
    @staticmethod
    def abi_name() -> str: ...

    # ── Snapshots ────────────────────────────────────────────────────────
    @staticmethod
    def snapshots() -> list[dict]: ...
    @staticmethod
    def set_snapshot_description(description: str) -> None: ...
    @staticmethod
    def is_snapshot_database() -> bool: ...

# =============================================================================
# address submodule
# =============================================================================

class address:
    # ── Enum ─────────────────────────────────────────────────────────────
    class Predicate:
        mapped: address.Predicate
        loaded: address.Predicate
        code: address.Predicate
        data: address.Predicate
        unknown: address.Predicate
        head: address.Predicate
        tail: address.Predicate

    # ── Navigation ───────────────────────────────────────────────────────
    @staticmethod
    def item_start(ea: int) -> int: ...
    @staticmethod
    def item_end(ea: int) -> int: ...
    @staticmethod
    def item_size(ea: int) -> int: ...
    @staticmethod
    def next_head(ea: int, limit: int = ...) -> int: ...
    @staticmethod
    def prev_head(ea: int, limit: int = ...) -> int: ...
    @staticmethod
    def next_defined(ea: int, limit: int = ...) -> int: ...
    @staticmethod
    def prev_defined(ea: int, limit: int = ...) -> int: ...
    @staticmethod
    def next_not_tail(ea: int) -> int: ...
    @staticmethod
    def prev_not_tail(ea: int) -> int: ...
    @staticmethod
    def next_mapped(ea: int) -> int: ...
    @staticmethod
    def prev_mapped(ea: int) -> int: ...

    # ── Predicates ───────────────────────────────────────────────────────
    @staticmethod
    def is_mapped(ea: int) -> bool: ...
    @staticmethod
    def is_loaded(ea: int) -> bool: ...
    @staticmethod
    def is_code(ea: int) -> bool: ...
    @staticmethod
    def is_data(ea: int) -> bool: ...
    @staticmethod
    def is_unknown(ea: int) -> bool: ...
    @staticmethod
    def is_head(ea: int) -> bool: ...
    @staticmethod
    def is_tail(ea: int) -> bool: ...

    # ── Search ───────────────────────────────────────────────────────────
    @staticmethod
    def find_first(start: int, end: int, predicate: address.Predicate) -> int: ...
    @staticmethod
    def find_next(ea: int, predicate: address.Predicate, end: int = ...) -> int: ...

    # ── Iteration ────────────────────────────────────────────────────────
    @staticmethod
    def items(start: int, end: int) -> list[int]: ...
    @staticmethod
    def code_items(start: int, end: int) -> list[int]: ...
    @staticmethod
    def data_items(start: int, end: int) -> list[int]: ...
    @staticmethod
    def unknown_bytes(start: int, end: int) -> list[int]: ...

# =============================================================================
# segment submodule
# =============================================================================

class segment:
    # ── Enums ────────────────────────────────────────────────────────────
    class Type:
        normal: segment.Type
        external: segment.Type
        code: segment.Type
        data: segment.Type
        bss: segment.Type
        absolute_symbols: segment.Type
        common: segment.Type
        null_: segment.Type
        undefined: segment.Type
        import_: segment.Type
        internal_memory: segment.Type
        group: segment.Type

    class Permissions:
        read: bool
        write: bool
        execute: bool

    class Segment:
        start: int
        end: int
        size: int
        bitness: int
        type: segment.Type
        permissions: segment.Permissions
        name: str
        class_name: str
        is_visible: bool

    # ── CRUD ─────────────────────────────────────────────────────────────
    @staticmethod
    def create(
        start: int,
        end: int,
        name: str,
        class_name: str = ...,
        type: segment.Type = ...,
    ) -> segment.Segment: ...
    @staticmethod
    def remove(addr: int) -> None: ...

    # ── Lookup ───────────────────────────────────────────────────────────
    @staticmethod
    def at(addr: int) -> segment.Segment: ...
    @staticmethod
    def by_name(name: str) -> segment.Segment: ...
    @staticmethod
    def by_index(idx: int) -> segment.Segment: ...
    @staticmethod
    def count() -> int: ...

    # ── Property mutation ────────────────────────────────────────────────
    @staticmethod
    def set_name(addr: int, name: str) -> None: ...
    @staticmethod
    def set_class(addr: int, class_name: str) -> None: ...
    @staticmethod
    def set_type(addr: int, type: segment.Type) -> None: ...
    @staticmethod
    def set_permissions(
        addr: int, read: bool, write: bool, execute: bool
    ) -> None: ...
    @staticmethod
    def set_bitness(addr: int, bits: int) -> None: ...
    @staticmethod
    def set_default_segment_register(
        addr: int, reg_index: int, value: int
    ) -> None: ...
    @staticmethod
    def set_default_segment_register_for_all(
        reg_index: int, value: int
    ) -> None: ...

    # ── Comments ─────────────────────────────────────────────────────────
    @staticmethod
    def comment(addr: int, repeatable: bool = ...) -> str: ...
    @staticmethod
    def set_comment(addr: int, text: str, repeatable: bool = ...) -> None: ...

    # ── Geometry ─────────────────────────────────────────────────────────
    @staticmethod
    def resize(addr: int, new_start: int, new_end: int) -> None: ...
    @staticmethod
    def move(addr: int, new_start: int) -> None: ...

    # ── Traversal ────────────────────────────────────────────────────────
    @staticmethod
    def all() -> list[segment.Segment]: ...
    @staticmethod
    def first() -> segment.Segment: ...
    @staticmethod
    def last() -> segment.Segment: ...
    @staticmethod
    def next(addr: int) -> segment.Segment: ...
    @staticmethod
    def prev(addr: int) -> segment.Segment: ...

# =============================================================================
# function submodule
# =============================================================================

class function:
    # ── Value types ──────────────────────────────────────────────────────
    class Function:
        start: int
        end: int
        size: int
        name: str
        bitness: int
        returns: bool
        is_library: bool
        is_thunk: bool
        is_visible: bool
        def refresh(self) -> None: ...

    class Chunk:
        start: int
        end: int
        is_tail: bool
        owner: int
        size: int

    class FrameVariable:
        name: str
        byte_offset: int
        byte_size: int
        comment: str
        is_special: bool

    class StackFrame:
        local_variables_size: int
        saved_registers_size: int
        arguments_size: int
        total_size: int
        variables: list[function.FrameVariable]

    class RegisterVariable:
        range_start: int
        range_end: int
        canonical_name: str
        user_name: str
        comment: str

    # ── CRUD ─────────────────────────────────────────────────────────────
    @staticmethod
    def create(start: int, end: int = ...) -> function.Function: ...
    @staticmethod
    def remove(addr: int) -> None: ...

    # ── Lookup ───────────────────────────────────────────────────────────
    @staticmethod
    def at(addr: int) -> function.Function: ...
    @staticmethod
    def by_index(index: int) -> function.Function: ...
    @staticmethod
    def count() -> int: ...
    @staticmethod
    def name_at(addr: int) -> str: ...

    # ── Boundary mutation ────────────────────────────────────────────────
    @staticmethod
    def set_start(addr: int, new_start: int) -> None: ...
    @staticmethod
    def set_end(addr: int, new_end: int) -> None: ...
    @staticmethod
    def update(addr: int) -> None: ...
    @staticmethod
    def reanalyze(addr: int) -> None: ...
    @staticmethod
    def is_outlined(addr: int) -> bool: ...
    @staticmethod
    def set_outlined(addr: int, outlined: bool) -> None: ...

    # ── Comments ─────────────────────────────────────────────────────────
    @staticmethod
    def comment(addr: int, repeatable: bool = ...) -> str: ...
    @staticmethod
    def set_comment(addr: int, text: str, repeatable: bool = ...) -> None: ...

    # ── Relationships ────────────────────────────────────────────────────
    @staticmethod
    def callers(addr: int) -> list[int]: ...
    @staticmethod
    def callees(addr: int) -> list[int]: ...

    # ── Chunks ───────────────────────────────────────────────────────────
    @staticmethod
    def chunks(addr: int) -> list[function.Chunk]: ...
    @staticmethod
    def tail_chunks(addr: int) -> list[function.Chunk]: ...
    @staticmethod
    def chunk_count(addr: int) -> int: ...
    @staticmethod
    def add_tail(func_addr: int, tail_start: int, tail_end: int) -> None: ...
    @staticmethod
    def remove_tail(func_addr: int, tail_addr: int) -> None: ...

    # ── Frame operations ─────────────────────────────────────────────────
    @staticmethod
    def frame(addr: int) -> function.StackFrame: ...
    @staticmethod
    def sp_delta_at(addr: int) -> int: ...
    @staticmethod
    def frame_variable_by_name(addr: int, name: str) -> function.FrameVariable: ...
    @staticmethod
    def frame_variable_by_offset(addr: int, offset: int) -> function.FrameVariable: ...
    @staticmethod
    def define_stack_variable(
        func_addr: int, name: str, frame_offset: int, type_name: str
    ) -> None: ...

    # ── Register variables ───────────────────────────────────────────────
    @staticmethod
    def add_register_variable(
        func_addr: int,
        range_start: int,
        range_end: int,
        register_name: str,
        user_name: str,
        comment: str = ...,
    ) -> None: ...
    @staticmethod
    def find_register_variable(
        func_addr: int, addr: int, register_name: str
    ) -> function.RegisterVariable: ...
    @staticmethod
    def remove_register_variable(
        func_addr: int, range_start: int, range_end: int, register_name: str
    ) -> None: ...
    @staticmethod
    def rename_register_variable(
        func_addr: int, addr: int, register_name: str, new_user_name: str
    ) -> None: ...
    @staticmethod
    def has_register_variables(func_addr: int, addr: int) -> bool: ...
    @staticmethod
    def register_variables(addr: int) -> list[function.RegisterVariable]: ...

    # ── Address enumeration ──────────────────────────────────────────────
    @staticmethod
    def item_addresses(addr: int) -> list[int]: ...
    @staticmethod
    def code_addresses(addr: int) -> list[int]: ...

    # ── Traversal ────────────────────────────────────────────────────────
    @staticmethod
    def all() -> list[function.Function]: ...

# =============================================================================
# instruction submodule
# =============================================================================

class instruction:
    # ── Enums ────────────────────────────────────────────────────────────
    class OperandType:
        none: instruction.OperandType
        register_: instruction.OperandType
        memory_direct: instruction.OperandType
        memory_phrase: instruction.OperandType
        memory_displacement: instruction.OperandType
        immediate: instruction.OperandType
        far_address: instruction.OperandType
        near_address: instruction.OperandType
        processor_specific_0: instruction.OperandType
        processor_specific_1: instruction.OperandType
        processor_specific_2: instruction.OperandType
        processor_specific_3: instruction.OperandType
        processor_specific_4: instruction.OperandType
        processor_specific_5: instruction.OperandType

    class RegisterCategory:
        unknown: instruction.RegisterCategory
        general_purpose: instruction.RegisterCategory
        segment: instruction.RegisterCategory
        floating_point: instruction.RegisterCategory
        vector: instruction.RegisterCategory
        mask: instruction.RegisterCategory
        control: instruction.RegisterCategory
        debug: instruction.RegisterCategory
        other: instruction.RegisterCategory

    class OperandFormat:
        default_: instruction.OperandFormat
        hex: instruction.OperandFormat
        decimal: instruction.OperandFormat
        octal: instruction.OperandFormat
        binary: instruction.OperandFormat
        character: instruction.OperandFormat
        float_: instruction.OperandFormat
        offset: instruction.OperandFormat
        stack_variable: instruction.OperandFormat

    # ── Value types ──────────────────────────────────────────────────────
    class Operand:
        index: int
        type: instruction.OperandType
        is_register: bool
        is_immediate: bool
        is_memory: bool
        register_id: int
        value: int
        target_address: int
        displacement: int
        byte_width: int
        register_name: str
        register_category: instruction.RegisterCategory

    class Instruction:
        address: int
        size: int
        opcode: int
        mnemonic: str
        operand_count: int
        operands: list[instruction.Operand]
        def operand(self, index: int) -> instruction.Operand: ...

    class StructOffsetPath:
        structure_ids: list[int]
        delta: int

    # ── Decode / create ──────────────────────────────────────────────────
    @staticmethod
    def decode(address: int) -> instruction.Instruction: ...
    @staticmethod
    def create(address: int) -> instruction.Instruction: ...
    @staticmethod
    def text(address: int) -> str: ...

    # ── Operand format setters ───────────────────────────────────────────
    @staticmethod
    def set_operand_hex(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_operand_decimal(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_operand_octal(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_operand_binary(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_operand_character(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_operand_float(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_operand_format(
        address: int,
        n: int = ...,
        format: instruction.OperandFormat = ...,
        base: int = ...,
    ) -> None: ...
    @staticmethod
    def set_operand_offset(
        address: int, n: int = ..., base: int = ...
    ) -> None: ...

    # ── Struct offset operations ─────────────────────────────────────────
    @staticmethod
    def set_operand_struct_offset(
        address: int, n: int, struct_name_or_id: str | int, delta: int = ...
    ) -> None: ...
    @staticmethod
    def set_operand_based_struct_offset(
        address: int, n: int, operand_value: int, base: int
    ) -> None: ...
    @staticmethod
    def operand_struct_offset_path(
        address: int, n: int = ...
    ) -> instruction.StructOffsetPath: ...
    @staticmethod
    def operand_struct_offset_path_names(
        address: int, n: int = ...
    ) -> list[str]: ...

    # ── Stack variable / clear / forced ──────────────────────────────────
    @staticmethod
    def set_operand_stack_variable(address: int, n: int = ...) -> None: ...
    @staticmethod
    def clear_operand_representation(address: int, n: int = ...) -> None: ...
    @staticmethod
    def set_forced_operand(address: int, n: int, text: str) -> None: ...
    @staticmethod
    def get_forced_operand(address: int, n: int = ...) -> str: ...

    # ── Operand queries ──────────────────────────────────────────────────
    @staticmethod
    def operand_text(address: int, n: int = ...) -> str: ...
    @staticmethod
    def operand_byte_width(address: int, n: int = ...) -> int: ...
    @staticmethod
    def operand_register_name(address: int, n: int = ...) -> str: ...
    @staticmethod
    def operand_register_category(
        address: int, n: int = ...
    ) -> instruction.RegisterCategory: ...

    # ── Operand display toggles ──────────────────────────────────────────
    @staticmethod
    def toggle_operand_sign(address: int, n: int = ...) -> None: ...
    @staticmethod
    def toggle_operand_negate(address: int, n: int = ...) -> None: ...

    # ── Cross-references ─────────────────────────────────────────────────
    @staticmethod
    def code_refs_from(address: int) -> list[int]: ...
    @staticmethod
    def data_refs_from(address: int) -> list[int]: ...
    @staticmethod
    def call_targets(address: int) -> list[int]: ...
    @staticmethod
    def jump_targets(address: int) -> list[int]: ...

    # ── Classification predicates ────────────────────────────────────────
    @staticmethod
    def has_fall_through(address: int) -> bool: ...
    @staticmethod
    def is_call(address: int) -> bool: ...
    @staticmethod
    def is_return(address: int) -> bool: ...
    @staticmethod
    def is_jump(address: int) -> bool: ...
    @staticmethod
    def is_conditional_jump(address: int) -> bool: ...

    # ── Sequential navigation ────────────────────────────────────────────
    @staticmethod
    def next(address: int) -> instruction.Instruction: ...
    @staticmethod
    def prev(address: int) -> instruction.Instruction: ...

# =============================================================================
# data submodule
# =============================================================================

class data:
    # ── Read ─────────────────────────────────────────────────────────────
    @staticmethod
    def read_byte(address: int) -> int: ...
    @staticmethod
    def read_word(address: int) -> int: ...
    @staticmethod
    def read_dword(address: int) -> int: ...
    @staticmethod
    def read_qword(address: int) -> int: ...
    @staticmethod
    def read_bytes(address: int, size: int) -> bytes: ...
    @staticmethod
    def read_string(
        address: int,
        max_length: int = ...,
        string_type: int = ...,
        conversion_flags: int = ...,
    ) -> str: ...

    # ── Write ────────────────────────────────────────────────────────────
    @staticmethod
    def write_byte(address: int, value: int) -> None: ...
    @staticmethod
    def write_word(address: int, value: int) -> None: ...
    @staticmethod
    def write_dword(address: int, value: int) -> None: ...
    @staticmethod
    def write_qword(address: int, value: int) -> None: ...
    @staticmethod
    def write_bytes(address: int, data: bytes) -> None: ...

    # ── Patch ────────────────────────────────────────────────────────────
    @staticmethod
    def patch_byte(address: int, value: int) -> None: ...
    @staticmethod
    def patch_word(address: int, value: int) -> None: ...
    @staticmethod
    def patch_dword(address: int, value: int) -> None: ...
    @staticmethod
    def patch_qword(address: int, value: int) -> None: ...
    @staticmethod
    def patch_bytes(address: int, data: bytes) -> None: ...

    # ── Revert patches ───────────────────────────────────────────────────
    @staticmethod
    def revert_patch(address: int) -> None: ...
    @staticmethod
    def revert_patches(address: int, count: int) -> int: ...

    # ── Original (pre-patch) values ──────────────────────────────────────
    @staticmethod
    def original_byte(address: int) -> int: ...
    @staticmethod
    def original_word(address: int) -> int: ...
    @staticmethod
    def original_dword(address: int) -> int: ...
    @staticmethod
    def original_qword(address: int) -> int: ...

    # ── Define / undefine items ──────────────────────────────────────────
    @staticmethod
    def define_byte(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_word(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_dword(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_qword(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_oword(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_tbyte(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_float(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_double(address: int, count: int = ...) -> None: ...
    @staticmethod
    def define_string(
        address: int, length: int, string_type: int = ...
    ) -> None: ...
    @staticmethod
    def define_struct(
        address: int, length: int, structure_id: int
    ) -> None: ...
    @staticmethod
    def undefine(address: int, count: int = ...) -> None: ...

    # ── Binary pattern search ────────────────────────────────────────────
    @staticmethod
    def find_binary_pattern(
        start: int,
        end: int,
        pattern: str,
        forward: bool = ...,
        skip_start: bool = ...,
        case_sensitive: bool = ...,
        radix: int = ...,
        strlits_encoding: int = ...,
    ) -> int: ...

# =============================================================================
# name submodule
# =============================================================================

class name:
    # ── Enum ─────────────────────────────────────────────────────────────
    class DemangleForm:
        short_: name.DemangleForm
        long_: name.DemangleForm
        full: name.DemangleForm

    # ── Value type ───────────────────────────────────────────────────────
    class Entry:
        address: int
        name: str
        user_defined: bool
        auto_generated: bool

    # ── Core naming ──────────────────────────────────────────────────────
    @staticmethod
    def set(address: int, name: str) -> None: ...
    @staticmethod
    def force_set(address: int, name: str) -> None: ...
    @staticmethod
    def remove(address: int) -> None: ...
    @staticmethod
    def get(address: int) -> str: ...
    @staticmethod
    def demangled(
        address: int, form: name.DemangleForm = ...
    ) -> str: ...
    @staticmethod
    def resolve(name: str, context: int = ...) -> int: ...

    # ── Name inventory ───────────────────────────────────────────────────
    @staticmethod
    def all(
        start: int = ...,
        end: int = ...,
        include_user_defined: bool = ...,
        include_auto_generated: bool = ...,
    ) -> list[name.Entry]: ...
    @staticmethod
    def all_user_defined(
        start: int = ..., end: int = ...
    ) -> list[name.Entry]: ...

    # ── Name property queries ────────────────────────────────────────────
    @staticmethod
    def is_public(address: int) -> bool: ...
    @staticmethod
    def is_weak(address: int) -> bool: ...
    @staticmethod
    def is_user_defined(address: int) -> bool: ...
    @staticmethod
    def is_auto_generated(address: int) -> bool: ...

    # ── Validation / sanitization ────────────────────────────────────────
    @staticmethod
    def is_valid_identifier(text: str) -> bool: ...
    @staticmethod
    def sanitize_identifier(text: str) -> str: ...

    # ── Property setters ─────────────────────────────────────────────────
    @staticmethod
    def set_public(address: int, value: bool = ...) -> None: ...
    @staticmethod
    def set_weak(address: int, value: bool = ...) -> None: ...

# =============================================================================
# xref submodule
# =============================================================================

class xref:
    # ── Enums ────────────────────────────────────────────────────────────
    class CodeType:
        call_far: xref.CodeType
        call_near: xref.CodeType
        jump_far: xref.CodeType
        jump_near: xref.CodeType
        flow: xref.CodeType

    class DataType:
        offset: xref.DataType
        write: xref.DataType
        read: xref.DataType
        text: xref.DataType
        informational: xref.DataType

    class ReferenceType:
        unknown: xref.ReferenceType
        flow: xref.ReferenceType
        call_near: xref.ReferenceType
        call_far: xref.ReferenceType
        jump_near: xref.ReferenceType
        jump_far: xref.ReferenceType
        offset: xref.ReferenceType
        read: xref.ReferenceType
        write: xref.ReferenceType
        text: xref.ReferenceType
        informational: xref.ReferenceType

    # ── Value type ───────────────────────────────────────────────────────
    class Reference:
        from_: int
        to: int
        is_code: bool
        type: xref.ReferenceType
        user_defined: bool

    # ── Mutation ─────────────────────────────────────────────────────────
    @staticmethod
    def add_code(from_: int, to: int, type: xref.CodeType) -> None: ...
    @staticmethod
    def add_data(from_: int, to: int, type: xref.DataType) -> None: ...
    @staticmethod
    def remove_code(from_: int, to: int) -> None: ...
    @staticmethod
    def remove_data(from_: int, to: int) -> None: ...

    # ── Enumeration ──────────────────────────────────────────────────────
    @staticmethod
    def refs_from(
        address: int, type: xref.ReferenceType | None = ...
    ) -> list[xref.Reference]: ...
    @staticmethod
    def refs_to(
        address: int, type: xref.ReferenceType | None = ...
    ) -> list[xref.Reference]: ...
    @staticmethod
    def code_refs_from(address: int) -> list[xref.Reference]: ...
    @staticmethod
    def code_refs_to(address: int) -> list[xref.Reference]: ...
    @staticmethod
    def data_refs_from(address: int) -> list[xref.Reference]: ...
    @staticmethod
    def data_refs_to(address: int) -> list[xref.Reference]: ...

    # ── Classification predicates ────────────────────────────────────────
    @staticmethod
    def is_call(type: xref.ReferenceType) -> bool: ...
    @staticmethod
    def is_jump(type: xref.ReferenceType) -> bool: ...
    @staticmethod
    def is_flow(type: xref.ReferenceType) -> bool: ...
    @staticmethod
    def is_data(type: xref.ReferenceType) -> bool: ...
    @staticmethod
    def is_data_read(type: xref.ReferenceType) -> bool: ...
    @staticmethod
    def is_data_write(type: xref.ReferenceType) -> bool: ...

# =============================================================================
# comment submodule
# =============================================================================

class comment:
    # ── Regular comments ─────────────────────────────────────────────────
    @staticmethod
    def get(addr: int, repeatable: bool = ...) -> str: ...
    @staticmethod
    def set(addr: int, text: str, repeatable: bool = ...) -> None: ...
    @staticmethod
    def append(addr: int, text: str, repeatable: bool = ...) -> None: ...
    @staticmethod
    def remove(addr: int, repeatable: bool = ...) -> None: ...

    # ── Anterior / posterior ─────────────────────────────────────────────
    @staticmethod
    def add_anterior(addr: int, text: str) -> None: ...
    @staticmethod
    def add_posterior(addr: int, text: str) -> None: ...
    @staticmethod
    def get_anterior(addr: int, line_index: int) -> str: ...
    @staticmethod
    def get_posterior(addr: int, line_index: int) -> str: ...
    @staticmethod
    def set_anterior(addr: int, line_index: int, text: str) -> None: ...
    @staticmethod
    def set_posterior(addr: int, line_index: int, text: str) -> None: ...
    @staticmethod
    def remove_anterior_line(addr: int, line_index: int) -> None: ...
    @staticmethod
    def remove_posterior_line(addr: int, line_index: int) -> None: ...

    # ── Bulk operations ──────────────────────────────────────────────────
    @staticmethod
    def set_anterior_lines(addr: int, lines: list[str]) -> None: ...
    @staticmethod
    def set_posterior_lines(addr: int, lines: list[str]) -> None: ...
    @staticmethod
    def clear_anterior(addr: int) -> None: ...
    @staticmethod
    def clear_posterior(addr: int) -> None: ...
    @staticmethod
    def anterior_lines(addr: int) -> list[str]: ...
    @staticmethod
    def posterior_lines(addr: int) -> list[str]: ...

    # ── Rendering ────────────────────────────────────────────────────────
    @staticmethod
    def render(
        addr: int,
        include_repeatable: bool = ...,
        include_extra_lines: bool = ...,
    ) -> str: ...

# =============================================================================
# search submodule
# =============================================================================

class search:
    # ── Enum ─────────────────────────────────────────────────────────────
    class Direction:
        forward: search.Direction
        backward: search.Direction

    # ── Text search ──────────────────────────────────────────────────────
    @staticmethod
    def text(
        addr: int,
        pattern: str,
        *,
        direction: str = ...,
        case_sensitive: bool = ...,
        regex: bool = ...,
        identifier: bool = ...,
        skip_start: bool = ...,
        no_break: bool = ...,
        no_show: bool = ...,
        break_on_cancel: bool = ...,
    ) -> int: ...

    # ── Immediate search ─────────────────────────────────────────────────
    @staticmethod
    def immediate(
        addr: int,
        value: int,
        *,
        direction: str = ...,
        skip_start: bool = ...,
        no_break: bool = ...,
        no_show: bool = ...,
        break_on_cancel: bool = ...,
    ) -> int: ...

    # ── Binary pattern search ────────────────────────────────────────────
    @staticmethod
    def binary_pattern(
        addr: int,
        pattern: str,
        *,
        direction: str = ...,
        skip_start: bool = ...,
        no_break: bool = ...,
        no_show: bool = ...,
        break_on_cancel: bool = ...,
    ) -> int: ...

    # ── Next-type searches ───────────────────────────────────────────────
    @staticmethod
    def next_code(addr: int) -> int: ...
    @staticmethod
    def next_data(addr: int) -> int: ...
    @staticmethod
    def next_unknown(addr: int) -> int: ...
    @staticmethod
    def next_error(addr: int) -> int: ...
    @staticmethod
    def next_defined(addr: int) -> int: ...

# =============================================================================
# analysis submodule
# =============================================================================

class analysis:
    @staticmethod
    def is_enabled() -> bool: ...
    @staticmethod
    def set_enabled(enabled: bool) -> None: ...
    @staticmethod
    def is_idle() -> bool: ...
    @staticmethod
    def wait() -> None: ...
    @staticmethod
    def wait_range(start: int, end: int) -> None: ...
    @staticmethod
    def schedule(addr: int) -> None: ...
    @staticmethod
    def schedule_range(start: int, end: int) -> None: ...
    @staticmethod
    def schedule_code(addr: int) -> None: ...
    @staticmethod
    def schedule_function(addr: int) -> None: ...
    @staticmethod
    def schedule_reanalysis(addr: int) -> None: ...
    @staticmethod
    def schedule_reanalysis_range(start: int, end: int) -> None: ...
    @staticmethod
    def cancel(start: int, end: int) -> None: ...
    @staticmethod
    def revert_decisions(start: int, end: int) -> None: ...

# =============================================================================
# types submodule (named "types" to avoid collision with Python builtin)
# =============================================================================

class types:
    # ── Enum ─────────────────────────────────────────────────────────────
    class CallingConvention:
        unknown: types.CallingConvention
        cdecl_: types.CallingConvention
        stdcall: types.CallingConvention
        pascal_: types.CallingConvention
        fastcall: types.CallingConvention
        thiscall: types.CallingConvention
        swift: types.CallingConvention
        golang: types.CallingConvention
        user_defined: types.CallingConvention

    # ── TypeInfo class ───────────────────────────────────────────────────
    class TypeInfo:
        # Predicates
        def is_void(self) -> bool: ...
        def is_integer(self) -> bool: ...
        def is_floating_point(self) -> bool: ...
        def is_pointer(self) -> bool: ...
        def is_array(self) -> bool: ...
        def is_function(self) -> bool: ...
        def is_struct(self) -> bool: ...
        def is_union(self) -> bool: ...
        def is_enum(self) -> bool: ...
        def is_typedef(self) -> bool: ...
        # Introspection
        def size(self) -> int: ...
        # Navigation
        def pointee_type(self) -> types.TypeInfo: ...
        def array_element_type(self) -> types.TypeInfo: ...
        def array_length(self) -> int: ...
        def resolve_typedef(self) -> types.TypeInfo: ...
        # Function type
        def function_return_type(self) -> types.TypeInfo: ...
        def function_argument_types(self) -> list[types.TypeInfo]: ...
        def calling_convention(self) -> types.CallingConvention: ...
        def is_variadic_function(self) -> bool: ...
        # Enum
        def enum_members(self) -> list[types.EnumMember]: ...
        # Struct / union
        def member_count(self) -> int: ...
        def members(self) -> list[types.Member]: ...
        def member_by_name(self, name: str) -> types.Member: ...
        def member_by_offset(self, offset: int) -> types.Member: ...
        def add_member(
            self, name: str, type: types.TypeInfo, byte_offset: int = ...
        ) -> None: ...
        # Application
        def apply(self, addr: int) -> None: ...
        def save_as(self, name: str) -> None: ...

    class EnumMember:
        name: str
        value: int
        comment: str

    class Member:
        name: str
        type: types.TypeInfo
        byte_offset: int
        bit_size: int
        comment: str

    # ── Primitive type factories ─────────────────────────────────────────
    @staticmethod
    def void_type() -> types.TypeInfo: ...
    @staticmethod
    def int8() -> types.TypeInfo: ...
    @staticmethod
    def int16() -> types.TypeInfo: ...
    @staticmethod
    def int32() -> types.TypeInfo: ...
    @staticmethod
    def int64() -> types.TypeInfo: ...
    @staticmethod
    def uint8() -> types.TypeInfo: ...
    @staticmethod
    def uint16() -> types.TypeInfo: ...
    @staticmethod
    def uint32() -> types.TypeInfo: ...
    @staticmethod
    def uint64() -> types.TypeInfo: ...
    @staticmethod
    def float32() -> types.TypeInfo: ...
    @staticmethod
    def float64() -> types.TypeInfo: ...

    # ── Composite type factories ─────────────────────────────────────────
    @staticmethod
    def pointer_to(target: types.TypeInfo) -> types.TypeInfo: ...
    @staticmethod
    def array_of(element: types.TypeInfo, count: int) -> types.TypeInfo: ...
    @staticmethod
    def function_type(
        return_type: types.TypeInfo,
        arg_types: list[types.TypeInfo] = ...,
        convention: types.CallingConvention = ...,
        variadic: bool = ...,
    ) -> types.TypeInfo: ...
    @staticmethod
    def from_declaration(decl: str) -> types.TypeInfo: ...
    @staticmethod
    def create_struct() -> types.TypeInfo: ...
    @staticmethod
    def create_union() -> types.TypeInfo: ...
    @staticmethod
    def by_name(name: str) -> types.TypeInfo: ...

    # ── Retrieval / removal ──────────────────────────────────────────────
    @staticmethod
    def retrieve(addr: int) -> types.TypeInfo: ...
    @staticmethod
    def retrieve_operand(addr: int, operand_index: int) -> types.TypeInfo: ...
    @staticmethod
    def remove_type(addr: int) -> None: ...

    # ── Type library operations ──────────────────────────────────────────
    @staticmethod
    def load_type_library(name: str) -> bool: ...
    @staticmethod
    def unload_type_library(name: str) -> None: ...
    @staticmethod
    def local_type_count() -> int: ...
    @staticmethod
    def local_type_name(ordinal: int) -> str: ...
    @staticmethod
    def import_type(library: str, name: str) -> int: ...
    @staticmethod
    def ensure_named_type(
        name: str, declaration: str = ...
    ) -> types.TypeInfo: ...
    @staticmethod
    def apply_named_type(addr: int, name: str) -> None: ...

# =============================================================================
# entry submodule
# =============================================================================

class entry:
    class EntryPoint:
        ordinal: int
        address: int
        name: str
        forwarder: str

    @staticmethod
    def count() -> int: ...
    @staticmethod
    def by_index(index: int) -> entry.EntryPoint: ...
    @staticmethod
    def by_ordinal(ordinal: int) -> entry.EntryPoint: ...
    @staticmethod
    def add(
        ordinal: int, addr: int, name: str = ..., make_code: bool = ...
    ) -> None: ...
    @staticmethod
    def rename(ordinal: int, name: str) -> None: ...
    @staticmethod
    def forwarder(ordinal: int) -> str: ...
    @staticmethod
    def set_forwarder(ordinal: int, name: str) -> None: ...
    @staticmethod
    def clear_forwarder(ordinal: int) -> None: ...

# =============================================================================
# fixup submodule
# =============================================================================

class fixup:
    class FixupType:
        off8: fixup.FixupType
        off16: fixup.FixupType
        seg16: fixup.FixupType
        ptr16: fixup.FixupType
        off32: fixup.FixupType
        ptr32: fixup.FixupType
        hi8: fixup.FixupType
        hi16: fixup.FixupType
        low8: fixup.FixupType
        low16: fixup.FixupType
        off64: fixup.FixupType
        off8_signed: fixup.FixupType
        off16_signed: fixup.FixupType
        off32_signed: fixup.FixupType
        custom: fixup.FixupType

    class Descriptor:
        source: int
        type: fixup.FixupType
        flags: int
        base: int
        target: int
        selector: int
        offset: int
        displacement: int
        def __init__(self) -> None: ...

    @staticmethod
    def at(source: int) -> fixup.Descriptor: ...
    @staticmethod
    def set(source: int, descriptor: fixup.Descriptor) -> None: ...
    @staticmethod
    def remove(source: int) -> None: ...
    @staticmethod
    def exists(source: int) -> bool: ...
    @staticmethod
    def contains(start: int, size: int) -> bool: ...
    @staticmethod
    def in_range(start: int, end: int) -> list[fixup.Descriptor]: ...
    @staticmethod
    def first() -> int | None: ...
    @staticmethod
    def next(address: int) -> int | None: ...
    @staticmethod
    def prev(address: int) -> int | None: ...
    @staticmethod
    def all() -> list[int]: ...

# =============================================================================
# event submodule
# =============================================================================

class event:
    @staticmethod
    def on_segment_added(callback: Callable[[int], None]) -> int: ...
    @staticmethod
    def on_segment_deleted(callback: Callable[[int, int], None]) -> int: ...
    @staticmethod
    def on_function_added(callback: Callable[[int], None]) -> int: ...
    @staticmethod
    def on_function_deleted(callback: Callable[[int], None]) -> int: ...
    @staticmethod
    def on_renamed(callback: Callable[[int, str, str], None]) -> int: ...
    @staticmethod
    def on_byte_patched(callback: Callable[[int, int], None]) -> int: ...
    @staticmethod
    def on_comment_changed(callback: Callable[[int, bool], None]) -> int: ...
    @staticmethod
    def on_event(callback: Callable[[dict], None]) -> int: ...
    @staticmethod
    def unsubscribe(token: int) -> None: ...

# =============================================================================
# storage submodule
# =============================================================================

class storage:
    class StorageNode:
        def id(self) -> int: ...
        def name(self) -> str: ...
        # Alt operations
        def alt(self, index: int, tag: str = ...) -> int: ...
        def set_alt(self, index: int, value: int, tag: str = ...) -> None: ...
        def remove_alt(self, index: int, tag: str = ...) -> None: ...
        # Sup operations
        def sup(self, index: int, tag: str = ...) -> bytes: ...
        def set_sup(self, index: int, data: bytes, tag: str = ...) -> None: ...
        # Hash operations
        def hash(self, key: str, tag: str = ...) -> str: ...
        def set_hash(self, key: str, value: str, tag: str = ...) -> None: ...
        # Blob operations
        def blob_size(self, index: int, tag: str = ...) -> int: ...
        def blob(self, index: int, tag: str = ...) -> bytes: ...
        def set_blob(self, index: int, data: bytes, tag: str = ...) -> None: ...
        def remove_blob(self, index: int, tag: str = ...) -> None: ...
        def blob_string(self, index: int, tag: str = ...) -> str: ...

    @staticmethod
    def open(name: str, create: bool = ...) -> storage.StorageNode: ...
    @staticmethod
    def open_by_id(id: int) -> storage.StorageNode: ...

# =============================================================================
# diagnostics submodule
# =============================================================================

class diagnostics:
    class LogLevel:
        trace: diagnostics.LogLevel
        debug: diagnostics.LogLevel
        info: diagnostics.LogLevel
        warning: diagnostics.LogLevel
        error: diagnostics.LogLevel

    @staticmethod
    def set_log_level(level: diagnostics.LogLevel) -> None: ...
    @staticmethod
    def log_level() -> diagnostics.LogLevel: ...
    @staticmethod
    def log(level: diagnostics.LogLevel, domain: str, message: str) -> None: ...
    @staticmethod
    def assert_invariant(condition: bool, message: str) -> None: ...
    @staticmethod
    def reset_performance_counters() -> None: ...
    @staticmethod
    def performance_counters() -> dict[str, int]: ...

# =============================================================================
# lumina submodule
# =============================================================================

class lumina:
    class Feature:
        primary_metadata: lumina.Feature
        decompiler: lumina.Feature
        telemetry: lumina.Feature
        secondary_metadata: lumina.Feature

    class PushMode:
        prefer_better_or_different: lumina.PushMode
        override: lumina.PushMode
        keep_existing: lumina.PushMode
        merge: lumina.PushMode

    class OperationCode:
        bad_pattern: lumina.OperationCode
        not_found: lumina.OperationCode
        error: lumina.OperationCode
        ok: lumina.OperationCode
        added: lumina.OperationCode

    class BatchResult:
        requested: int
        completed: int
        succeeded: int
        failed: int
        codes: list[lumina.OperationCode]

    @staticmethod
    def has_connection(feature: lumina.Feature = ...) -> bool: ...
    @staticmethod
    def close_connection(feature: lumina.Feature = ...) -> None: ...
    @staticmethod
    def close_all_connections() -> None: ...
    @staticmethod
    def pull(
        addresses: int | list[int],
        auto_apply: bool = ...,
        skip_frequency_update: bool = ...,
        feature: lumina.Feature = ...,
    ) -> lumina.BatchResult: ...
    @staticmethod
    def push(
        addresses: int | list[int],
        mode: lumina.PushMode = ...,
        feature: lumina.Feature = ...,
    ) -> lumina.BatchResult: ...

# =============================================================================
# lines submodule
# =============================================================================

class lines:
    class Color:
        DEFAULT: lines.Color
        REGULAR_COMMENT: lines.Color
        REPEATABLE_COMMENT: lines.Color
        AUTO_COMMENT: lines.Color
        INSTRUCTION: lines.Color
        DATA_NAME: lines.Color
        REGULAR_DATA_NAME: lines.Color
        DEMANGLED_NAME: lines.Color
        SYMBOL: lines.Color
        CHAR_LITERAL: lines.Color
        STRING: lines.Color
        NUMBER: lines.Color
        VOID: lines.Color
        CODE_REFERENCE: lines.Color
        DATA_REFERENCE: lines.Color
        CODE_REF_TAIL: lines.Color
        DATA_REF_TAIL: lines.Color
        ERROR: lines.Color
        PREFIX: lines.Color
        BINARY_PREFIX: lines.Color
        EXTRA: lines.Color
        ALT_OPERAND: lines.Color
        HIDDEN_NAME: lines.Color
        LIBRARY_NAME: lines.Color
        LOCAL_NAME: lines.Color
        DUMMY_CODE_NAME: lines.Color
        ASM_DIRECTIVE: lines.Color
        MACRO: lines.Color
        DATA_STRING: lines.Color
        DATA_CHAR: lines.Color
        DATA_NUMBER: lines.Color
        KEYWORD: lines.Color
        REGISTER: lines.Color
        IMPORTED_NAME: lines.Color
        SEGMENT_NAME: lines.Color
        UNKNOWN_NAME: lines.Color
        CODE_NAME: lines.Color
        USER_NAME: lines.Color
        COLLAPSED: lines.Color

    COLOR_ON: int
    COLOR_OFF: int
    COLOR_ESC: int
    COLOR_INV: int
    COLOR_ADDR: int
    COLOR_ADDR_SIZE: int

    @staticmethod
    def colstr(text: str, color: lines.Color) -> str: ...
    @staticmethod
    def tag_remove(tagged_text: str) -> str: ...
    @staticmethod
    def tag_advance(tagged_text: str, pos: int) -> int: ...
    @staticmethod
    def tag_strlen(tagged_text: str) -> int: ...
    @staticmethod
    def make_addr_tag(item_index: int) -> str: ...
    @staticmethod
    def decode_addr_tag(tagged_text: str, pos: int) -> int: ...

# =============================================================================
# decompiler submodule
# =============================================================================

class decompiler:
    class VariableStorage:
        unknown: decompiler.VariableStorage
        register_: decompiler.VariableStorage
        stack: decompiler.VariableStorage

    class DecompiledFunction:
        def pseudocode(self) -> str: ...
        def lines(self) -> list[str]: ...
        def raw_lines(self) -> list[str]: ...
        def declaration(self) -> str: ...
        def variable_count(self) -> int: ...
        def variables(self) -> list[dict]: ...
        def rename_variable(self, old_name: str, new_name: str) -> None: ...
        def retype_variable(
            self, name_or_index: str | int, new_type: str
        ) -> None: ...
        def entry_address(self) -> int: ...
        def line_to_address(self, line: int) -> int: ...
        def address_map(self) -> list[dict]: ...
        def refresh(self) -> None: ...

    @staticmethod
    def available() -> bool: ...
    @staticmethod
    def decompile(address: int) -> decompiler.DecompiledFunction: ...
    @staticmethod
    def register_microcode_filter(
        match_fn: Callable[[dict], bool],
        apply_fn: Callable[[dict], str | int | bool],
    ) -> int: ...
    @staticmethod
    def unregister_microcode_filter(token: int) -> None: ...
    @staticmethod
    def on_maturity_changed(callback: Callable[[dict], None]) -> int: ...
    @staticmethod
    def on_func_printed(callback: Callable[[dict], None]) -> int: ...
    @staticmethod
    def on_refresh_pseudocode(callback: Callable[[dict], None]) -> int: ...
    @staticmethod
    def unsubscribe(token: int) -> None: ...
    @staticmethod
    def mark_dirty(address: int, with_callers: bool = ...) -> None: ...
    @staticmethod
    def mark_dirty_with_callers(address: int) -> None: ...
