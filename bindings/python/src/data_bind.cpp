/// \file data_bind.cpp
/// \brief pybind11 bindings for ida::data — byte-level read, write, patch,
///        define, and binary pattern search.

#include "helpers.hpp"
#include <ida/data.hpp>

namespace data = ida::data;

void init_data(py::module_& parent) {
    auto m = parent.def_submodule("data",
        "Byte-level read, write, patch, define, and search operations.");

    // ── Read family ─────────────────────────────────────────────────────

    m.def("read_byte", [](ida::Address addr) {
        return unwrap(data::read_byte(addr));
    }, py::arg("address"),
       "Read a single byte.");

    m.def("read_word", [](ida::Address addr) {
        return unwrap(data::read_word(addr));
    }, py::arg("address"),
       "Read a 16-bit word.");

    m.def("read_dword", [](ida::Address addr) {
        return unwrap(data::read_dword(addr));
    }, py::arg("address"),
       "Read a 32-bit dword.");

    m.def("read_qword", [](ida::Address addr) {
        return unwrap(data::read_qword(addr));
    }, py::arg("address"),
       "Read a 64-bit qword.");

    m.def("read_bytes", [](ida::Address addr, ida::AddressSize size) {
        auto bytes = unwrap(data::read_bytes(addr, size));
        return py::bytes(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }, py::arg("address"), py::arg("size"),
       "Read raw bytes as a bytes object.");

    m.def("read_string", [](ida::Address addr, ida::AddressSize max_length,
                            std::int32_t string_type, int conversion_flags) {
        return unwrap(data::read_string(addr, max_length, string_type,
                                        conversion_flags));
    }, py::arg("address"),
       py::arg("max_length") = 0,
       py::arg("string_type") = 0,
       py::arg("conversion_flags") = 0,
       "Read a string literal as UTF-8 text.");

    // ── Write family ────────────────────────────────────────────────────

    m.def("write_byte", [](ida::Address addr, std::uint8_t value) {
        check_status(data::write_byte(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Write a single byte.");

    m.def("write_word", [](ida::Address addr, std::uint16_t value) {
        check_status(data::write_word(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Write a 16-bit word.");

    m.def("write_dword", [](ida::Address addr, std::uint32_t value) {
        check_status(data::write_dword(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Write a 32-bit dword.");

    m.def("write_qword", [](ida::Address addr, std::uint64_t value) {
        check_status(data::write_qword(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Write a 64-bit qword.");

    m.def("write_bytes", [](ida::Address addr, py::bytes data_bytes) {
        std::string buf = data_bytes;
        auto* ptr = reinterpret_cast<const std::uint8_t*>(buf.data());
        check_status(data::write_bytes(addr,
            std::span<const std::uint8_t>(ptr, buf.size())));
    }, py::arg("address"), py::arg("data"),
       "Write raw bytes from a bytes object.");

    // ── Patch family ────────────────────────────────────────────────────

    m.def("patch_byte", [](ida::Address addr, std::uint8_t value) {
        check_status(data::patch_byte(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Patch a single byte (original value preserved).");

    m.def("patch_word", [](ida::Address addr, std::uint16_t value) {
        check_status(data::patch_word(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Patch a 16-bit word (original value preserved).");

    m.def("patch_dword", [](ida::Address addr, std::uint32_t value) {
        check_status(data::patch_dword(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Patch a 32-bit dword (original value preserved).");

    m.def("patch_qword", [](ida::Address addr, std::uint64_t value) {
        check_status(data::patch_qword(addr, value));
    }, py::arg("address"), py::arg("value"),
       "Patch a 64-bit qword (original value preserved).");

    m.def("patch_bytes", [](ida::Address addr, py::bytes data_bytes) {
        std::string buf = data_bytes;
        auto* ptr = reinterpret_cast<const std::uint8_t*>(buf.data());
        check_status(data::patch_bytes(addr,
            std::span<const std::uint8_t>(ptr, buf.size())));
    }, py::arg("address"), py::arg("data"),
       "Patch raw bytes from a bytes object (originals preserved).");

    // ── Revert patches ──────────────────────────────────────────────────

    m.def("revert_patch", [](ida::Address addr) {
        check_status(data::revert_patch(addr));
    }, py::arg("address"),
       "Revert a patched byte back to its original value.");

    m.def("revert_patches", [](ida::Address addr, ida::AddressSize count) {
        return unwrap(data::revert_patches(addr, count));
    }, py::arg("address"), py::arg("count"),
       "Revert patched bytes in [address, address + count). Returns count reverted.");

    // ── Original (pre-patch) values ─────────────────────────────────────

    m.def("original_byte", [](ida::Address addr) {
        return unwrap(data::original_byte(addr));
    }, py::arg("address"),
       "Read the original (pre-patch) byte value.");

    m.def("original_word", [](ida::Address addr) {
        return unwrap(data::original_word(addr));
    }, py::arg("address"),
       "Read the original (pre-patch) word value.");

    m.def("original_dword", [](ida::Address addr) {
        return unwrap(data::original_dword(addr));
    }, py::arg("address"),
       "Read the original (pre-patch) dword value.");

    m.def("original_qword", [](ida::Address addr) {
        return unwrap(data::original_qword(addr));
    }, py::arg("address"),
       "Read the original (pre-patch) qword value.");

    // ── Define / undefine items ─────────────────────────────────────────

    m.def("define_byte", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_byte(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a byte item.");

    m.def("define_word", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_word(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a word item.");

    m.def("define_dword", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_dword(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a dword item.");

    m.def("define_qword", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_qword(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a qword item.");

    m.def("define_oword", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_oword(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define an oword (16-byte) item.");

    m.def("define_tbyte", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_tbyte(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a tbyte (10-byte) item.");

    m.def("define_float", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_float(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a float item.");

    m.def("define_double", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::define_double(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Define a double item.");

    m.def("define_string", [](ida::Address addr, ida::AddressSize length,
                              std::int32_t string_type) {
        check_status(data::define_string(addr, length, string_type));
    }, py::arg("address"), py::arg("length"), py::arg("string_type") = 0,
       "Define a string item.");

    m.def("define_struct", [](ida::Address addr, ida::AddressSize length,
                              std::uint64_t structure_id) {
        check_status(data::define_struct(addr, length, structure_id));
    }, py::arg("address"), py::arg("length"), py::arg("structure_id"),
       "Define a struct item.");

    m.def("undefine", [](ida::Address addr, ida::AddressSize count) {
        check_status(data::undefine(addr, count));
    }, py::arg("address"), py::arg("count") = 1,
       "Undefine (delete) items at address.");

    // ── Binary pattern search ───────────────────────────────────────────

    m.def("find_binary_pattern",
        [](ida::Address start, ida::Address end, const std::string& pattern,
           bool forward, bool skip_start, bool case_sensitive,
           int radix, int strlits_encoding) {
            return unwrap(data::find_binary_pattern(
                start, end, pattern, forward, skip_start, case_sensitive,
                radix, strlits_encoding));
        },
        py::arg("start"), py::arg("end"), py::arg("pattern"),
        py::arg("forward") = true,
        py::arg("skip_start") = false,
        py::arg("case_sensitive") = true,
        py::arg("radix") = 16,
        py::arg("strlits_encoding") = 0,
        "Search for an IDA binary pattern string (e.g. '55 48 89 E5').");
}
