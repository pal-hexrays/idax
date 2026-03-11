/// \file xref_bind.cpp
/// \brief pybind11 bindings for ida::xref — cross-reference enumeration
///        and mutation.

#include "helpers.hpp"
#include <ida/xref.hpp>

namespace xr = ida::xref;

void init_xref(py::module_& parent) {
    auto m = parent.def_submodule("xref",
        "Cross-reference enumeration and mutation.");

    // ── Enums ───────────────────────────────────────────────────────────

    py::enum_<xr::CodeType>(m, "CodeType")
        .value("call_far",  xr::CodeType::CallFar)
        .value("call_near", xr::CodeType::CallNear)
        .value("jump_far",  xr::CodeType::JumpFar)
        .value("jump_near", xr::CodeType::JumpNear)
        .value("flow",      xr::CodeType::Flow);

    py::enum_<xr::DataType>(m, "DataType")
        .value("offset",        xr::DataType::Offset)
        .value("write",         xr::DataType::Write)
        .value("read",          xr::DataType::Read)
        .value("text",          xr::DataType::Text)
        .value("informational", xr::DataType::Informational);

    py::enum_<xr::ReferenceType>(m, "ReferenceType")
        .value("unknown",       xr::ReferenceType::Unknown)
        .value("flow",          xr::ReferenceType::Flow)
        .value("call_near",     xr::ReferenceType::CallNear)
        .value("call_far",      xr::ReferenceType::CallFar)
        .value("jump_near",     xr::ReferenceType::JumpNear)
        .value("jump_far",      xr::ReferenceType::JumpFar)
        .value("offset",        xr::ReferenceType::Offset)
        .value("read",          xr::ReferenceType::Read)
        .value("write",         xr::ReferenceType::Write)
        .value("text",          xr::ReferenceType::Text)
        .value("informational", xr::ReferenceType::Informational);

    // ── Value types ─────────────────────────────────────────────────────

    py::class_<xr::Reference>(m, "Reference")
        .def_readonly("from_",        &xr::Reference::from)
        .def_readonly("to",           &xr::Reference::to)
        .def_readonly("is_code",      &xr::Reference::is_code)
        .def_readonly("type",         &xr::Reference::type)
        .def_readonly("user_defined", &xr::Reference::user_defined)
        .def("__repr__", [](const xr::Reference& r) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "<Reference 0x%llx -> 0x%llx%s>",
                          static_cast<unsigned long long>(r.from),
                          static_cast<unsigned long long>(r.to),
                          r.is_code ? " code" : " data");
            return std::string(buf);
        });

    // ── Mutation ────────────────────────────────────────────────────────

    m.def("add_code", [](ida::Address from, ida::Address to, xr::CodeType type) {
        check_status(xr::add_code(from, to, type));
    }, py::arg("from_"), py::arg("to"), py::arg("type"),
       "Add a code cross-reference.");

    m.def("add_data", [](ida::Address from, ida::Address to, xr::DataType type) {
        check_status(xr::add_data(from, to, type));
    }, py::arg("from_"), py::arg("to"), py::arg("type"),
       "Add a data cross-reference.");

    m.def("remove_code", [](ida::Address from, ida::Address to) {
        check_status(xr::remove_code(from, to));
    }, py::arg("from_"), py::arg("to"),
       "Remove a code cross-reference.");

    m.def("remove_data", [](ida::Address from, ida::Address to) {
        check_status(xr::remove_data(from, to));
    }, py::arg("from_"), py::arg("to"),
       "Remove a data cross-reference.");

    // ── Enumeration ─────────────────────────────────────────────────────

    m.def("refs_from",
        [](ida::Address addr, std::optional<xr::ReferenceType> type) {
            if (type) {
                return unwrap(xr::refs_from(addr, *type));
            }
            return unwrap(xr::refs_from(addr));
        },
        py::arg("address"), py::arg("type") = py::none(),
        "All references originating from address, optionally filtered by type.");

    m.def("refs_to",
        [](ida::Address addr, std::optional<xr::ReferenceType> type) {
            if (type) {
                return unwrap(xr::refs_to(addr, *type));
            }
            return unwrap(xr::refs_to(addr));
        },
        py::arg("address"), py::arg("type") = py::none(),
        "All references targeting address, optionally filtered by type.");

    m.def("code_refs_from", [](ida::Address addr) {
        return unwrap(xr::code_refs_from(addr));
    }, py::arg("address"),
       "Only code references from address.");

    m.def("code_refs_to", [](ida::Address addr) {
        return unwrap(xr::code_refs_to(addr));
    }, py::arg("address"),
       "Only code references to address.");

    m.def("data_refs_from", [](ida::Address addr) {
        return unwrap(xr::data_refs_from(addr));
    }, py::arg("address"),
       "Only data references from address.");

    m.def("data_refs_to", [](ida::Address addr) {
        return unwrap(xr::data_refs_to(addr));
    }, py::arg("address"),
       "Only data references to address.");

    // ── Classification predicates ───────────────────────────────────────

    m.def("is_call", [](xr::ReferenceType type) {
        return xr::is_call(type);
    }, py::arg("type"),
       "Is the reference type a call?");

    m.def("is_jump", [](xr::ReferenceType type) {
        return xr::is_jump(type);
    }, py::arg("type"),
       "Is the reference type a jump?");

    m.def("is_flow", [](xr::ReferenceType type) {
        return xr::is_flow(type);
    }, py::arg("type"),
       "Is the reference type a flow?");

    m.def("is_data", [](xr::ReferenceType type) {
        return xr::is_data(type);
    }, py::arg("type"),
       "Is the reference type a data reference?");

    m.def("is_data_read", [](xr::ReferenceType type) {
        return xr::is_data_read(type);
    }, py::arg("type"),
       "Is the reference type a data read?");

    m.def("is_data_write", [](xr::ReferenceType type) {
        return xr::is_data_write(type);
    }, py::arg("type"),
       "Is the reference type a data write?");
}
