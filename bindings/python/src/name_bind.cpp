/// \file name_bind.cpp
/// \brief pybind11 bindings for ida::name — naming, demangling, name inventory,
///        and name property operations.

#include "helpers.hpp"
#include <ida/name.hpp>

namespace nm = ida::name;

void init_name(py::module_& parent) {
    auto m = parent.def_submodule("name",
        "Naming, demangling, name inventory, and property operations.");

    // ── Enums ───────────────────────────────────────────────────────────

    py::enum_<nm::DemangleForm>(m, "DemangleForm")
        .value("short_", nm::DemangleForm::Short)
        .value("long_",  nm::DemangleForm::Long)
        .value("full",   nm::DemangleForm::Full);

    // ── Value types ─────────────────────────────────────────────────────

    py::class_<nm::Entry>(m, "Entry")
        .def_readonly("address",        &nm::Entry::address)
        .def_readonly("name",           &nm::Entry::name)
        .def_readonly("user_defined",   &nm::Entry::user_defined)
        .def_readonly("auto_generated", &nm::Entry::auto_generated)
        .def("__repr__", [](const nm::Entry& e) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "<Entry '%s' at 0x%llx>",
                          e.name.c_str(),
                          static_cast<unsigned long long>(e.address));
            return std::string(buf);
        });

    // ── Core naming ─────────────────────────────────────────────────────

    m.def("set", [](ida::Address addr, const std::string& name) {
        check_status(nm::set(addr, name));
    }, py::arg("address"), py::arg("name"),
       "Set or replace the name at address.");

    m.def("force_set", [](ida::Address addr, const std::string& name) {
        check_status(nm::force_set(addr, name));
    }, py::arg("address"), py::arg("name"),
       "Force-set a name, appending a numeric suffix if taken.");

    m.def("remove", [](ida::Address addr) {
        check_status(nm::remove(addr));
    }, py::arg("address"),
       "Remove the name at address.");

    m.def("get", [](ida::Address addr) {
        return unwrap(nm::get(addr));
    }, py::arg("address"),
       "Get the name at address.");

    m.def("demangled", [](ida::Address addr, nm::DemangleForm form) {
        return unwrap(nm::demangled(addr, form));
    }, py::arg("address"), py::arg("form") = nm::DemangleForm::Short,
       "Get the demangled name at address.");

    m.def("resolve", [](const std::string& name, ida::Address context) {
        return unwrap(nm::resolve(name, context));
    }, py::arg("name"), py::arg("context") = ida::BadAddress,
       "Resolve a name to an address.");

    // ── Name inventory ──────────────────────────────────────────────────

    m.def("all", [](ida::Address start, ida::Address end,
                    bool include_user_defined, bool include_auto_generated) {
        nm::ListOptions opts;
        opts.start = start;
        opts.end = end;
        opts.include_user_defined = include_user_defined;
        opts.include_auto_generated = include_auto_generated;
        return unwrap(nm::all(opts));
    }, py::arg("start") = ida::BadAddress,
       py::arg("end") = ida::BadAddress,
       py::arg("include_user_defined") = true,
       py::arg("include_auto_generated") = true,
       "Enumerate names with filtering options.");

    m.def("all_user_defined", [](ida::Address start, ida::Address end) {
        return unwrap(nm::all_user_defined(start, end));
    }, py::arg("start") = ida::BadAddress,
       py::arg("end") = ida::BadAddress,
       "Enumerate only user-defined names, optionally in [start, end).");

    // ── Name property queries ───────────────────────────────────────────

    m.def("is_public", [](ida::Address addr) {
        return nm::is_public(addr);
    }, py::arg("address"),
       "Check if the name at address is public.");

    m.def("is_weak", [](ida::Address addr) {
        return nm::is_weak(addr);
    }, py::arg("address"),
       "Check if the name at address is weak.");

    m.def("is_user_defined", [](ida::Address addr) {
        return nm::is_user_defined(addr);
    }, py::arg("address"),
       "Check if the name at address is user-defined.");

    m.def("is_auto_generated", [](ida::Address addr) {
        return nm::is_auto_generated(addr);
    }, py::arg("address"),
       "Check if the name at address is auto-generated.");

    // ── Validation / sanitization ───────────────────────────────────────

    m.def("is_valid_identifier", [](const std::string& text) {
        return unwrap(nm::is_valid_identifier(text));
    }, py::arg("text"),
       "Validate an identifier according to IDA naming rules.");

    m.def("sanitize_identifier", [](const std::string& text) {
        return unwrap(nm::sanitize_identifier(text));
    }, py::arg("text"),
       "Normalize an identifier by replacing invalid characters.");

    // ── Property setters ────────────────────────────────────────────────

    m.def("set_public", [](ida::Address addr, bool value) {
        check_status(nm::set_public(addr, value));
    }, py::arg("address"), py::arg("value") = true,
       "Set or clear the public flag on a name.");

    m.def("set_weak", [](ida::Address addr, bool value) {
        check_status(nm::set_weak(addr, value));
    }, py::arg("address"), py::arg("value") = true,
       "Set or clear the weak flag on a name.");
}
