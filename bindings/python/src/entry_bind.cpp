/// \file entry_bind.cpp
/// \brief pybind11 bindings for ida::entry — program entry points (exports).

#include "helpers.hpp"
#include <ida/entry.hpp>

namespace en = ida::entry;

void init_entry(py::module_& parent) {
    auto m = parent.def_submodule("entry",
        "Program entry points (exports).");

    // ── Value type ─────────────────────────────────────────────────────

    py::class_<en::EntryPoint>(m, "EntryPoint")
        .def_readonly("ordinal",   &en::EntryPoint::ordinal)
        .def_readonly("address",   &en::EntryPoint::address)
        .def_readonly("name",      &en::EntryPoint::name)
        .def_readonly("forwarder", &en::EntryPoint::forwarder)
        .def("__repr__", [](const en::EntryPoint& ep) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "<EntryPoint '%s' ordinal=%llu at 0x%llx>",
                          ep.name.c_str(),
                          static_cast<unsigned long long>(ep.ordinal),
                          static_cast<unsigned long long>(ep.address));
            return std::string(buf);
        });

    // ── Functions ──────────────────────────────────────────────────────

    m.def("count", []() {
        return unwrap(en::count());
    }, "Get the number of entry points.");

    m.def("by_index", [](std::size_t index) {
        return unwrap(en::by_index(index));
    }, py::arg("index"),
       "Get entry point by index.");

    m.def("by_ordinal", [](std::uint64_t ordinal) {
        return unwrap(en::by_ordinal(ordinal));
    }, py::arg("ordinal"),
       "Get entry point by ordinal.");

    m.def("add", [](std::uint64_t ordinal, ida::Address addr,
                     const std::string& name, bool make_code) {
        check_status(en::add(ordinal, addr, name, make_code));
    }, py::arg("ordinal"), py::arg("addr"),
       py::arg("name") = "", py::arg("make_code") = true,
       "Add a new entry point.");

    m.def("rename", [](std::uint64_t ordinal, const std::string& name) {
        check_status(en::rename(ordinal, name));
    }, py::arg("ordinal"), py::arg("name"),
       "Rename an entry point.");

    m.def("forwarder", [](std::uint64_t ordinal) {
        return unwrap(en::forwarder(ordinal));
    }, py::arg("ordinal"),
       "Get entry forwarder text by ordinal.");

    m.def("set_forwarder", [](std::uint64_t ordinal, const std::string& name) {
        check_status(en::set_forwarder(ordinal, name));
    }, py::arg("ordinal"), py::arg("name"),
       "Set entry forwarder text by ordinal.");

    m.def("clear_forwarder", [](std::uint64_t ordinal) {
        check_status(en::clear_forwarder(ordinal));
    }, py::arg("ordinal"),
       "Clear entry forwarder text for ordinal.");
}
