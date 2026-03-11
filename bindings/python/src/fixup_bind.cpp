/// \file fixup_bind.cpp
/// \brief pybind11 bindings for ida::fixup — relocation / fixup information.

#include "helpers.hpp"
#include <ida/fixup.hpp>

namespace fx = ida::fixup;

void init_fixup(py::module_& parent) {
    auto m = parent.def_submodule("fixup",
        "Relocation / fixup information.");

    // ── Enum ──────────────────────────────────────────────────────────────

    py::enum_<fx::Type>(m, "FixupType")
        .value("off8",         fx::Type::Off8)
        .value("off16",        fx::Type::Off16)
        .value("seg16",        fx::Type::Seg16)
        .value("ptr16",        fx::Type::Ptr16)
        .value("off32",        fx::Type::Off32)
        .value("ptr32",        fx::Type::Ptr32)
        .value("hi8",          fx::Type::Hi8)
        .value("hi16",         fx::Type::Hi16)
        .value("low8",         fx::Type::Low8)
        .value("low16",        fx::Type::Low16)
        .value("off64",        fx::Type::Off64)
        .value("off8_signed",  fx::Type::Off8Signed)
        .value("off16_signed", fx::Type::Off16Signed)
        .value("off32_signed", fx::Type::Off32Signed)
        .value("custom",       fx::Type::Custom);

    // ── Value type ────────────────────────────────────────────────────────

    py::class_<fx::Descriptor>(m, "Descriptor")
        .def(py::init<>())
        .def_readwrite("source",       &fx::Descriptor::source)
        .def_readwrite("type",         &fx::Descriptor::type)
        .def_readwrite("flags",        &fx::Descriptor::flags)
        .def_readwrite("base",         &fx::Descriptor::base)
        .def_readwrite("target",       &fx::Descriptor::target)
        .def_readwrite("selector",     &fx::Descriptor::selector)
        .def_readwrite("offset",       &fx::Descriptor::offset)
        .def_readwrite("displacement", &fx::Descriptor::displacement)
        .def("__repr__", [](const fx::Descriptor& d) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "<Descriptor source=0x%llx target=0x%llx>",
                          static_cast<unsigned long long>(d.source),
                          static_cast<unsigned long long>(d.target));
            return std::string(buf);
        });

    // ── Functions ─────────────────────────────────────────────────────────

    m.def("at", [](ida::Address source) {
        return unwrap(fx::at(source));
    }, py::arg("source"),
       "Get the fixup descriptor at the given address.");

    m.def("set", [](ida::Address source, const fx::Descriptor& desc) {
        fx::Descriptor d = desc;
        d.source = source;
        check_status(fx::set(source, d));
    }, py::arg("source"), py::arg("descriptor"),
       "Set a fixup at the given address.");

    m.def("remove", [](ida::Address source) {
        check_status(fx::remove(source));
    }, py::arg("source"),
       "Remove the fixup at the given address.");

    m.def("exists", [](ida::Address source) {
        return fx::exists(source);
    }, py::arg("source"),
       "Check whether a fixup exists at the given address.");

    m.def("contains", [](ida::Address start, ida::AddressSize size) {
        return fx::contains(start, size);
    }, py::arg("start"), py::arg("size"),
       "Check whether an address range contains any fixups.");

    m.def("in_range", [](ida::Address start, ida::Address end) {
        return unwrap(fx::in_range(start, end));
    }, py::arg("start"), py::arg("end"),
       "Collect fixup descriptors in [start, end).");

    m.def("first", []() -> std::optional<ida::Address> {
        auto result = fx::first();
        if (!result) {
            if (result.error().category == ida::ErrorCategory::NotFound)
                return std::nullopt;
            throw_idax_error(result.error());
        }
        return *result;
    }, "Get the first fixup address, or None if no fixups exist.");

    m.def("next", [](ida::Address address) -> std::optional<ida::Address> {
        auto result = fx::next(address);
        if (!result) {
            if (result.error().category == ida::ErrorCategory::NotFound)
                return std::nullopt;
            throw_idax_error(result.error());
        }
        return *result;
    }, py::arg("address"),
       "Get the next fixup address after the given address, or None.");

    m.def("prev", [](ida::Address address) -> std::optional<ida::Address> {
        auto result = fx::prev(address);
        if (!result) {
            if (result.error().category == ida::ErrorCategory::NotFound)
                return std::nullopt;
            throw_idax_error(result.error());
        }
        return *result;
    }, py::arg("address"),
       "Get the previous fixup address before the given address, or None.");

    m.def("all", []() {
        auto range = fx::all();
        std::vector<ida::Address> addresses;
        for (auto it = range.begin(); it != range.end(); ++it) {
            addresses.push_back((*it).source);
        }
        return addresses;
    }, "Get all fixup source addresses.");
}
