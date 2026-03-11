/// \file segment_bind.cpp
/// \brief pybind11 bindings for ida::segment — creation, query, traversal, properties.

#include "helpers.hpp"
#include <ida/segment.hpp>

namespace seg = ida::segment;

// ── Segment Python wrapper ──────────────────────────────────────────────

/// Thin wrapper so we can expose Segment as a py::class_ with properties.
struct PySegment {
    ida::Address     start;
    ida::Address     end;
    ida::AddressSize size;
    int              bitness;
    seg::Type        type;
    seg::Permissions permissions;
    std::string      name;
    std::string      class_name;
    bool             is_visible;

    explicit PySegment(const seg::Segment& s)
        : start(s.start())
        , end(s.end())
        , size(s.size())
        , bitness(s.bitness())
        , type(s.type())
        , permissions(s.permissions())
        , name(s.name())
        , class_name(s.class_name())
        , is_visible(s.is_visible()) {}
};

void init_segment(py::module_& parent) {
    auto m = parent.def_submodule("segment",
        "Segment operations: creation, query, traversal, properties.");

    // ── Enums ───────────────────────────────────────────────────────────

    py::enum_<seg::Type>(m, "Type")
        .value("normal",           seg::Type::Normal)
        .value("external",         seg::Type::External)
        .value("code",             seg::Type::Code)
        .value("data",             seg::Type::Data)
        .value("bss",              seg::Type::Bss)
        .value("absolute_symbols", seg::Type::AbsoluteSymbols)
        .value("common",           seg::Type::Common)
        .value("null_",            seg::Type::Null)
        .value("undefined",        seg::Type::Undefined)
        .value("import_",          seg::Type::Import)
        .value("internal_memory",  seg::Type::InternalMemory)
        .value("group",            seg::Type::Group);

    // ── Value types ─────────────────────────────────────────────────────

    py::class_<seg::Permissions>(m, "Permissions")
        .def_readonly("read",    &seg::Permissions::read)
        .def_readonly("write",   &seg::Permissions::write)
        .def_readonly("execute", &seg::Permissions::execute)
        .def("__repr__", [](const seg::Permissions& p) {
            std::string s = "Permissions(";
            if (p.read)    s += "r";
            if (p.write)   s += "w";
            if (p.execute) s += "x";
            s += ")";
            return s;
        });

    py::class_<PySegment>(m, "Segment")
        .def_readonly("start",       &PySegment::start)
        .def_readonly("end",         &PySegment::end)
        .def_readonly("size",        &PySegment::size)
        .def_readonly("bitness",     &PySegment::bitness)
        .def_readonly("type",        &PySegment::type)
        .def_readonly("permissions", &PySegment::permissions)
        .def_readonly("name",        &PySegment::name)
        .def_readonly("class_name",  &PySegment::class_name)
        .def_readonly("is_visible",  &PySegment::is_visible)
        .def("__repr__", [](const PySegment& s) {
            return "<Segment '" + s.name + "' "
                   "0x" + py::cast(s.start).attr("__format__")("x").cast<std::string>() +
                   "-0x" + py::cast(s.end).attr("__format__")("x").cast<std::string>() +
                   ">";
        });

    // ── Helper lambda to convert Segment → PySegment ────────────────────
    auto to_py = [](const seg::Segment& s) { return PySegment(s); };

    // ── CRUD ────────────────────────────────────────────────────────────

    m.def("create", [to_py](ida::Address start, ida::Address end,
                            const std::string& name,
                            const std::string& class_name,
                            seg::Type type) {
        return to_py(unwrap(seg::create(start, end, name, class_name, type)));
    }, py::arg("start"),
       py::arg("end"),
       py::arg("name"),
       py::arg("class_name") = "",
       py::arg("type") = seg::Type::Normal,
       "Create a new segment [start, end).");

    m.def("remove", [](ida::Address addr) {
        check_status(seg::remove(addr));
    }, py::arg("addr"),
       "Remove the segment containing addr.");

    // ── Lookup ──────────────────────────────────────────────────────────

    m.def("at", [to_py](ida::Address addr) {
        return to_py(unwrap(seg::at(addr)));
    }, py::arg("addr"),
       "Segment containing the given address.");

    m.def("by_name", [to_py](const std::string& name) {
        return to_py(unwrap(seg::by_name(name)));
    }, py::arg("name"),
       "Segment with the given name.");

    m.def("by_index", [to_py](std::size_t idx) {
        return to_py(unwrap(seg::by_index(idx)));
    }, py::arg("idx"),
       "Segment by its positional index (0-based).");

    m.def("count", []() {
        return unwrap(seg::count());
    }, "Total number of segments.");

    // ── Property mutation ───────────────────────────────────────────────

    m.def("set_name", [](ida::Address addr, const std::string& name) {
        check_status(seg::set_name(addr, name));
    }, py::arg("addr"),
       py::arg("name"),
       "Set the name of the segment containing addr.");

    m.def("set_class", [](ida::Address addr, const std::string& class_name) {
        check_status(seg::set_class(addr, class_name));
    }, py::arg("addr"),
       py::arg("class_name"),
       "Set the class of the segment containing addr.");

    m.def("set_type", [](ida::Address addr, seg::Type type) {
        check_status(seg::set_type(addr, type));
    }, py::arg("addr"),
       py::arg("type"),
       "Set the type of the segment containing addr.");

    m.def("set_permissions", [](ida::Address addr, bool read, bool write, bool execute) {
        seg::Permissions perm{read, write, execute};
        check_status(seg::set_permissions(addr, perm));
    }, py::arg("addr"),
       py::arg("read"),
       py::arg("write"),
       py::arg("execute"),
       "Set permissions of the segment containing addr.");

    m.def("set_bitness", [](ida::Address addr, int bits) {
        check_status(seg::set_bitness(addr, bits));
    }, py::arg("addr"),
       py::arg("bits"),
       "Set the bitness of the segment containing addr.");

    m.def("set_default_segment_register", [](ida::Address addr, int reg_index, std::uint64_t value) {
        check_status(seg::set_default_segment_register(addr, reg_index, value));
    }, py::arg("addr"),
       py::arg("reg_index"),
       py::arg("value"),
       "Set default segment register value for the segment containing addr.");

    m.def("set_default_segment_register_for_all", [](int reg_index, std::uint64_t value) {
        check_status(seg::set_default_segment_register_for_all(reg_index, value));
    }, py::arg("reg_index"),
       py::arg("value"),
       "Set default segment register value for all segments.");

    // ── Comments ────────────────────────────────────────────────────────

    m.def("comment", [](ida::Address addr, bool repeatable) {
        return unwrap(seg::comment(addr, repeatable));
    }, py::arg("addr"),
       py::arg("repeatable") = false,
       "Get the comment for the segment containing addr.");

    m.def("set_comment", [](ida::Address addr, const std::string& text, bool repeatable) {
        check_status(seg::set_comment(addr, text, repeatable));
    }, py::arg("addr"),
       py::arg("text"),
       py::arg("repeatable") = false,
       "Set the comment for the segment containing addr.");

    // ── Geometry ────────────────────────────────────────────────────────

    m.def("resize", [](ida::Address addr, ida::Address new_start, ida::Address new_end) {
        check_status(seg::resize(addr, new_start, new_end));
    }, py::arg("addr"),
       py::arg("new_start"),
       py::arg("new_end"),
       "Resize the segment containing addr to [new_start, new_end).");

    m.def("move", [](ida::Address addr, ida::Address new_start) {
        check_status(seg::move(addr, new_start));
    }, py::arg("addr"),
       py::arg("new_start"),
       "Move the segment containing addr to start at new_start.");

    // ── Traversal ───────────────────────────────────────────────────────

    m.def("all", [to_py]() {
        std::vector<PySegment> result;
        for (auto s : seg::all()) {
            result.push_back(to_py(s));
        }
        return result;
    }, "List of all segments.");

    m.def("first", [to_py]() {
        return to_py(unwrap(seg::first()));
    }, "First segment in database order.");

    m.def("last", [to_py]() {
        return to_py(unwrap(seg::last()));
    }, "Last segment in database order.");

    m.def("next", [to_py](ida::Address addr) {
        return to_py(unwrap(seg::next(addr)));
    }, py::arg("addr"),
       "Segment immediately after the one containing addr.");

    m.def("prev", [to_py](ida::Address addr) {
        return to_py(unwrap(seg::prev(addr)));
    }, py::arg("addr"),
       "Segment immediately before the one containing addr.");
}
