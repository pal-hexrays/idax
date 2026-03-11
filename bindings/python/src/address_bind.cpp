/// \file address_bind.cpp
/// \brief pybind11 bindings for ida::address — navigation, predicates, search, and iteration.

#include "helpers.hpp"
#include <ida/address.hpp>

namespace addr = ida::address;

void init_address(py::module_& parent) {
    auto m = parent.def_submodule("address",
        "Address navigation, predicates, search, and iteration.");

    // ── Enum ────────────────────────────────────────────────────────────

    py::enum_<addr::Predicate>(m, "Predicate")
        .value("mapped",  addr::Predicate::Mapped)
        .value("loaded",  addr::Predicate::Loaded)
        .value("code",    addr::Predicate::Code)
        .value("data",    addr::Predicate::Data)
        .value("unknown", addr::Predicate::Unknown)
        .value("head",    addr::Predicate::Head)
        .value("tail",    addr::Predicate::Tail);

    // ── Navigation ──────────────────────────────────────────────────────

    m.def("item_start", [](ida::Address ea) {
        return unwrap(addr::item_start(ea));
    }, py::arg("ea"),
       "Start address of the item containing ea.");

    m.def("item_end", [](ida::Address ea) {
        return unwrap(addr::item_end(ea));
    }, py::arg("ea"),
       "First address past the end of the item containing ea.");

    m.def("item_size", [](ida::Address ea) {
        return unwrap(addr::item_size(ea));
    }, py::arg("ea"),
       "Size of the item at ea in bytes.");

    m.def("next_head", [](ida::Address ea, ida::Address limit) {
        return unwrap(addr::next_head(ea, limit));
    }, py::arg("ea"),
       py::arg("limit") = ida::BadAddress,
       "Start of the next defined item after ea.");

    m.def("prev_head", [](ida::Address ea, ida::Address limit) {
        return unwrap(addr::prev_head(ea, limit));
    }, py::arg("ea"),
       py::arg("limit") = 0,
       "Start of the previous defined item before ea.");

    m.def("next_defined", [](ida::Address ea, ida::Address limit) {
        return unwrap(addr::next_defined(ea, limit));
    }, py::arg("ea"),
       py::arg("limit") = ida::BadAddress,
       "Next defined item after ea (alias for next_head).");

    m.def("prev_defined", [](ida::Address ea, ida::Address limit) {
        return unwrap(addr::prev_defined(ea, limit));
    }, py::arg("ea"),
       py::arg("limit") = 0,
       "Previous defined item before ea (alias for prev_head).");

    m.def("next_not_tail", [](ida::Address ea) {
        return unwrap(addr::next_not_tail(ea));
    }, py::arg("ea"),
       "Next address that is not a tail byte.");

    m.def("prev_not_tail", [](ida::Address ea) {
        return unwrap(addr::prev_not_tail(ea));
    }, py::arg("ea"),
       "Previous address that is not a tail byte.");

    m.def("next_mapped", [](ida::Address ea) {
        return unwrap(addr::next_mapped(ea));
    }, py::arg("ea"),
       "Next mapped address.");

    m.def("prev_mapped", [](ida::Address ea) {
        return unwrap(addr::prev_mapped(ea));
    }, py::arg("ea"),
       "Previous mapped address.");

    // ── Predicates ──────────────────────────────────────────────────────

    m.def("is_mapped", [](ida::Address ea) {
        return addr::is_mapped(ea);
    }, py::arg("ea"),
       "Whether the address is mapped (has flag bytes).");

    m.def("is_loaded", [](ida::Address ea) {
        return addr::is_loaded(ea);
    }, py::arg("ea"),
       "Whether the address is loaded from the input file.");

    m.def("is_code", [](ida::Address ea) {
        return addr::is_code(ea);
    }, py::arg("ea"),
       "Whether the address is the start of a code item.");

    m.def("is_data", [](ida::Address ea) {
        return addr::is_data(ea);
    }, py::arg("ea"),
       "Whether the address is the start of a data item.");

    m.def("is_unknown", [](ida::Address ea) {
        return addr::is_unknown(ea);
    }, py::arg("ea"),
       "Whether the address is unexplored.");

    m.def("is_head", [](ida::Address ea) {
        return addr::is_head(ea);
    }, py::arg("ea"),
       "Whether the address is a head byte (start of an item).");

    m.def("is_tail", [](ida::Address ea) {
        return addr::is_tail(ea);
    }, py::arg("ea"),
       "Whether the address is a tail byte.");

    // ── Search ──────────────────────────────────────────────────────────

    m.def("find_first", [](ida::Address start, ida::Address end, addr::Predicate predicate) {
        return unwrap(addr::find_first(start, end, predicate));
    }, py::arg("start"),
       py::arg("end"),
       py::arg("predicate"),
       "Find first address in [start, end) matching predicate.");

    m.def("find_next", [](ida::Address ea, addr::Predicate predicate, ida::Address end) {
        return unwrap(addr::find_next(ea, predicate, end));
    }, py::arg("ea"),
       py::arg("predicate"),
       py::arg("end") = ida::BadAddress,
       "Find next address after ea matching predicate.");

    // ── Iteration ───────────────────────────────────────────────────────

    m.def("items", [](ida::Address start, ida::Address end) {
        std::vector<ida::Address> result;
        for (auto ea : addr::items(start, end)) {
            result.push_back(ea);
        }
        return result;
    }, py::arg("start"),
       py::arg("end"),
       "List of all item head addresses in [start, end).");

    m.def("code_items", [](ida::Address start, ida::Address end) {
        std::vector<ida::Address> result;
        for (auto ea : addr::code_items(start, end)) {
            result.push_back(ea);
        }
        return result;
    }, py::arg("start"),
       py::arg("end"),
       "List of code item addresses in [start, end).");

    m.def("data_items", [](ida::Address start, ida::Address end) {
        std::vector<ida::Address> result;
        for (auto ea : addr::data_items(start, end)) {
            result.push_back(ea);
        }
        return result;
    }, py::arg("start"),
       py::arg("end"),
       "List of data item addresses in [start, end).");

    m.def("unknown_bytes", [](ida::Address start, ida::Address end) {
        std::vector<ida::Address> result;
        for (auto ea : addr::unknown_bytes(start, end)) {
            result.push_back(ea);
        }
        return result;
    }, py::arg("start"),
       py::arg("end"),
       "List of unknown byte addresses in [start, end).");
}
