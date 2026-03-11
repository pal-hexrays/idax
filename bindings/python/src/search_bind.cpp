/// \file search_bind.cpp
/// \brief pybind11 bindings for ida::search — text, binary, and immediate searches.

#include "helpers.hpp"
#include <ida/search.hpp>

namespace sr = ida::search;

void init_search(py::module_& parent) {
    auto m = parent.def_submodule("search",
        "Text, binary, and immediate value searches.");

    // ── Enums ──────────────────────────────────────────────────────────

    py::enum_<sr::Direction>(m, "Direction")
        .value("forward",  sr::Direction::Forward)
        .value("backward", sr::Direction::Backward);

    // ── Text search ────────────────────────────────────────────────────

    m.def("text",
        [](ida::Address addr, const std::string& pattern,
           const std::string& direction, bool case_sensitive,
           bool regex, bool identifier, bool skip_start,
           bool no_break, bool no_show, bool break_on_cancel) {
            sr::TextOptions opts;
            opts.direction = (direction == "backward")
                ? sr::Direction::Backward : sr::Direction::Forward;
            opts.case_sensitive = case_sensitive;
            opts.regex = regex;
            opts.identifier = identifier;
            opts.skip_start = skip_start;
            opts.no_break = no_break;
            opts.no_show = no_show;
            opts.break_on_cancel = break_on_cancel;
            return unwrap(sr::text(pattern, addr, opts));
        },
        py::arg("addr"), py::arg("pattern"),
        py::kw_only(),
        py::arg("direction") = "forward",
        py::arg("case_sensitive") = true,
        py::arg("regex") = false,
        py::arg("identifier") = false,
        py::arg("skip_start") = false,
        py::arg("no_break") = true,
        py::arg("no_show") = true,
        py::arg("break_on_cancel") = false,
        "Search for a text string in the disassembly listing.");

    // ── Immediate search ───────────────────────────────────────────────

    m.def("immediate",
        [](ida::Address addr, std::uint64_t value,
           const std::string& direction, bool skip_start,
           bool no_break, bool no_show, bool break_on_cancel) {
            sr::ImmediateOptions opts;
            opts.direction = (direction == "backward")
                ? sr::Direction::Backward : sr::Direction::Forward;
            opts.skip_start = skip_start;
            opts.no_break = no_break;
            opts.no_show = no_show;
            opts.break_on_cancel = break_on_cancel;
            return unwrap(sr::immediate(value, addr, opts));
        },
        py::arg("addr"), py::arg("value"),
        py::kw_only(),
        py::arg("direction") = "forward",
        py::arg("skip_start") = false,
        py::arg("no_break") = true,
        py::arg("no_show") = true,
        py::arg("break_on_cancel") = false,
        "Search for an immediate value in instruction operands.");

    // ── Binary pattern search ──────────────────────────────────────────

    m.def("binary_pattern",
        [](ida::Address addr, const std::string& pattern,
           const std::string& direction, bool skip_start,
           bool no_break, bool no_show, bool break_on_cancel) {
            sr::BinaryPatternOptions opts;
            opts.direction = (direction == "backward")
                ? sr::Direction::Backward : sr::Direction::Forward;
            opts.skip_start = skip_start;
            opts.no_break = no_break;
            opts.no_show = no_show;
            opts.break_on_cancel = break_on_cancel;
            return unwrap(sr::binary_pattern(pattern, addr, opts));
        },
        py::arg("addr"), py::arg("pattern"),
        py::kw_only(),
        py::arg("direction") = "forward",
        py::arg("skip_start") = false,
        py::arg("no_break") = true,
        py::arg("no_show") = true,
        py::arg("break_on_cancel") = false,
        "Search for a binary byte pattern (hex string like '90 90 CC').");

    // ── Next-* searches ────────────────────────────────────────────────

    m.def("next_code", [](ida::Address addr) {
        return unwrap(sr::next_code(addr));
    }, py::arg("addr"),
       "Find the next address containing code.");

    m.def("next_data", [](ida::Address addr) {
        return unwrap(sr::next_data(addr));
    }, py::arg("addr"),
       "Find the next address containing data.");

    m.def("next_unknown", [](ida::Address addr) {
        return unwrap(sr::next_unknown(addr));
    }, py::arg("addr"),
       "Find the next unexplored (unknown) byte.");

    m.def("next_error", [](ida::Address addr) {
        return unwrap(sr::next_error(addr));
    }, py::arg("addr"),
       "Find the next address with an analyzer error/problem marker.");

    m.def("next_defined", [](ida::Address addr) {
        return unwrap(sr::next_defined(addr));
    }, py::arg("addr"),
       "Find the next defined item address.");
}
