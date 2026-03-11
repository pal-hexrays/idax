/// \file comment_bind.cpp
/// \brief pybind11 bindings for ida::comment — comment access and mutation.

#include "helpers.hpp"
#include <ida/comment.hpp>

namespace cm = ida::comment;

void init_comment(py::module_& parent) {
    auto m = parent.def_submodule("comment",
        "Comment access and mutation (regular, repeatable, anterior/posterior).");

    // ── Regular comments ───────────────────────────────────────────────

    m.def("get", [](ida::Address addr, bool repeatable) {
        return unwrap(cm::get(addr, repeatable));
    }, py::arg("addr"), py::arg("repeatable") = false,
       "Get the comment at address.");

    m.def("set", [](ida::Address addr, const std::string& text, bool repeatable) {
        check_status(cm::set(addr, text, repeatable));
    }, py::arg("addr"), py::arg("text"), py::arg("repeatable") = false,
       "Set the comment at address.");

    m.def("append", [](ida::Address addr, const std::string& text, bool repeatable) {
        check_status(cm::append(addr, text, repeatable));
    }, py::arg("addr"), py::arg("text"), py::arg("repeatable") = false,
       "Append text to the comment at address.");

    m.def("remove", [](ida::Address addr, bool repeatable) {
        check_status(cm::remove(addr, repeatable));
    }, py::arg("addr"), py::arg("repeatable") = false,
       "Remove the comment at address.");

    // ── Anterior / posterior single-line ────────────────────────────────

    m.def("add_anterior", [](ida::Address addr, const std::string& text) {
        check_status(cm::add_anterior(addr, text));
    }, py::arg("addr"), py::arg("text"),
       "Add an anterior comment line at address.");

    m.def("add_posterior", [](ida::Address addr, const std::string& text) {
        check_status(cm::add_posterior(addr, text));
    }, py::arg("addr"), py::arg("text"),
       "Add a posterior comment line at address.");

    m.def("get_anterior", [](ida::Address addr, int line_index) {
        return unwrap(cm::get_anterior(addr, line_index));
    }, py::arg("addr"), py::arg("line_index"),
       "Get anterior comment line at index.");

    m.def("get_posterior", [](ida::Address addr, int line_index) {
        return unwrap(cm::get_posterior(addr, line_index));
    }, py::arg("addr"), py::arg("line_index"),
       "Get posterior comment line at index.");

    m.def("set_anterior", [](ida::Address addr, int line_index, const std::string& text) {
        check_status(cm::set_anterior(addr, line_index, text));
    }, py::arg("addr"), py::arg("line_index"), py::arg("text"),
       "Set anterior comment line at index.");

    m.def("set_posterior", [](ida::Address addr, int line_index, const std::string& text) {
        check_status(cm::set_posterior(addr, line_index, text));
    }, py::arg("addr"), py::arg("line_index"), py::arg("text"),
       "Set posterior comment line at index.");

    m.def("remove_anterior_line", [](ida::Address addr, int line_index) {
        check_status(cm::remove_anterior_line(addr, line_index));
    }, py::arg("addr"), py::arg("line_index"),
       "Remove anterior comment line at index.");

    m.def("remove_posterior_line", [](ida::Address addr, int line_index) {
        check_status(cm::remove_posterior_line(addr, line_index));
    }, py::arg("addr"), py::arg("line_index"),
       "Remove posterior comment line at index.");

    // ── Bulk operations ────────────────────────────────────────────────

    m.def("set_anterior_lines", [](ida::Address addr, const std::vector<std::string>& lines) {
        check_status(cm::set_anterior_lines(addr, lines));
    }, py::arg("addr"), py::arg("lines"),
       "Set all anterior comment lines at address.");

    m.def("set_posterior_lines", [](ida::Address addr, const std::vector<std::string>& lines) {
        check_status(cm::set_posterior_lines(addr, lines));
    }, py::arg("addr"), py::arg("lines"),
       "Set all posterior comment lines at address.");

    m.def("clear_anterior", [](ida::Address addr) {
        check_status(cm::clear_anterior(addr));
    }, py::arg("addr"),
       "Clear all anterior comment lines at address.");

    m.def("clear_posterior", [](ida::Address addr) {
        check_status(cm::clear_posterior(addr));
    }, py::arg("addr"),
       "Clear all posterior comment lines at address.");

    m.def("anterior_lines", [](ida::Address addr) {
        return unwrap(cm::anterior_lines(addr));
    }, py::arg("addr"),
       "Get all anterior comment lines at address.");

    m.def("posterior_lines", [](ida::Address addr) {
        return unwrap(cm::posterior_lines(addr));
    }, py::arg("addr"),
       "Get all posterior comment lines at address.");

    // ── Rendering ──────────────────────────────────────────────────────

    m.def("render", [](ida::Address addr, bool include_repeatable, bool include_extra_lines) {
        return unwrap(cm::render(addr, include_repeatable, include_extra_lines));
    }, py::arg("addr"), py::arg("include_repeatable") = true,
       py::arg("include_extra_lines") = true,
       "Render comments at address into one normalized text block.");
}
