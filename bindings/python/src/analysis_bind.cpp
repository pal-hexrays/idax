/// \file analysis_bind.cpp
/// \brief pybind11 bindings for ida::analysis — auto-analysis control,
///        scheduling, waiting.

#include "helpers.hpp"
#include <ida/analysis.hpp>

namespace an = ida::analysis;

void init_analysis(py::module_& parent) {
    auto m = parent.def_submodule("analysis",
        "Auto-analysis control: scheduling, waiting, enable/disable.");

    // ── Enable / disable / idle ────────────────────────────────────────

    m.def("is_enabled", []() {
        return an::is_enabled();
    }, "Check if the auto-analyser is enabled.");

    m.def("set_enabled", [](bool enabled) {
        check_status(an::set_enabled(enabled));
    }, py::arg("enabled"),
       "Enable or disable the auto-analyser.");

    m.def("is_idle", []() {
        return an::is_idle();
    }, "Check if the auto-analyser is idle (no pending work).");

    // ── Waiting ────────────────────────────────────────────────────────

    m.def("wait", []() {
        check_status(an::wait());
    }, "Block until the auto-analyser finishes all pending work.");

    m.def("wait_range", [](ida::Address start, ida::Address end) {
        check_status(an::wait_range(start, end));
    }, py::arg("start"), py::arg("end"),
       "Block until the auto-analyser finishes work in [start, end).");

    // ── Scheduling ─────────────────────────────────────────────────────

    m.def("schedule", [](ida::Address addr) {
        check_status(an::schedule(addr));
    }, py::arg("addr"),
       "Schedule reanalysis of the byte at address.");

    m.def("schedule_range", [](ida::Address start, ida::Address end) {
        check_status(an::schedule_range(start, end));
    }, py::arg("start"), py::arg("end"),
       "Schedule reanalysis of the range [start, end).");

    m.def("schedule_code", [](ida::Address addr) {
        check_status(an::schedule_code(addr));
    }, py::arg("addr"),
       "Schedule conversion to code at address.");

    m.def("schedule_function", [](ida::Address addr) {
        check_status(an::schedule_function(addr));
    }, py::arg("addr"),
       "Schedule function creation/recovery at address.");

    m.def("schedule_reanalysis", [](ida::Address addr) {
        check_status(an::schedule_reanalysis(addr));
    }, py::arg("addr"),
       "Schedule reanalysis at address.");

    m.def("schedule_reanalysis_range", [](ida::Address start, ida::Address end) {
        check_status(an::schedule_reanalysis_range(start, end));
    }, py::arg("start"), py::arg("end"),
       "Schedule reanalysis for [start, end).");

    // ── Cancellation / revert ──────────────────────────────────────────

    m.def("cancel", [](ida::Address start, ida::Address end) {
        check_status(an::cancel(start, end));
    }, py::arg("start"), py::arg("end"),
       "Remove pending queue entries in [start, end).");

    m.def("revert_decisions", [](ida::Address start, ida::Address end) {
        check_status(an::revert_decisions(start, end));
    }, py::arg("start"), py::arg("end"),
       "Revert analyzer-generated decisions in [start, end).");
}
