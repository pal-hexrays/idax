/// \file diagnostics_bind.cpp
/// \brief pybind11 bindings for ida::diagnostics — logging, invariants, and counters.

#include "helpers.hpp"
#include <ida/diagnostics.hpp>

namespace dg = ida::diagnostics;

void init_diagnostics(py::module_& parent) {
    auto m = parent.def_submodule("diagnostics",
        "Logging, invariants, and performance counters.");

    // ── Enum ──────────────────────────────────────────────────────────────

    py::enum_<dg::LogLevel>(m, "LogLevel")
        .value("trace",   dg::LogLevel::Trace)
        .value("debug",   dg::LogLevel::Debug)
        .value("info",    dg::LogLevel::Info)
        .value("warning", dg::LogLevel::Warning)
        .value("error",   dg::LogLevel::Error);

    // ── Functions ─────────────────────────────────────────────────────────

    m.def("set_log_level", [](dg::LogLevel level) {
        check_status(dg::set_log_level(level));
    }, py::arg("level"),
       "Set the current log level.");

    m.def("log_level", []() {
        return dg::log_level();
    }, "Get the current log level.");

    m.def("log", [](dg::LogLevel level, const std::string& domain,
                     const std::string& message) {
        dg::log(level, domain, message);
    }, py::arg("level"), py::arg("domain"), py::arg("message"),
       "Emit a log message at the given level and domain.");

    m.def("assert_invariant", [](bool condition, const std::string& message) {
        check_status(dg::assert_invariant(condition, message));
    }, py::arg("condition"), py::arg("message"),
       "Assert a runtime invariant; raises on failure.");

    m.def("reset_performance_counters", []() {
        dg::reset_performance_counters();
    }, "Reset all performance counters to zero.");

    m.def("performance_counters", []() {
        auto counters = dg::performance_counters();
        py::dict d;
        d["log_messages"] = counters.log_messages;
        d["invariant_failures"] = counters.invariant_failures;
        return d;
    }, "Get current performance counters as a dict.");
}
