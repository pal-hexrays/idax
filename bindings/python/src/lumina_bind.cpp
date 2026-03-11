/// \file lumina_bind.cpp
/// \brief pybind11 bindings for ida::lumina — Lumina metadata pull/push.

#include "helpers.hpp"
#include <ida/lumina.hpp>

namespace lm = ida::lumina;

void init_lumina(py::module_& parent) {
    auto m = parent.def_submodule("lumina",
        "Lumina metadata pull/push.");

    // ── Enums ─────────────────────────────────────────────────────────────

    py::enum_<lm::Feature>(m, "Feature")
        .value("primary_metadata",   lm::Feature::PrimaryMetadata)
        .value("decompiler",         lm::Feature::Decompiler)
        .value("telemetry",          lm::Feature::Telemetry)
        .value("secondary_metadata", lm::Feature::SecondaryMetadata);

    py::enum_<lm::PushMode>(m, "PushMode")
        .value("prefer_better_or_different", lm::PushMode::PreferBetterOrDifferent)
        .value("override",                   lm::PushMode::Override)
        .value("keep_existing",              lm::PushMode::KeepExisting)
        .value("merge",                      lm::PushMode::Merge);

    py::enum_<lm::OperationCode>(m, "OperationCode")
        .value("bad_pattern", lm::OperationCode::BadPattern)
        .value("not_found",   lm::OperationCode::NotFound)
        .value("error",       lm::OperationCode::Error)
        .value("ok",          lm::OperationCode::Ok)
        .value("added",       lm::OperationCode::Added);

    // ── Value type ────────────────────────────────────────────────────────

    py::class_<lm::BatchResult>(m, "BatchResult")
        .def_readonly("requested", &lm::BatchResult::requested)
        .def_readonly("completed", &lm::BatchResult::completed)
        .def_readonly("succeeded", &lm::BatchResult::succeeded)
        .def_readonly("failed",    &lm::BatchResult::failed)
        .def_readonly("codes",     &lm::BatchResult::codes)
        .def("__repr__", [](const lm::BatchResult& r) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "<BatchResult requested=%zu completed=%zu "
                          "succeeded=%zu failed=%zu>",
                          r.requested, r.completed,
                          r.succeeded, r.failed);
            return std::string(buf);
        });

    // ── Functions ─────────────────────────────────────────────────────────

    m.def("has_connection", [](lm::Feature feature) {
        return unwrap(lm::has_connection(feature));
    }, py::arg("feature") = lm::Feature::PrimaryMetadata,
       "Check whether a Lumina connection is open for the given feature.");

    m.def("close_connection", [](lm::Feature feature) {
        check_status(lm::close_connection(feature));
    }, py::arg("feature") = lm::Feature::PrimaryMetadata,
       "Close a Lumina connection for one feature channel.");

    m.def("close_all_connections", []() {
        check_status(lm::close_all_connections());
    }, "Close all Lumina connections.");

    m.def("pull", [](std::variant<ida::Address, std::vector<ida::Address>> addresses,
                     bool auto_apply, bool skip_frequency_update,
                     lm::Feature feature) {
        if (auto* single = std::get_if<ida::Address>(&addresses)) {
            return unwrap(lm::pull(*single, auto_apply,
                                   skip_frequency_update, feature));
        }
        auto& vec = std::get<std::vector<ida::Address>>(addresses);
        return unwrap(lm::pull(
            std::span<const ida::Address>(vec.data(), vec.size()),
            auto_apply, skip_frequency_update, feature));
    }, py::arg("addresses"),
       py::arg("auto_apply") = true,
       py::arg("skip_frequency_update") = false,
       py::arg("feature") = lm::Feature::PrimaryMetadata,
       "Pull metadata for one or more function addresses.");

    m.def("push", [](std::variant<ida::Address, std::vector<ida::Address>> addresses,
                     lm::PushMode mode, lm::Feature feature) {
        if (auto* single = std::get_if<ida::Address>(&addresses)) {
            return unwrap(lm::push(*single, mode, feature));
        }
        auto& vec = std::get<std::vector<ida::Address>>(addresses);
        return unwrap(lm::push(
            std::span<const ida::Address>(vec.data(), vec.size()),
            mode, feature));
    }, py::arg("addresses"),
       py::arg("mode") = lm::PushMode::PreferBetterOrDifferent,
       py::arg("feature") = lm::Feature::PrimaryMetadata,
       "Push metadata for one or more function addresses.");
}
