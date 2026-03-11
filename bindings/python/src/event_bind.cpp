/// \file event_bind.cpp
/// \brief pybind11 bindings for ida::event — typed event subscriptions.
///
/// Callbacks must hold the GIL when called from C++ threads.  Each Python
/// callback is wrapped in a shared_ptr to prevent the GC from collecting it
/// while the subscription is live.

#include "helpers.hpp"
#include <ida/event.hpp>

#include <memory>

namespace ev = ida::event;

namespace {

/// Convert an EventKind enum to a Python string.
static const char* event_kind_to_string(ev::EventKind kind) {
    switch (kind) {
        case ev::EventKind::SegmentAdded:    return "segment_added";
        case ev::EventKind::SegmentDeleted:  return "segment_deleted";
        case ev::EventKind::FunctionAdded:   return "function_added";
        case ev::EventKind::FunctionDeleted: return "function_deleted";
        case ev::EventKind::Renamed:         return "renamed";
        case ev::EventKind::BytePatched:     return "byte_patched";
        case ev::EventKind::CommentChanged:  return "comment_changed";
    }
    return "unknown";
}

/// Convert an ida::event::Event to a Python dict.
static py::dict event_to_dict(const ev::Event& e) {
    py::dict d;
    d["kind"]              = event_kind_to_string(e.kind);
    d["address"]           = e.address;
    d["secondary_address"] = e.secondary_address;
    d["new_name"]          = e.new_name;
    d["old_name"]          = e.old_name;
    d["old_value"]         = e.old_value;
    d["repeatable"]        = e.repeatable;
    return d;
}

} // anonymous namespace

void init_event(py::module_& parent) {
    auto m = parent.def_submodule("event",
        "Typed event subscriptions for IDB database changes.");

    // ── on_segment_added ────────────────────────────────────────────────

    m.def("on_segment_added", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_segment_added(
            [held](ida::Address start) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(start);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to segment-added events. Returns a token for unsubscribe.");

    // ── on_segment_deleted ──────────────────────────────────────────────

    m.def("on_segment_deleted", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_segment_deleted(
            [held](ida::Address start, ida::Address end) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(start, end);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to segment-deleted events. Returns a token for unsubscribe.");

    // ── on_function_added ───────────────────────────────────────────────

    m.def("on_function_added", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_function_added(
            [held](ida::Address entry) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(entry);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to function-added events. Returns a token for unsubscribe.");

    // ── on_function_deleted ─────────────────────────────────────────────

    m.def("on_function_deleted", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_function_deleted(
            [held](ida::Address entry) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(entry);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to function-deleted events. Returns a token for unsubscribe.");

    // ── on_renamed ──────────────────────────────────────────────────────

    m.def("on_renamed", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_renamed(
            [held](ida::Address ea, std::string new_name, std::string old_name) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(ea, new_name, old_name);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to rename events. Callback receives (address, new_name, old_name).");

    // ── on_byte_patched ─────────────────────────────────────────────────

    m.def("on_byte_patched", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_byte_patched(
            [held](ida::Address ea, std::uint32_t old_value) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(ea, old_value);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to byte-patched events. Callback receives (address, old_value).");

    // ── on_comment_changed ──────────────────────────────────────────────

    m.def("on_comment_changed", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_comment_changed(
            [held](ida::Address ea, bool repeatable) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(ea, repeatable);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to comment-changed events. Callback receives (address, repeatable).");

    // ── on_event (catch-all) ────────────────────────────────────────────

    m.def("on_event", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(ev::on_event(
            [held](const ev::Event& ev) {
                py::gil_scoped_acquire gil;
                try {
                    (*held)(event_to_dict(ev));
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to all IDB events. Callback receives a dict with kind, address, etc.");

    // ── unsubscribe ─────────────────────────────────────────────────────

    m.def("unsubscribe", [](std::uint64_t token) {
        check_status(ev::unsubscribe(token));
    }, py::arg("token"),
       "Unsubscribe a previously registered event callback.");
}
