/// \file storage_bind.cpp
/// \brief pybind11 bindings for ida::storage — low-level persistent key-value storage.
///
/// Wraps ida::storage::Node as a py::class_.  pybind11 manages lifetime via
/// unique_ptr automatically — no Nan::ObjectWrap ceremony needed.

#include "helpers.hpp"
#include <ida/storage.hpp>

#include <memory>

namespace st = ida::storage;

namespace {

/// Helper: extract a tag character from a Python string argument.
/// Returns the first character of the string, or the default if not provided.
static std::uint8_t parse_tag(const std::string& tag) {
    return tag.empty() ? 'A' : static_cast<std::uint8_t>(tag[0]);
}

} // anonymous namespace

void init_storage(py::module_& parent) {
    auto m = parent.def_submodule("storage",
        "Low-level persistent key-value storage (netnode abstraction).");

    // ── StorageNode class ───────────────────────────────────────────────

    py::class_<st::Node>(m, "StorageNode")
        .def("id", [](const st::Node& self) {
            return unwrap(self.id());
        }, "Get the numeric node ID.")

        .def("name", [](const st::Node& self) {
            return unwrap(self.name());
        }, "Get the node name.")

        // ── Alt operations ──────────────────────────────────────────────

        .def("alt", [](const st::Node& self, ida::Address index, const std::string& tag) {
            return unwrap(self.alt(index, parse_tag(tag)));
        }, py::arg("index"), py::arg("tag") = "A",
           "Read an integer value at the given index.")

        .def("set_alt", [](st::Node& self, ida::Address index, std::uint64_t value,
                           const std::string& tag) {
            check_status(self.set_alt(index, value, parse_tag(tag)));
        }, py::arg("index"), py::arg("value"), py::arg("tag") = "A",
           "Set an integer value at the given index.")

        .def("remove_alt", [](st::Node& self, ida::Address index, const std::string& tag) {
            check_status(self.remove_alt(index, parse_tag(tag)));
        }, py::arg("index"), py::arg("tag") = "A",
           "Remove an integer value at the given index.")

        // ── Sup operations ──────────────────────────────────────────────

        .def("sup", [](const st::Node& self, ida::Address index, const std::string& tag) {
            auto data = unwrap(self.sup(index, parse_tag(tag)));
            return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, py::arg("index"), py::arg("tag") = "S",
           "Read small binary data at the given index.")

        .def("set_sup", [](st::Node& self, ida::Address index, py::bytes data,
                           const std::string& tag) {
            std::string_view sv = data;
            auto span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size());
            check_status(self.set_sup(index, span, parse_tag(tag)));
        }, py::arg("index"), py::arg("data"), py::arg("tag") = "S",
           "Write small binary data at the given index.")

        // ── Hash operations ─────────────────────────────────────────────

        .def("hash", [](const st::Node& self, const std::string& key, const std::string& tag) {
            return unwrap(self.hash(key, parse_tag(tag)));
        }, py::arg("key"), py::arg("tag") = "H",
           "Read a string value for the given key.")

        .def("set_hash", [](st::Node& self, const std::string& key, const std::string& value,
                            const std::string& tag) {
            check_status(self.set_hash(key, value, parse_tag(tag)));
        }, py::arg("key"), py::arg("value"), py::arg("tag") = "H",
           "Set a string value for the given key.")

        // ── Blob operations ─────────────────────────────────────────────

        .def("blob_size", [](const st::Node& self, ida::Address index, const std::string& tag) {
            return unwrap(self.blob_size(index, parse_tag(tag)));
        }, py::arg("index"), py::arg("tag") = "B",
           "Get the size of a blob at the given index.")

        .def("blob", [](const st::Node& self, ida::Address index, const std::string& tag) {
            auto data = unwrap(self.blob(index, parse_tag(tag)));
            return py::bytes(reinterpret_cast<const char*>(data.data()), data.size());
        }, py::arg("index"), py::arg("tag") = "B",
           "Read a blob at the given index.")

        .def("set_blob", [](st::Node& self, ida::Address index, py::bytes data,
                            const std::string& tag) {
            std::string_view sv = data;
            auto span = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size());
            check_status(self.set_blob(index, span, parse_tag(tag)));
        }, py::arg("index"), py::arg("data"), py::arg("tag") = "B",
           "Write a blob at the given index.")

        .def("remove_blob", [](st::Node& self, ida::Address index, const std::string& tag) {
            check_status(self.remove_blob(index, parse_tag(tag)));
        }, py::arg("index"), py::arg("tag") = "B",
           "Remove a blob at the given index.")

        .def("blob_string", [](const st::Node& self, ida::Address index, const std::string& tag) {
            return unwrap(self.blob_string(index, parse_tag(tag)));
        }, py::arg("index"), py::arg("tag") = "B",
           "Read a blob as a string at the given index.")

        .def("__repr__", [](const st::Node& self) {
            auto name_result = self.name();
            if (name_result) {
                return "<StorageNode '" + *name_result + "'>";
            }
            return std::string("<StorageNode>");
        });

    // ── Factory functions ───────────────────────────────────────────────

    m.def("open", [](const std::string& name, bool create) {
        return unwrap(st::Node::open(name, create));
    }, py::arg("name"), py::arg("create") = false,
       "Open a storage node by name. Set create=True to create if it doesn't exist.");

    m.def("open_by_id", [](std::uint64_t id) {
        return unwrap(st::Node::open_by_id(id));
    }, py::arg("id"),
       "Open a storage node by its numeric ID.");
}
