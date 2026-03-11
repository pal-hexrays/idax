/// \file database_bind.cpp
/// \brief pybind11 bindings for ida::database — lifecycle, metadata, and snapshots.

#include "helpers.hpp"
#include <ida/database.hpp>

namespace db = ida::database;

// ── Snapshot helper ─────────────────────────────────────────────────────

/// Recursively convert a Snapshot tree to a Python dict.
static py::dict snapshot_to_dict(const db::Snapshot& snap) {
    py::list children;
    for (const auto& child : snap.children) {
        children.append(snapshot_to_dict(child));
    }

    py::dict d;
    d["id"] = snap.id;
    d["flags"] = snap.flags;
    d["description"] = snap.description;
    d["filename"] = snap.filename;
    d["children"] = children;
    return d;
}

// ── Module registration ─────────────────────────────────────────────────

void init_database(py::module_& parent) {
    auto m = parent.def_submodule("database",
        "Database lifecycle, metadata, and snapshot operations.");

    // ── Enums ───────────────────────────────────────────────────────────

    py::enum_<db::OpenMode>(m, "OpenMode")
        .value("analyze",       db::OpenMode::Analyze)
        .value("skip_analysis", db::OpenMode::SkipAnalysis);

    py::enum_<db::LoadIntent>(m, "LoadIntent")
        .value("auto_detect", db::LoadIntent::AutoDetect)
        .value("binary",      db::LoadIntent::Binary)
        .value("non_binary",  db::LoadIntent::NonBinary);

    // ── Value types ─────────────────────────────────────────────────────

    py::class_<db::PluginLoadPolicy>(m, "PluginLoadPolicy")
        .def(py::init<>())
        .def(py::init([](bool disable_user_plugins, py::list allowlist_patterns) {
            db::PluginLoadPolicy p;
            p.disable_user_plugins = disable_user_plugins;
            for (auto& item : allowlist_patterns) {
                p.allowlist_patterns.push_back(item.cast<std::string>());
            }
            return p;
        }), py::arg("disable_user_plugins") = false,
            py::arg("allowlist_patterns") = py::list())
        .def_readwrite("disable_user_plugins", &db::PluginLoadPolicy::disable_user_plugins)
        .def_readwrite("allowlist_patterns",   &db::PluginLoadPolicy::allowlist_patterns);

    py::class_<db::RuntimeOptions>(m, "RuntimeOptions")
        .def(py::init<>())
        .def(py::init([](bool quiet, std::optional<db::PluginLoadPolicy> plugin_policy) {
            db::RuntimeOptions rt;
            rt.quiet = quiet;
            if (plugin_policy) rt.plugin_policy = *plugin_policy;
            return rt;
        }), py::arg("quiet") = false,
            py::arg("plugin_policy") = std::nullopt)
        .def_readwrite("quiet",         &db::RuntimeOptions::quiet)
        .def_readwrite("plugin_policy", &db::RuntimeOptions::plugin_policy);

    py::class_<db::CompilerInfo>(m, "CompilerInfo")
        .def_readonly("id",           &db::CompilerInfo::id)
        .def_readonly("uncertain",    &db::CompilerInfo::uncertain)
        .def_readonly("name",         &db::CompilerInfo::name)
        .def_readonly("abbreviation", &db::CompilerInfo::abbreviation);

    py::class_<db::ImportSymbol>(m, "ImportSymbol")
        .def_readonly("address", &db::ImportSymbol::address)
        .def_readonly("name",    &db::ImportSymbol::name)
        .def_readonly("ordinal", &db::ImportSymbol::ordinal);

    py::class_<db::ImportModule>(m, "ImportModule")
        .def_readonly("index",   &db::ImportModule::index)
        .def_readonly("name",    &db::ImportModule::name)
        .def_readonly("symbols", &db::ImportModule::symbols);

    // ── Lifecycle ───────────────────────────────────────────────────────

    m.def("init", [](bool quiet, std::optional<db::PluginLoadPolicy> plugin_policy) {
        if (!quiet && !plugin_policy) {
            check_status(db::init());
        } else {
            db::RuntimeOptions rt;
            rt.quiet = quiet;
            if (plugin_policy) rt.plugin_policy = *plugin_policy;
            check_status(db::init(rt));
        }
    }, py::arg("quiet") = false,
       py::arg("plugin_policy") = std::nullopt,
       "Initialise the IDA library. Call once before any other idax call.");

    m.def("open", [](const std::string& path,
                      std::optional<bool> auto_analysis,
                      std::optional<db::OpenMode> mode,
                      std::optional<db::LoadIntent> intent) {
        if (intent) {
            // open(path, intent, mode)
            db::OpenMode m = mode.value_or(db::OpenMode::Analyze);
            check_status(db::open(path, *intent, m));
        } else if (mode) {
            // open(path, mode)
            check_status(db::open(path, *mode));
        } else if (auto_analysis) {
            // open(path, auto_analysis)
            check_status(db::open(path, *auto_analysis));
        } else {
            // open(path)
            check_status(db::open(path));
        }
    }, py::arg("path"),
       py::arg("auto_analysis") = std::nullopt,
       py::arg("mode") = std::nullopt,
       py::arg("intent") = std::nullopt,
       "Open (or create) a database for the given input file.");

    m.def("open_binary", [](const std::string& path, db::OpenMode mode) {
        check_status(db::open_binary(path, mode));
    }, py::arg("path"),
       py::arg("mode") = db::OpenMode::Analyze,
       "Open with explicit binary-input intent.");

    m.def("open_non_binary", [](const std::string& path, db::OpenMode mode) {
        check_status(db::open_non_binary(path, mode));
    }, py::arg("path"),
       py::arg("mode") = db::OpenMode::Analyze,
       "Open with explicit non-binary-input intent.");

    m.def("save", []() {
        check_status(db::save());
    }, "Save the current database.");

    m.def("close", [](bool save_before) {
        check_status(db::close(save_before));
    }, py::arg("save_before") = false,
       "Close the current database.");

    m.def("file_to_database", [](const std::string& file_path,
                                  std::int64_t file_offset,
                                  ida::Address ea,
                                  ida::AddressSize size,
                                  bool patchable,
                                  bool remote) {
        check_status(db::file_to_database(file_path, file_offset, ea, size, patchable, remote));
    }, py::arg("file_path"),
       py::arg("file_offset"),
       py::arg("ea"),
       py::arg("size"),
       py::arg("patchable") = true,
       py::arg("remote") = false,
       "Load a file range into the database at [ea, ea+size).");

    m.def("memory_to_database", [](py::bytes data,
                                    ida::Address ea,
                                    std::int64_t file_offset) {
        std::string_view sv = data;
        std::span<const std::uint8_t> bytes(
            reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size());
        check_status(db::memory_to_database(bytes, ea, file_offset));
    }, py::arg("data"),
       py::arg("ea"),
       py::arg("file_offset") = -1,
       "Load bytes from memory into the database at [ea, ea+len(data)).");

    // ── Metadata ────────────────────────────────────────────────────────

    m.def("input_file_path", []() {
        return unwrap(db::input_file_path());
    }, "Path of the original input file.");

    m.def("file_type_name", []() {
        return unwrap(db::file_type_name());
    }, "Human-readable input file type name.");

    m.def("loader_format_name", []() {
        return unwrap(db::loader_format_name());
    }, "Loader-reported format name.");

    m.def("input_md5", []() {
        return unwrap(db::input_md5());
    }, "MD5 hash of the original input file (hex string).");

    m.def("compiler_info", []() {
        return unwrap(db::compiler_info());
    }, "Target compiler metadata for this database.");

    m.def("import_modules", []() {
        return unwrap(db::import_modules());
    }, "Import-module inventory with per-symbol names/ordinals/addresses.");

    m.def("image_base", []() {
        return unwrap(db::image_base());
    }, "Image base address of the loaded binary.");

    m.def("min_address", []() {
        return unwrap(db::min_address());
    }, "Lowest mapped address in the database.");

    m.def("max_address", []() {
        return unwrap(db::max_address());
    }, "Highest mapped address in the database.");

    m.def("address_bounds", []() {
        auto range = unwrap(db::address_bounds());
        py::dict d;
        d["start"] = range.start;
        d["end"] = range.end;
        return d;
    }, "Address bounds as a dict with 'start' and 'end' keys.");

    m.def("address_span", []() {
        return unwrap(db::address_span());
    }, "Span of mapped address space (max_address - min_address).");

    m.def("processor_id", []() {
        return unwrap(db::processor_id());
    }, "Active processor module ID (PLFM_* constant).");

    m.def("processor", []() {
        return static_cast<int>(unwrap(db::processor()));
    }, "Active processor module ID as an integer.");

    m.def("processor_name", []() {
        return unwrap(db::processor_name());
    }, "Active processor module short name.");

    m.def("address_bitness", []() {
        return unwrap(db::address_bitness());
    }, "Program address bitness for the current database (16/32/64).");

    m.def("set_address_bitness", [](int bits) {
        check_status(db::set_address_bitness(bits));
    }, py::arg("bits"),
       "Set the program address bitness (16, 32, or 64).");

    m.def("is_big_endian", []() {
        return unwrap(db::is_big_endian());
    }, "Endianness of the current database.");

    m.def("abi_name", []() {
        return unwrap(db::abi_name());
    }, "Active ABI name when available.");

    // ── Snapshots ───────────────────────────────────────────────────────

    m.def("snapshots", []() {
        auto snaps = unwrap(db::snapshots());
        py::list result;
        for (const auto& snap : snaps) {
            result.append(snapshot_to_dict(snap));
        }
        return result;
    }, "Build and return the database snapshot tree.");

    m.def("set_snapshot_description", [](const std::string& desc) {
        check_status(db::set_snapshot_description(desc));
    }, py::arg("description"),
       "Update the current database snapshot description.");

    m.def("is_snapshot_database", []() {
        return unwrap(db::is_snapshot_database());
    }, "Whether the current database is marked as a snapshot.");
}
