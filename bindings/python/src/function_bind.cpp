/// \file function_bind.cpp
/// \brief pybind11 bindings for ida::function — creation, query, traversal,
///        chunks, frames, register variables.

#include "helpers.hpp"
#include <ida/function.hpp>
#include <ida/type.hpp>

namespace fn = ida::function;

void init_function(py::module_& parent) {
    auto m = parent.def_submodule("function",
        "Function operations: creation, query, traversal, chunks, frames.");

    // ── Value types ─────────────────────────────────────────────────────

    py::class_<fn::Function>(m, "Function")
        .def_property_readonly("start", &fn::Function::start)
        .def_property_readonly("end", &fn::Function::end)
        .def_property_readonly("size", &fn::Function::size)
        .def_property_readonly("name", [](const fn::Function& f) {
            return std::string(f.name());
        })
        .def_property_readonly("bitness", &fn::Function::bitness)
        .def_property_readonly("returns", &fn::Function::returns)
        .def_property_readonly("is_library", &fn::Function::is_library)
        .def_property_readonly("is_thunk", &fn::Function::is_thunk)
        .def_property_readonly("is_visible", &fn::Function::is_visible)
        .def("refresh", [](fn::Function& f) {
            check_status(f.refresh());
        })
        .def("__repr__", [](const fn::Function& f) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "<Function '%s' at 0x%llx>",
                          std::string(f.name()).c_str(),
                          static_cast<unsigned long long>(f.start()));
            return std::string(buf);
        });

    py::class_<fn::Chunk>(m, "Chunk")
        .def_readonly("start", &fn::Chunk::start)
        .def_readonly("end", &fn::Chunk::end)
        .def_readonly("is_tail", &fn::Chunk::is_tail)
        .def_readonly("owner", &fn::Chunk::owner)
        .def_property_readonly("size", &fn::Chunk::size);

    py::class_<fn::FrameVariable>(m, "FrameVariable")
        .def_readonly("name", &fn::FrameVariable::name)
        .def_readonly("byte_offset", &fn::FrameVariable::byte_offset)
        .def_readonly("byte_size", &fn::FrameVariable::byte_size)
        .def_readonly("comment", &fn::FrameVariable::comment)
        .def_readonly("is_special", &fn::FrameVariable::is_special);

    py::class_<fn::StackFrame>(m, "StackFrame")
        .def_property_readonly("local_variables_size",
                               &fn::StackFrame::local_variables_size)
        .def_property_readonly("saved_registers_size",
                               &fn::StackFrame::saved_registers_size)
        .def_property_readonly("arguments_size",
                               &fn::StackFrame::arguments_size)
        .def_property_readonly("total_size",
                               &fn::StackFrame::total_size)
        .def_property_readonly("variables",
                               &fn::StackFrame::variables);

    py::class_<fn::RegisterVariable>(m, "RegisterVariable")
        .def_readonly("range_start", &fn::RegisterVariable::range_start)
        .def_readonly("range_end", &fn::RegisterVariable::range_end)
        .def_readonly("canonical_name", &fn::RegisterVariable::canonical_name)
        .def_readonly("user_name", &fn::RegisterVariable::user_name)
        .def_readonly("comment", &fn::RegisterVariable::comment);

    // ── CRUD ────────────────────────────────────────────────────────────

    m.def("create", [](ida::Address start, ida::Address end) {
        return unwrap(fn::create(start, end));
    }, py::arg("start"), py::arg("end") = ida::BadAddress,
       "Create a function. If end is BAD_ADDRESS, IDA determines the bounds.");

    m.def("remove", [](ida::Address addr) {
        check_status(fn::remove(addr));
    }, py::arg("addr"),
       "Delete the function containing addr.");

    // ── Lookup ──────────────────────────────────────────────────────────

    m.def("at", [](ida::Address addr) {
        return unwrap(fn::at(addr));
    }, py::arg("addr"),
       "Function containing the given address.");

    m.def("by_index", [](std::size_t index) {
        return unwrap(fn::by_index(index));
    }, py::arg("index"),
       "Function by positional index (0-based).");

    m.def("count", []() {
        return unwrap(fn::count());
    }, "Total number of functions.");

    m.def("name_at", [](ida::Address addr) {
        return unwrap(fn::name_at(addr));
    }, py::arg("addr"),
       "Get the name of the function containing addr.");

    // ── Boundary mutation ───────────────────────────────────────────────

    m.def("set_start", [](ida::Address addr, ida::Address new_start) {
        check_status(fn::set_start(addr, new_start));
    }, py::arg("addr"), py::arg("new_start"),
       "Set the start address of the function containing addr.");

    m.def("set_end", [](ida::Address addr, ida::Address new_end) {
        check_status(fn::set_end(addr, new_end));
    }, py::arg("addr"), py::arg("new_end"),
       "Set the end address of the function containing addr.");

    m.def("update", [](ida::Address addr) {
        check_status(fn::update(addr));
    }, py::arg("addr"),
       "Persist current function metadata after property changes.");

    m.def("reanalyze", [](ida::Address addr) {
        check_status(fn::reanalyze(addr));
    }, py::arg("addr"),
       "Schedule reanalysis for all items in the function.");

    m.def("is_outlined", [](ida::Address addr) {
        return unwrap(fn::is_outlined(addr));
    }, py::arg("addr"),
       "Return True if the function is marked as outlined.");

    m.def("set_outlined", [](ida::Address addr, bool outlined) {
        check_status(fn::set_outlined(addr, outlined));
    }, py::arg("addr"), py::arg("outlined"),
       "Set or clear the outlined marker on a function.");

    // ── Comments ────────────────────────────────────────────────────────

    m.def("comment", [](ida::Address addr, bool repeatable) {
        return unwrap(fn::comment(addr, repeatable));
    }, py::arg("addr"), py::arg("repeatable") = false,
       "Get the comment for the function containing addr.");

    m.def("set_comment", [](ida::Address addr, const std::string& text,
                            bool repeatable) {
        check_status(fn::set_comment(addr, text, repeatable));
    }, py::arg("addr"), py::arg("text"), py::arg("repeatable") = false,
       "Set the comment for the function containing addr.");

    // ── Relationships ───────────────────────────────────────────────────

    m.def("callers", [](ida::Address addr) {
        return unwrap(fn::callers(addr));
    }, py::arg("addr"),
       "Addresses of all functions that call the function at addr.");

    m.def("callees", [](ida::Address addr) {
        return unwrap(fn::callees(addr));
    }, py::arg("addr"),
       "Addresses of all functions called from the function at addr.");

    // ── Chunks ──────────────────────────────────────────────────────────

    m.def("chunks", [](ida::Address addr) {
        return unwrap(fn::chunks(addr));
    }, py::arg("addr"),
       "Get all chunks (entry + tails) for the function containing addr.");

    m.def("tail_chunks", [](ida::Address addr) {
        return unwrap(fn::tail_chunks(addr));
    }, py::arg("addr"),
       "Get only tail chunks for the function containing addr.");

    m.def("chunk_count", [](ida::Address addr) {
        return unwrap(fn::chunk_count(addr));
    }, py::arg("addr"),
       "Number of chunks for the function at addr.");

    m.def("add_tail", [](ida::Address func_addr, ida::Address tail_start,
                         ida::Address tail_end) {
        check_status(fn::add_tail(func_addr, tail_start, tail_end));
    }, py::arg("func_addr"), py::arg("tail_start"), py::arg("tail_end"),
       "Append a tail chunk to the function.");

    m.def("remove_tail", [](ida::Address func_addr, ida::Address tail_addr) {
        check_status(fn::remove_tail(func_addr, tail_addr));
    }, py::arg("func_addr"), py::arg("tail_addr"),
       "Remove a tail chunk from the function.");

    // ── Frame operations ────────────────────────────────────────────────

    m.def("frame", [](ida::Address addr) {
        return unwrap(fn::frame(addr));
    }, py::arg("addr"),
       "Retrieve a snapshot of the stack frame for the function at addr.");

    m.def("sp_delta_at", [](ida::Address addr) {
        return unwrap(fn::sp_delta_at(addr));
    }, py::arg("addr"),
       "Get the cumulative SP delta before the instruction at addr.");

    m.def("frame_variable_by_name", [](ida::Address addr,
                                       const std::string& name) {
        return unwrap(fn::frame_variable_by_name(addr, name));
    }, py::arg("addr"), py::arg("name"),
       "Find a frame variable by name in the function containing addr.");

    m.def("frame_variable_by_offset", [](ida::Address addr,
                                         std::size_t offset) {
        return unwrap(fn::frame_variable_by_offset(addr, offset));
    }, py::arg("addr"), py::arg("offset"),
       "Find a frame variable by byte offset in the function containing addr.");

    m.def("define_stack_variable", [](ida::Address func_addr,
                                      const std::string& name,
                                      std::int32_t frame_offset,
                                      const std::string& type_name) {
        auto type_info = unwrap(ida::type::TypeInfo::by_name(type_name));
        check_status(fn::define_stack_variable(func_addr, name,
                                               frame_offset, type_info));
    }, py::arg("func_addr"), py::arg("name"),
       py::arg("frame_offset"), py::arg("type_name"),
       "Define a stack variable in the function's frame.");

    // ── Register variables ──────────────────────────────────────────────

    m.def("add_register_variable", [](ida::Address func_addr,
                                      ida::Address range_start,
                                      ida::Address range_end,
                                      const std::string& register_name,
                                      const std::string& user_name,
                                      const std::string& comment) {
        check_status(fn::add_register_variable(func_addr, range_start,
                                                range_end, register_name,
                                                user_name, comment));
    }, py::arg("func_addr"), py::arg("range_start"), py::arg("range_end"),
       py::arg("register_name"), py::arg("user_name"),
       py::arg("comment") = "",
       "Define a register variable in the function.");

    m.def("find_register_variable", [](ida::Address func_addr,
                                       ida::Address addr,
                                       const std::string& register_name) {
        return unwrap(fn::find_register_variable(func_addr, addr,
                                                  register_name));
    }, py::arg("func_addr"), py::arg("addr"), py::arg("register_name"),
       "Find a register variable at an address by canonical register name.");

    m.def("remove_register_variable", [](ida::Address func_addr,
                                         ida::Address range_start,
                                         ida::Address range_end,
                                         const std::string& register_name) {
        check_status(fn::remove_register_variable(func_addr, range_start,
                                                    range_end, register_name));
    }, py::arg("func_addr"), py::arg("range_start"), py::arg("range_end"),
       py::arg("register_name"),
       "Remove a register variable definition.");

    m.def("rename_register_variable", [](ida::Address func_addr,
                                         ida::Address addr,
                                         const std::string& register_name,
                                         const std::string& new_user_name) {
        check_status(fn::rename_register_variable(func_addr, addr,
                                                    register_name,
                                                    new_user_name));
    }, py::arg("func_addr"), py::arg("addr"), py::arg("register_name"),
       py::arg("new_user_name"),
       "Rename an existing register variable.");

    m.def("has_register_variables", [](ida::Address func_addr,
                                       ida::Address addr) {
        return unwrap(fn::has_register_variables(func_addr, addr));
    }, py::arg("func_addr"), py::arg("addr"),
       "Check if there are any register variables at the given address.");

    m.def("register_variables", [](ida::Address addr) {
        return unwrap(fn::register_variables(addr));
    }, py::arg("addr"),
       "List all register variables defined for a function.");

    // ── Address enumeration ─────────────────────────────────────────────

    m.def("item_addresses", [](ida::Address addr) {
        return unwrap(fn::item_addresses(addr));
    }, py::arg("addr"),
       "Enumerate all item head addresses in the function body.");

    m.def("code_addresses", [](ida::Address addr) {
        return unwrap(fn::code_addresses(addr));
    }, py::arg("addr"),
       "Enumerate only code item addresses in the function body.");

    // ── Traversal ───────────────────────────────────────────────────────

    m.def("all", []() {
        std::size_t n = unwrap(fn::count());
        py::list result;
        for (std::size_t i = 0; i < n; ++i) {
            result.append(unwrap(fn::by_index(i)));
        }
        return result;
    }, "List of all functions.");
}
