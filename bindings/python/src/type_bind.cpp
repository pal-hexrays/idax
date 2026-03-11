/// \file type_bind.cpp
/// \brief pybind11 bindings for ida::type — type construction, introspection,
///        and application (TypeInfo class).
///
/// The Python submodule is called `types` (not `type`) to avoid collision
/// with the Python builtin.

#include "helpers.hpp"
#include <ida/type.hpp>

namespace ty = ida::type;

void init_types(py::module_& parent) {
    auto m = parent.def_submodule("types",
        "Type system: construction, introspection, and application.");

    // ── CallingConvention enum ───────────────────────────────────────────

    py::enum_<ty::CallingConvention>(m, "CallingConvention")
        .value("unknown",       ty::CallingConvention::Unknown)
        .value("cdecl_",        ty::CallingConvention::Cdecl)
        .value("stdcall",       ty::CallingConvention::Stdcall)
        .value("pascal_",       ty::CallingConvention::Pascal)
        .value("fastcall",      ty::CallingConvention::Fastcall)
        .value("thiscall",      ty::CallingConvention::Thiscall)
        .value("swift",         ty::CallingConvention::Swift)
        .value("golang",        ty::CallingConvention::Golang)
        .value("user_defined",  ty::CallingConvention::UserDefined);

    // ── TypeInfo class ──────────────────────────────────────────────────
    // Registered before Member so that Member.type can reference it.

    py::class_<ty::TypeInfo>(m, "TypeInfo")
        // ── Predicates ──────────────────────────────────────────────────
        .def("is_void",           &ty::TypeInfo::is_void)
        .def("is_integer",        &ty::TypeInfo::is_integer)
        .def("is_floating_point", &ty::TypeInfo::is_floating_point)
        .def("is_pointer",        &ty::TypeInfo::is_pointer)
        .def("is_array",          &ty::TypeInfo::is_array)
        .def("is_function",       &ty::TypeInfo::is_function)
        .def("is_struct",         &ty::TypeInfo::is_struct)
        .def("is_union",          &ty::TypeInfo::is_union)
        .def("is_enum",           &ty::TypeInfo::is_enum)
        .def("is_typedef",        &ty::TypeInfo::is_typedef)

        // ── Introspection ───────────────────────────────────────────────
        .def("size", [](const ty::TypeInfo& self) {
            return unwrap(self.size());
        }, "Size of the type in bytes.")

        .def("__str__", [](const ty::TypeInfo& self) {
            return unwrap(self.to_string());
        })

        .def("__repr__", [](const ty::TypeInfo& self) {
            auto s = self.to_string();
            if (s) return "<TypeInfo '" + *s + "'>";
            return std::string("<TypeInfo>");
        })

        // ── Navigation ──────────────────────────────────────────────────
        .def("pointee_type", [](const ty::TypeInfo& self) {
            return unwrap(self.pointee_type());
        }, "For pointer types, return the pointee type.",
           py::return_value_policy::move)

        .def("array_element_type", [](const ty::TypeInfo& self) {
            return unwrap(self.array_element_type());
        }, "For array types, return the element type.",
           py::return_value_policy::move)

        .def("array_length", [](const ty::TypeInfo& self) {
            return unwrap(self.array_length());
        }, "For array types, return the number of elements.")

        .def("resolve_typedef", [](const ty::TypeInfo& self) {
            return unwrap(self.resolve_typedef());
        }, "Resolve typedef links to the final target type.",
           py::return_value_policy::move)

        // ── Function info ───────────────────────────────────────────────
        .def("function_return_type", [](const ty::TypeInfo& self) {
            return unwrap(self.function_return_type());
        }, "Return type of a function type.",
           py::return_value_policy::move)

        .def("function_argument_types", [](const ty::TypeInfo& self) {
            return unwrap(self.function_argument_types());
        }, "Argument types of a function type.")

        .def("calling_convention", [](const ty::TypeInfo& self) {
            return unwrap(self.calling_convention());
        }, "Calling convention of a function type.")

        .def("is_variadic_function", [](const ty::TypeInfo& self) {
            return unwrap(self.is_variadic_function());
        }, "Whether the function type has variadic arguments.")

        // ── Enum ────────────────────────────────────────────────────────
        .def("enum_members", [](const ty::TypeInfo& self) {
            return unwrap(self.enum_members());
        }, "Members of an enum type.")

        // ── Struct/union ────────────────────────────────────────────────
        .def("member_count", [](const ty::TypeInfo& self) {
            return unwrap(self.member_count());
        }, "Number of struct/union members.")

        .def("members", [](const ty::TypeInfo& self) {
            return unwrap(self.members());
        }, "All members of a struct/union type.")

        .def("member_by_name", [](const ty::TypeInfo& self,
                                   const std::string& name) {
            return unwrap(self.member_by_name(name));
        }, py::arg("name"),
           "Find a struct/union member by name.")

        .def("member_by_offset", [](const ty::TypeInfo& self,
                                     std::size_t offset) {
            return unwrap(self.member_by_offset(offset));
        }, py::arg("offset"),
           "Find a struct/union member by byte offset.")

        .def("add_member", [](ty::TypeInfo& self,
                               const std::string& name,
                               const ty::TypeInfo& member_type,
                               std::size_t byte_offset) {
            check_status(self.add_member(name, member_type, byte_offset));
        }, py::arg("name"), py::arg("type"),
           py::arg("byte_offset") = 0,
           "Add a member to this struct/union type.")

        // ── Application ─────────────────────────────────────────────────
        .def("apply", [](const ty::TypeInfo& self, ida::Address addr) {
            check_status(self.apply(addr));
        }, py::arg("addr"),
           "Apply this type at the given address.")

        .def("save_as", [](const ty::TypeInfo& self,
                            const std::string& name) {
            check_status(self.save_as(name));
        }, py::arg("name"),
           "Save this type to the local type library under the given name.");

    // ── EnumMember value type ───────────────────────────────────────────

    py::class_<ty::EnumMember>(m, "EnumMember")
        .def_readonly("name",    &ty::EnumMember::name)
        .def_readonly("value",   &ty::EnumMember::value)
        .def_readonly("comment", &ty::EnumMember::comment)
        .def("__repr__", [](const ty::EnumMember& em) {
            return "<EnumMember '" + em.name + "' = " +
                   std::to_string(em.value) + ">";
        });

    // ── Member value type ───────────────────────────────────────────────

    py::class_<ty::Member>(m, "Member")
        .def_readonly("name",        &ty::Member::name)
        .def_readonly("type",        &ty::Member::type)
        .def_readonly("byte_offset", &ty::Member::byte_offset)
        .def_readonly("bit_size",    &ty::Member::bit_size)
        .def_readonly("comment",     &ty::Member::comment)
        .def("__repr__", [](const ty::Member& mem) {
            return "<Member '" + mem.name + "' offset=" +
                   std::to_string(mem.byte_offset) + ">";
        });

    // ═════════════════════════════════════════════════════════════════════
    // Factory functions — primitive types
    // ═════════════════════════════════════════════════════════════════════

    m.def("void_type", &ty::TypeInfo::void_type,
          "Create a void type.",
          py::return_value_policy::move);
    m.def("int8",    &ty::TypeInfo::int8,    "Create a signed 8-bit integer type.",  py::return_value_policy::move);
    m.def("int16",   &ty::TypeInfo::int16,   "Create a signed 16-bit integer type.", py::return_value_policy::move);
    m.def("int32",   &ty::TypeInfo::int32,   "Create a signed 32-bit integer type.", py::return_value_policy::move);
    m.def("int64",   &ty::TypeInfo::int64,   "Create a signed 64-bit integer type.", py::return_value_policy::move);
    m.def("uint8",   &ty::TypeInfo::uint8,   "Create an unsigned 8-bit integer type.",  py::return_value_policy::move);
    m.def("uint16",  &ty::TypeInfo::uint16,  "Create an unsigned 16-bit integer type.", py::return_value_policy::move);
    m.def("uint32",  &ty::TypeInfo::uint32,  "Create an unsigned 32-bit integer type.", py::return_value_policy::move);
    m.def("uint64",  &ty::TypeInfo::uint64,  "Create an unsigned 64-bit integer type.", py::return_value_policy::move);
    m.def("float32", &ty::TypeInfo::float32, "Create a 32-bit floating point type.",    py::return_value_policy::move);
    m.def("float64", &ty::TypeInfo::float64, "Create a 64-bit floating point type.",    py::return_value_policy::move);

    // ── Composite type factories ────────────────────────────────────────

    m.def("pointer_to", &ty::TypeInfo::pointer_to,
          py::arg("target"),
          "Create a pointer type to the given target type.",
          py::return_value_policy::move);

    m.def("array_of", &ty::TypeInfo::array_of,
          py::arg("element"), py::arg("count"),
          "Create an array type of the given element type and count.",
          py::return_value_policy::move);

    m.def("function_type", [](const ty::TypeInfo& return_type,
                               const std::vector<ty::TypeInfo>& arg_types,
                               ty::CallingConvention convention,
                               bool variadic) {
        return unwrap(ty::TypeInfo::function_type(return_type, arg_types,
                                                   convention, variadic));
    }, py::arg("return_type"),
       py::arg("arg_types") = std::vector<ty::TypeInfo>{},
       py::arg("convention") = ty::CallingConvention::Unknown,
       py::arg("variadic") = false,
       "Create a function type.",
       py::return_value_policy::move);

    m.def("from_declaration", [](const std::string& decl) {
        return unwrap(ty::TypeInfo::from_declaration(decl));
    }, py::arg("decl"),
       "Create a type from a C declaration string.",
       py::return_value_policy::move);

    m.def("create_struct", &ty::TypeInfo::create_struct,
          "Create an empty struct type.",
          py::return_value_policy::move);

    m.def("create_union", &ty::TypeInfo::create_union,
          "Create an empty union type.",
          py::return_value_policy::move);

    m.def("by_name", [](const std::string& name) {
        return unwrap(ty::TypeInfo::by_name(name));
    }, py::arg("name"),
       "Look up a named type in the local type library.",
       py::return_value_policy::move);

    // ═════════════════════════════════════════════════════════════════════
    // Free functions — retrieval, removal
    // ═════════════════════════════════════════════════════════════════════

    m.def("retrieve", [](ida::Address addr) {
        return unwrap(ty::retrieve(addr));
    }, py::arg("addr"),
       "Retrieve the type applied at an address.",
       py::return_value_policy::move);

    m.def("retrieve_operand", [](ida::Address addr, int operand_index) {
        return unwrap(ty::retrieve_operand(addr, operand_index));
    }, py::arg("addr"), py::arg("operand_index"),
       "Retrieve the type of an operand at an address.",
       py::return_value_policy::move);

    m.def("remove_type", [](ida::Address addr) {
        check_status(ty::remove_type(addr));
    }, py::arg("addr"),
       "Remove type information at an address.");

    // ═════════════════════════════════════════════════════════════════════
    // Type library operations
    // ═════════════════════════════════════════════════════════════════════

    m.def("load_type_library", [](const std::string& name) {
        return unwrap(ty::load_type_library(name));
    }, py::arg("name"),
       "Load a type library (.til file) by name.");

    m.def("unload_type_library", [](const std::string& name) {
        check_status(ty::unload_type_library(name));
    }, py::arg("name"),
       "Unload a previously loaded type library.");

    m.def("local_type_count", []() {
        return unwrap(ty::local_type_count());
    }, "Get the number of local types in the database.");

    m.def("local_type_name", [](std::size_t ordinal) {
        return unwrap(ty::local_type_name(ordinal));
    }, py::arg("ordinal"),
       "Get the name of a local type by ordinal (1-based).");

    m.def("import_type", [](const std::string& source_til,
                             const std::string& type_name) {
        return unwrap(ty::import_type(source_til, type_name));
    }, py::arg("library"), py::arg("name"),
       "Import a named type from a loaded type library to the local type library.");

    m.def("ensure_named_type", [](const std::string& type_name,
                                   const std::string& source_til) {
        return unwrap(ty::ensure_named_type(type_name, source_til));
    }, py::arg("name"), py::arg("declaration") = "",
       "Ensure a named type exists in the local type library and return it.",
       py::return_value_policy::move);

    m.def("apply_named_type", [](ida::Address addr,
                                  const std::string& type_name) {
        check_status(ty::apply_named_type(addr, type_name));
    }, py::arg("addr"), py::arg("name"),
       "Apply a named type from the local type library at an address.");
}
