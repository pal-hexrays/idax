/// \file instruction_bind.cpp
/// \brief pybind11 bindings for ida::instruction — decode, operand access,
///        operand formatting, cross-reference queries, instruction classification.

#include "helpers.hpp"
#include <ida/instruction.hpp>

namespace insn = ida::instruction;

void init_instruction(py::module_& parent) {
    auto m = parent.def_submodule("instruction",
        "Instruction decode, operand access, formatting, and classification.");

    // ── Enums ───────────────────────────────────────────────────────────

    py::enum_<insn::OperandType>(m, "OperandType")
        .value("none",                 insn::OperandType::None)
        .value("register_",           insn::OperandType::Register)
        .value("memory_direct",       insn::OperandType::MemoryDirect)
        .value("memory_phrase",       insn::OperandType::MemoryPhrase)
        .value("memory_displacement", insn::OperandType::MemoryDisplacement)
        .value("immediate",           insn::OperandType::Immediate)
        .value("far_address",         insn::OperandType::FarAddress)
        .value("near_address",        insn::OperandType::NearAddress)
        .value("processor_specific_0", insn::OperandType::ProcessorSpecific0)
        .value("processor_specific_1", insn::OperandType::ProcessorSpecific1)
        .value("processor_specific_2", insn::OperandType::ProcessorSpecific2)
        .value("processor_specific_3", insn::OperandType::ProcessorSpecific3)
        .value("processor_specific_4", insn::OperandType::ProcessorSpecific4)
        .value("processor_specific_5", insn::OperandType::ProcessorSpecific5);

    py::enum_<insn::RegisterCategory>(m, "RegisterCategory")
        .value("unknown",         insn::RegisterCategory::Unknown)
        .value("general_purpose", insn::RegisterCategory::GeneralPurpose)
        .value("segment",         insn::RegisterCategory::Segment)
        .value("floating_point",  insn::RegisterCategory::FloatingPoint)
        .value("vector",          insn::RegisterCategory::Vector)
        .value("mask",            insn::RegisterCategory::Mask)
        .value("control",         insn::RegisterCategory::Control)
        .value("debug",           insn::RegisterCategory::Debug)
        .value("other",           insn::RegisterCategory::Other);

    py::enum_<insn::OperandFormat>(m, "OperandFormat")
        .value("default_",       insn::OperandFormat::Default)
        .value("hex",            insn::OperandFormat::Hex)
        .value("decimal",        insn::OperandFormat::Decimal)
        .value("octal",          insn::OperandFormat::Octal)
        .value("binary",         insn::OperandFormat::Binary)
        .value("character",      insn::OperandFormat::Character)
        .value("float_",         insn::OperandFormat::Float)
        .value("offset",         insn::OperandFormat::Offset)
        .value("stack_variable", insn::OperandFormat::StackVariable);

    // ── Value types ─────────────────────────────────────────────────────

    py::class_<insn::Operand>(m, "Operand")
        .def_property_readonly("index",             &insn::Operand::index)
        .def_property_readonly("type",              &insn::Operand::type)
        .def_property_readonly("is_register",       &insn::Operand::is_register)
        .def_property_readonly("is_immediate",      &insn::Operand::is_immediate)
        .def_property_readonly("is_memory",         &insn::Operand::is_memory)
        .def_property_readonly("register_id",       &insn::Operand::register_id)
        .def_property_readonly("value",             &insn::Operand::value)
        .def_property_readonly("target_address",    &insn::Operand::target_address)
        .def_property_readonly("displacement",      &insn::Operand::displacement)
        .def_property_readonly("byte_width",        &insn::Operand::byte_width)
        .def_property_readonly("register_name",     &insn::Operand::register_name)
        .def_property_readonly("register_category", &insn::Operand::register_category)
        .def("__repr__", [](const insn::Operand& op) {
            return "<Operand index=" + std::to_string(op.index()) +
                   " width=" + std::to_string(op.byte_width()) + ">";
        });

    py::class_<insn::Instruction>(m, "Instruction")
        .def_property_readonly("address",       &insn::Instruction::address)
        .def_property_readonly("size",          &insn::Instruction::size)
        .def_property_readonly("opcode",        &insn::Instruction::opcode)
        .def_property_readonly("mnemonic",      &insn::Instruction::mnemonic)
        .def_property_readonly("operand_count", &insn::Instruction::operand_count)
        .def_property_readonly("operands",      &insn::Instruction::operands)
        .def("operand", [](const insn::Instruction& i, std::size_t index) {
            return unwrap(i.operand(index));
        }, py::arg("index"),
           "Get operand by index.")
        .def("__repr__", [](const insn::Instruction& i) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "<Instruction '%s' at 0x%llx>",
                          i.mnemonic().c_str(),
                          static_cast<unsigned long long>(i.address()));
            return std::string(buf);
        });

    py::class_<insn::StructOffsetPath>(m, "StructOffsetPath")
        .def_readonly("structure_ids", &insn::StructOffsetPath::structure_ids)
        .def_readonly("delta",         &insn::StructOffsetPath::delta);

    // ── Decode / create ─────────────────────────────────────────────────

    m.def("decode", [](ida::Address addr) {
        return unwrap(insn::decode(addr));
    }, py::arg("address"),
       "Decode an instruction without modifying the database.");

    m.def("create", [](ida::Address addr) {
        return unwrap(insn::create(addr));
    }, py::arg("address"),
       "Create an instruction in the database (marks bytes as code).");

    m.def("text", [](ida::Address addr) {
        return unwrap(insn::text(addr));
    }, py::arg("address"),
       "Get the rendered disassembly text at an address.");

    // ── Operand format setters ──────────────────────────────────────────

    m.def("set_operand_hex", [](ida::Address addr, int n) {
        check_status(insn::set_operand_hex(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand display format to hexadecimal.");

    m.def("set_operand_decimal", [](ida::Address addr, int n) {
        check_status(insn::set_operand_decimal(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand display format to decimal.");

    m.def("set_operand_octal", [](ida::Address addr, int n) {
        check_status(insn::set_operand_octal(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand display format to octal.");

    m.def("set_operand_binary", [](ida::Address addr, int n) {
        check_status(insn::set_operand_binary(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand display format to binary.");

    m.def("set_operand_character", [](ida::Address addr, int n) {
        check_status(insn::set_operand_character(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand display format to character constant.");

    m.def("set_operand_float", [](ida::Address addr, int n) {
        check_status(insn::set_operand_float(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand display format to floating point.");

    m.def("set_operand_format", [](ida::Address addr, int n,
                                   insn::OperandFormat format,
                                   ida::Address base) {
        check_status(insn::set_operand_format(addr, n, format, base));
    }, py::arg("address"), py::arg("n") = 0,
       py::arg("format") = insn::OperandFormat::Default,
       py::arg("base") = 0,
       "Generic operand format setter.");

    m.def("set_operand_offset", [](ida::Address addr, int n, ida::Address base) {
        check_status(insn::set_operand_offset(addr, n, base));
    }, py::arg("address"), py::arg("n") = 0, py::arg("base") = 0,
       "Set operand as an offset reference.");

    // ── Struct offset operations ────────────────────────────────────────

    m.def("set_operand_struct_offset",
        [](ida::Address addr, int n, const py::object& struct_name_or_id,
           ida::AddressDelta delta) {
            if (py::isinstance<py::str>(struct_name_or_id)) {
                auto name = struct_name_or_id.cast<std::string>();
                check_status(insn::set_operand_struct_offset(addr, n, name, delta));
            } else {
                auto id = struct_name_or_id.cast<std::uint64_t>();
                check_status(insn::set_operand_struct_offset(addr, n, id, delta));
            }
        },
        py::arg("address"), py::arg("n"), py::arg("struct_name_or_id"),
        py::arg("delta") = 0,
        "Set operand to display as a structure member offset (by name or id).");

    m.def("set_operand_based_struct_offset",
        [](ida::Address addr, int n, ida::Address operand_value, ida::Address base) {
            check_status(insn::set_operand_based_struct_offset(addr, n, operand_value, base));
        },
        py::arg("address"), py::arg("n"),
        py::arg("operand_value"), py::arg("base"),
        "Set operand representation as a structure offset using an explicit base.");

    m.def("operand_struct_offset_path", [](ida::Address addr, int n) {
        return unwrap(insn::operand_struct_offset_path(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Read struct-offset path metadata for an operand.");

    m.def("operand_struct_offset_path_names", [](ida::Address addr, int n) {
        return unwrap(insn::operand_struct_offset_path_names(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Read struct-offset path metadata as resolved type names.");

    // ── Stack variable / clear / forced ─────────────────────────────────

    m.def("set_operand_stack_variable", [](ida::Address addr, int n) {
        check_status(insn::set_operand_stack_variable(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Set operand to display as a stack variable.");

    m.def("clear_operand_representation", [](ida::Address addr, int n) {
        check_status(insn::clear_operand_representation(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Clear operand representation (reset to default).");

    m.def("set_forced_operand", [](ida::Address addr, int n,
                                   const std::string& text) {
        check_status(insn::set_forced_operand(addr, n, text));
    }, py::arg("address"), py::arg("n"), py::arg("text"),
       "Set or clear forced (manual) operand text.");

    m.def("get_forced_operand", [](ida::Address addr, int n) {
        return unwrap(insn::get_forced_operand(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Retrieve forced (manual) operand text, if any.");

    // ── Operand queries ─────────────────────────────────────────────────

    m.def("operand_text", [](ida::Address addr, int n) {
        return unwrap(insn::operand_text(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Render only the operand text for operand index n.");

    m.def("operand_byte_width", [](ida::Address addr, int n) {
        return unwrap(insn::operand_byte_width(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Structured byte-width query for operand index n.");

    m.def("operand_register_name", [](ida::Address addr, int n) {
        return unwrap(insn::operand_register_name(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Register name for operand index n.");

    m.def("operand_register_category", [](ida::Address addr, int n) {
        return unwrap(insn::operand_register_category(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Register classification for operand index n.");

    // ── Operand display toggles ─────────────────────────────────────────

    m.def("toggle_operand_sign", [](ida::Address addr, int n) {
        check_status(insn::toggle_operand_sign(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Toggle sign inversion on operand display.");

    m.def("toggle_operand_negate", [](ida::Address addr, int n) {
        check_status(insn::toggle_operand_negate(addr, n));
    }, py::arg("address"), py::arg("n") = 0,
       "Toggle bitwise negation on operand display.");

    // ── Cross-references ────────────────────────────────────────────────

    m.def("code_refs_from", [](ida::Address addr) {
        return unwrap(insn::code_refs_from(addr));
    }, py::arg("address"),
       "Code cross-references originating from the instruction.");

    m.def("data_refs_from", [](ida::Address addr) {
        return unwrap(insn::data_refs_from(addr));
    }, py::arg("address"),
       "Data cross-references originating from the instruction.");

    m.def("call_targets", [](ida::Address addr) {
        return unwrap(insn::call_targets(addr));
    }, py::arg("address"),
       "All call targets from the instruction.");

    m.def("jump_targets", [](ida::Address addr) {
        return unwrap(insn::jump_targets(addr));
    }, py::arg("address"),
       "All jump targets from the instruction.");

    // ── Classification predicates ───────────────────────────────────────

    m.def("has_fall_through", [](ida::Address addr) {
        return insn::has_fall_through(addr);
    }, py::arg("address"),
       "Does the instruction have fall-through to the next instruction?");

    m.def("is_call", [](ida::Address addr) {
        return insn::is_call(addr);
    }, py::arg("address"),
       "Is the instruction a call instruction?");

    m.def("is_return", [](ida::Address addr) {
        return insn::is_return(addr);
    }, py::arg("address"),
       "Is the instruction a return instruction?");

    m.def("is_jump", [](ida::Address addr) {
        return insn::is_jump(addr);
    }, py::arg("address"),
       "Is the instruction any jump instruction?");

    m.def("is_conditional_jump", [](ida::Address addr) {
        return insn::is_conditional_jump(addr);
    }, py::arg("address"),
       "Is the instruction a conditional jump instruction?");

    // ── Sequential navigation ───────────────────────────────────────────

    m.def("next", [](ida::Address addr) {
        return unwrap(insn::next(addr));
    }, py::arg("address"),
       "Decode the next instruction sequentially after address.");

    m.def("prev", [](ida::Address addr) {
        return unwrap(insn::prev(addr));
    }, py::arg("address"),
       "Decode the previous instruction before address.");
}
