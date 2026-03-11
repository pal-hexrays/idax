/// \file decompiler_bind.cpp
/// \brief pybind11 bindings for ida::decompiler — Hex-Rays decompilation,
///        pseudocode access, variable manipulation, address mapping,
///        microcode filter callbacks, and event subscriptions.

#include "helpers.hpp"
#include <ida/decompiler.hpp>
#include <ida/instruction.hpp>
#include <ida/type.hpp>

#include <memory>
#include <mutex>
#include <unordered_map>

namespace decomp = ida::decompiler;

namespace {

// ── Microcode enum -> string helpers ────────────────────────────────────

static const char* microcode_opcode_to_string(decomp::MicrocodeOpcode opcode) {
    switch (opcode) {
        case decomp::MicrocodeOpcode::NoOperation:          return "no_operation";
        case decomp::MicrocodeOpcode::Move:                 return "move";
        case decomp::MicrocodeOpcode::Add:                  return "add";
        case decomp::MicrocodeOpcode::Subtract:             return "subtract";
        case decomp::MicrocodeOpcode::Multiply:             return "multiply";
        case decomp::MicrocodeOpcode::ZeroExtend:           return "zero_extend";
        case decomp::MicrocodeOpcode::LoadMemory:           return "load_memory";
        case decomp::MicrocodeOpcode::StoreMemory:          return "store_memory";
        case decomp::MicrocodeOpcode::BitwiseOr:            return "bitwise_or";
        case decomp::MicrocodeOpcode::BitwiseAnd:           return "bitwise_and";
        case decomp::MicrocodeOpcode::BitwiseXor:           return "bitwise_xor";
        case decomp::MicrocodeOpcode::ShiftLeft:            return "shift_left";
        case decomp::MicrocodeOpcode::ShiftRightLogical:    return "shift_right_logical";
        case decomp::MicrocodeOpcode::ShiftRightArithmetic: return "shift_right_arithmetic";
        case decomp::MicrocodeOpcode::FloatAdd:             return "float_add";
        case decomp::MicrocodeOpcode::FloatSub:             return "float_sub";
        case decomp::MicrocodeOpcode::FloatMul:             return "float_mul";
        case decomp::MicrocodeOpcode::FloatDiv:             return "float_div";
        case decomp::MicrocodeOpcode::IntegerToFloat:       return "integer_to_float";
        case decomp::MicrocodeOpcode::FloatToFloat:         return "float_to_float";
    }
    return "unknown";
}

static const char* microcode_operand_kind_to_string(decomp::MicrocodeOperandKind kind) {
    switch (kind) {
        case decomp::MicrocodeOperandKind::Empty:             return "empty";
        case decomp::MicrocodeOperandKind::Register:          return "register";
        case decomp::MicrocodeOperandKind::LocalVariable:     return "local_variable";
        case decomp::MicrocodeOperandKind::RegisterPair:      return "register_pair";
        case decomp::MicrocodeOperandKind::GlobalAddress:     return "global_address";
        case decomp::MicrocodeOperandKind::StackVariable:     return "stack_variable";
        case decomp::MicrocodeOperandKind::HelperReference:   return "helper_reference";
        case decomp::MicrocodeOperandKind::BlockReference:    return "block_reference";
        case decomp::MicrocodeOperandKind::NestedInstruction: return "nested_instruction";
        case decomp::MicrocodeOperandKind::UnsignedImmediate: return "unsigned_immediate";
        case decomp::MicrocodeOperandKind::SignedImmediate:   return "signed_immediate";
    }
    return "unknown";
}

// ── VariableStorage enum -> string ──────────────────────────────────────

static const char* variable_storage_to_string(decomp::VariableStorage storage) {
    switch (storage) {
        case decomp::VariableStorage::Unknown:  return "unknown";
        case decomp::VariableStorage::Register: return "register";
        case decomp::VariableStorage::Stack:    return "stack";
    }
    return "unknown";
}

// ── Microcode structs -> Python dicts ───────────────────────────────────

static py::dict microcode_instruction_to_dict(const decomp::MicrocodeInstruction& instruction);

static py::dict microcode_operand_to_dict(const decomp::MicrocodeOperand& operand) {
    py::dict d;
    d["kind"]                   = microcode_operand_kind_to_string(operand.kind);
    d["register_id"]            = operand.register_id;
    d["local_variable_index"]   = operand.local_variable_index;
    d["local_variable_offset"]  = operand.local_variable_offset;
    d["second_register_id"]     = operand.second_register_id;
    d["global_address"]         = operand.global_address;
    d["stack_offset"]           = operand.stack_offset;
    d["helper_name"]            = operand.helper_name;
    d["block_index"]            = operand.block_index;
    d["unsigned_immediate"]     = operand.unsigned_immediate;
    d["signed_immediate"]       = operand.signed_immediate;
    d["byte_width"]             = operand.byte_width;
    d["mark_user_defined_type"] = operand.mark_user_defined_type;

    if (operand.nested_instruction != nullptr)
        d["nested_instruction"] = microcode_instruction_to_dict(*operand.nested_instruction);
    else
        d["nested_instruction"] = py::none();

    return d;
}

static py::dict microcode_instruction_to_dict(const decomp::MicrocodeInstruction& instruction) {
    py::dict d;
    d["opcode"]                     = microcode_opcode_to_string(instruction.opcode);
    d["left"]                       = microcode_operand_to_dict(instruction.left);
    d["right"]                      = microcode_operand_to_dict(instruction.right);
    d["destination"]                = microcode_operand_to_dict(instruction.destination);
    d["floating_point_instruction"] = instruction.floating_point_instruction;
    return d;
}

// ── LocalVariable -> Python dict ────────────────────────────────────────

static py::dict local_variable_to_dict(const decomp::LocalVariable& var) {
    py::dict d;
    d["name"]          = var.name;
    d["type_name"]     = var.type_name;
    d["is_argument"]   = var.is_argument;
    d["width"]         = var.width;
    d["has_user_name"] = var.has_user_name;
    d["has_nice_name"] = var.has_nice_name;
    d["storage"]       = variable_storage_to_string(var.storage);
    d["comment"]       = var.comment;
    return d;
}

// ── AddressMapping -> Python dict ───────────────────────────────────────

static py::dict address_mapping_to_dict(const decomp::AddressMapping& m) {
    py::dict d;
    d["address"]     = m.address;
    d["line_number"] = m.line_number;
    return d;
}

// ── Native Instruction -> Python dict (for MicrocodeContext::instruction) ─

static py::dict native_instruction_to_dict(const ida::instruction::Instruction& insn) {
    py::list operands;
    for (std::size_t i = 0; i < insn.operand_count(); ++i) {
        py::dict op;
        const auto& operand = insn.operands()[i];
        op["index"]             = operand.index();
        op["is_register"]       = operand.is_register();
        op["is_immediate"]      = operand.is_immediate();
        op["is_memory"]         = operand.is_memory();
        op["register_id"]       = static_cast<int>(operand.register_id());
        op["value"]             = operand.value();
        op["target_address"]    = operand.target_address();
        op["displacement"]      = operand.displacement();
        op["byte_width"]        = operand.byte_width();
        op["register_name"]     = operand.register_name();
        operands.append(op);
    }

    py::dict d;
    d["address"]       = insn.address();
    d["size"]          = insn.size();
    d["opcode"]        = static_cast<int>(insn.opcode());
    d["mnemonic"]      = insn.mnemonic();
    d["operand_count"] = static_cast<int>(insn.operand_count());
    d["operands"]      = operands;
    return d;
}

// ── Microcode filter storage ────────────────────────────────────────────

static std::mutex g_microcode_filters_mutex;
static std::unordered_map<decomp::FilterToken,
                          std::shared_ptr<decomp::MicrocodeFilter>>
    g_microcode_filters;

static void store_microcode_filter(decomp::FilterToken token,
                                   std::shared_ptr<decomp::MicrocodeFilter> filter) {
    std::lock_guard<std::mutex> lock(g_microcode_filters_mutex);
    g_microcode_filters[token] = std::move(filter);
}

static void remove_microcode_filter(decomp::FilterToken token) {
    std::lock_guard<std::mutex> lock(g_microcode_filters_mutex);
    g_microcode_filters.erase(token);
}

// ── Python microcode filter ─────────────────────────────────────────────

class PyMicrocodeFilter final : public decomp::MicrocodeFilter {
public:
    PyMicrocodeFilter(py::function match_fn, py::function apply_fn)
        : match_fn_(std::make_shared<py::function>(std::move(match_fn)))
        , apply_fn_(std::make_shared<py::function>(std::move(apply_fn))) {}

    bool match(const decomp::MicrocodeContext& context) override {
        py::gil_scoped_acquire gil;
        try {
            py::dict ctx_dict = build_context_dict(context);
            py::object result = (*match_fn_)(ctx_dict);
            return result.cast<bool>();
        } catch (py::error_already_set& e) {
            e.restore();
            return false;
        }
    }

    decomp::MicrocodeApplyResult apply(decomp::MicrocodeContext& context) override {
        py::gil_scoped_acquire gil;
        try {
            py::dict ctx_dict = build_context_dict(context);
            py::object result = (*apply_fn_)(ctx_dict);
            return parse_apply_result(result);
        } catch (py::error_already_set& e) {
            e.restore();
            return decomp::MicrocodeApplyResult::Error;
        }
    }

private:
    static py::dict build_context_dict(const decomp::MicrocodeContext& context) {
        py::dict d;
        d["address"]          = context.address();
        d["instruction_type"] = context.instruction_type();

        auto block_count = context.block_instruction_count();
        if (block_count)
            d["block_instruction_count"] = *block_count;
        else
            d["block_instruction_count"] = py::none();

        auto insn = context.instruction();
        if (insn)
            d["instruction"] = native_instruction_to_dict(*insn);
        else
            d["instruction"] = py::none();

        auto has_last = context.has_last_emitted_instruction();
        if (has_last && *has_last) {
            auto last = context.last_emitted_instruction();
            if (last)
                d["last_emitted_instruction"] = microcode_instruction_to_dict(*last);
            else
                d["last_emitted_instruction"] = py::none();
        } else {
            d["last_emitted_instruction"] = py::none();
        }

        return d;
    }

    static decomp::MicrocodeApplyResult parse_apply_result(const py::object& value) {
        if (py::isinstance<py::str>(value)) {
            auto text = value.cast<std::string>();
            if (text == "handled")
                return decomp::MicrocodeApplyResult::Handled;
            if (text == "error")
                return decomp::MicrocodeApplyResult::Error;
            return decomp::MicrocodeApplyResult::NotHandled;
        }

        if (py::isinstance<py::int_>(value)) {
            int code = value.cast<int>();
            switch (code) {
                case 1:  return decomp::MicrocodeApplyResult::Handled;
                case 2:  return decomp::MicrocodeApplyResult::Error;
                default: return decomp::MicrocodeApplyResult::NotHandled;
            }
        }

        if (py::isinstance<py::bool_>(value)) {
            return value.cast<bool>()
                ? decomp::MicrocodeApplyResult::Handled
                : decomp::MicrocodeApplyResult::NotHandled;
        }

        return decomp::MicrocodeApplyResult::NotHandled;
    }

    std::shared_ptr<py::function> match_fn_;
    std::shared_ptr<py::function> apply_fn_;
};

} // anonymous namespace

void init_decompiler(py::module_& parent) {
    auto m = parent.def_submodule("decompiler",
        "Hex-Rays decompilation, pseudocode access, variable manipulation, "
        "address mapping, microcode filters, and event subscriptions.");

    // ── VariableStorage enum ────────────────────────────────────────────

    py::enum_<decomp::VariableStorage>(m, "VariableStorage")
        .value("unknown",   decomp::VariableStorage::Unknown)
        .value("register_", decomp::VariableStorage::Register)
        .value("stack",     decomp::VariableStorage::Stack);

    // ── DecompiledFunction class ────────────────────────────────────────

    py::class_<decomp::DecompiledFunction>(m, "DecompiledFunction")
        .def("pseudocode", [](const decomp::DecompiledFunction& self) {
            return unwrap(self.pseudocode());
        }, "Get the full pseudocode as a single string.")

        .def("lines", [](const decomp::DecompiledFunction& self) {
            return unwrap(self.lines());
        }, "Get pseudocode as individual lines (color codes stripped).")

        .def("raw_lines", [](const decomp::DecompiledFunction& self) {
            return unwrap(self.raw_lines());
        }, "Get raw pseudocode lines with IDA color tags preserved.")

        .def("declaration", [](const decomp::DecompiledFunction& self) {
            return unwrap(self.declaration());
        }, "Get the function prototype/declaration line.")

        .def("variable_count", [](const decomp::DecompiledFunction& self) {
            return unwrap(self.variable_count());
        }, "Number of local variables (including arguments).")

        .def("variables", [](const decomp::DecompiledFunction& self) {
            auto vars = unwrap(self.variables());
            py::list result;
            for (const auto& var : vars)
                result.append(local_variable_to_dict(var));
            return result;
        }, "Get all local variables as list of dicts.")

        .def("rename_variable", [](decomp::DecompiledFunction& self,
                                   const std::string& old_name,
                                   const std::string& new_name) {
            check_status(self.rename_variable(old_name, new_name));
        }, py::arg("old_name"), py::arg("new_name"),
           "Rename a local variable (persistent).")

        .def("retype_variable", [](decomp::DecompiledFunction& self,
                                   const py::object& name_or_index,
                                   const std::string& new_type) {
            auto type_result = ida::type::TypeInfo::from_declaration(new_type);
            if (!type_result)
                throw_idax_error(type_result.error());

            if (py::isinstance<py::str>(name_or_index)) {
                auto name = name_or_index.cast<std::string>();
                check_status(self.retype_variable(name, *type_result));
            } else if (py::isinstance<py::int_>(name_or_index)) {
                auto index = name_or_index.cast<std::size_t>();
                check_status(self.retype_variable(index, *type_result));
            } else {
                throw py::type_error("First argument must be a variable name (str) or index (int)");
            }
        }, py::arg("name_or_index"), py::arg("new_type"),
           "Retype a local variable by name or index. Call refresh() after.")

        .def("entry_address", [](const decomp::DecompiledFunction& self) {
            return self.entry_address();
        }, "Get the entry address of the decompiled function.")

        .def("line_to_address", [](const decomp::DecompiledFunction& self, int line) {
            return unwrap(self.line_to_address(line));
        }, py::arg("line"),
           "Map a pseudocode line number (0-based) to a binary address.")

        .def("address_map", [](const decomp::DecompiledFunction& self) {
            auto mappings = unwrap(self.address_map());
            py::list result;
            for (const auto& mapping : mappings)
                result.append(address_mapping_to_dict(mapping));
            return result;
        }, "Get all address-to-line mappings.")

        .def("refresh", [](const decomp::DecompiledFunction& self) {
            check_status(self.refresh());
        }, "Refresh pseudocode text (after modifying variables/comments).")

        .def("__repr__", [](const decomp::DecompiledFunction& self) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                          "<DecompiledFunction at 0x%llx>",
                          static_cast<unsigned long long>(self.entry_address()));
            return std::string(buf);
        });

    // ── Free functions ──────────────────────────────────────────────────

    m.def("available", []() {
        return unwrap(decomp::available());
    }, "Check whether the Hex-Rays decompiler is available.");

    m.def("decompile", [](ida::Address addr) {
        return unwrap(decomp::decompile(addr));
    }, py::arg("address"),
       py::return_value_policy::move,
       "Decompile the function at the given address.");

    // ── Microcode filter ────────────────────────────────────────────────

    m.def("register_microcode_filter",
        [](py::function match_fn, py::function apply_fn) -> std::uint64_t {
            auto filter = std::make_shared<PyMicrocodeFilter>(
                std::move(match_fn), std::move(apply_fn));
            auto token = unwrap(decomp::register_microcode_filter(filter));
            store_microcode_filter(token, filter);
            return token;
        },
        py::arg("match_fn"), py::arg("apply_fn"),
        "Register a microcode filter. match_fn(ctx) -> bool, "
        "apply_fn(ctx) -> 'handled'|'notHandled'|'error'. Returns a token.");

    m.def("unregister_microcode_filter", [](std::uint64_t token) {
        check_status(decomp::unregister_microcode_filter(token));
        remove_microcode_filter(token);
    }, py::arg("token"),
       "Unregister a previously registered microcode filter.");

    // ── Event subscriptions ─────────────────────────────────────────────

    m.def("on_maturity_changed", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(decomp::on_maturity_changed(
            [held](const decomp::MaturityEvent& event) {
                py::gil_scoped_acquire gil;
                try {
                    py::dict d;
                    d["function_address"] = event.function_address;
                    d["new_maturity"]     = static_cast<int>(event.new_maturity);
                    (*held)(d);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to decompiler maturity transitions. Returns a token.");

    m.def("on_func_printed", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(decomp::on_func_printed(
            [held](const decomp::PseudocodeEvent& event) {
                py::gil_scoped_acquire gil;
                try {
                    py::dict d;
                    d["function_address"] = event.function_address;
                    (*held)(d);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to func_printed events. Returns a token.");

    m.def("on_refresh_pseudocode", [](py::function callback) -> std::uint64_t {
        auto held = std::make_shared<py::function>(std::move(callback));
        auto token = unwrap(decomp::on_refresh_pseudocode(
            [held](const decomp::PseudocodeEvent& event) {
                py::gil_scoped_acquire gil;
                try {
                    py::dict d;
                    d["function_address"] = event.function_address;
                    (*held)(d);
                } catch (py::error_already_set& e) {
                    e.restore();
                }
            }));
        return token;
    }, py::arg("callback"),
       "Subscribe to refresh_pseudocode events. Returns a token.");

    m.def("unsubscribe", [](std::uint64_t token) {
        check_status(decomp::unsubscribe(token));
    }, py::arg("token"),
       "Unsubscribe a previously registered decompiler event callback.");

    // ── Cache invalidation ──────────────────────────────────────────────

    m.def("mark_dirty", [](ida::Address addr, bool with_callers) {
        check_status(decomp::mark_dirty(addr, with_callers));
    }, py::arg("address"), py::arg("with_callers") = false,
       "Mark a decompiled function cache entry dirty.");

    m.def("mark_dirty_with_callers", [](ida::Address addr) {
        check_status(decomp::mark_dirty_with_callers(addr));
    }, py::arg("address"),
       "Mark a function and all caller functions dirty in decompiler cache.");
}
