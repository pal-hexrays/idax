/// \file lines_bind.cpp
/// \brief pybind11 bindings for ida::lines — color tag manipulation and constants.

#include "helpers.hpp"
#include <ida/lines.hpp>

namespace ln = ida::lines;

void init_lines(py::module_& parent) {
    auto m = parent.def_submodule("lines",
        "Color tag manipulation and constants.");

    // ── Color enum ────────────────────────────────────────────────────────

    py::enum_<ln::Color>(m, "Color")
        .value("DEFAULT",            ln::Color::Default)
        .value("REGULAR_COMMENT",    ln::Color::RegularComment)
        .value("REPEATABLE_COMMENT", ln::Color::RepeatableComment)
        .value("AUTO_COMMENT",       ln::Color::AutoComment)
        .value("INSTRUCTION",        ln::Color::Instruction)
        .value("DATA_NAME",          ln::Color::DataName)
        .value("REGULAR_DATA_NAME",  ln::Color::RegularDataName)
        .value("DEMANGLED_NAME",     ln::Color::DemangledName)
        .value("SYMBOL",             ln::Color::Symbol)
        .value("CHAR_LITERAL",       ln::Color::CharLiteral)
        .value("STRING",             ln::Color::String)
        .value("NUMBER",             ln::Color::Number)
        .value("VOID",               ln::Color::Void)
        .value("CODE_REFERENCE",     ln::Color::CodeReference)
        .value("DATA_REFERENCE",     ln::Color::DataReference)
        .value("CODE_REF_TAIL",      ln::Color::CodeRefTail)
        .value("DATA_REF_TAIL",      ln::Color::DataRefTail)
        .value("ERROR",              ln::Color::Error)
        .value("PREFIX",             ln::Color::Prefix)
        .value("BINARY_PREFIX",      ln::Color::BinaryPrefix)
        .value("EXTRA",              ln::Color::Extra)
        .value("ALT_OPERAND",        ln::Color::AltOperand)
        .value("HIDDEN_NAME",        ln::Color::HiddenName)
        .value("LIBRARY_NAME",       ln::Color::LibraryName)
        .value("LOCAL_NAME",         ln::Color::LocalName)
        .value("DUMMY_CODE_NAME",    ln::Color::DummyCodeName)
        .value("ASM_DIRECTIVE",      ln::Color::AsmDirective)
        .value("MACRO",              ln::Color::Macro)
        .value("DATA_STRING",        ln::Color::DataString)
        .value("DATA_CHAR",          ln::Color::DataChar)
        .value("DATA_NUMBER",        ln::Color::DataNumber)
        .value("KEYWORD",            ln::Color::Keyword)
        .value("REGISTER",           ln::Color::Register)
        .value("IMPORTED_NAME",      ln::Color::ImportedName)
        .value("SEGMENT_NAME",       ln::Color::SegmentName)
        .value("UNKNOWN_NAME",       ln::Color::UnknownName)
        .value("CODE_NAME",          ln::Color::CodeName)
        .value("USER_NAME",          ln::Color::UserName)
        .value("COLLAPSED",          ln::Color::Collapsed);

    // ── Tag control byte constants ────────────────────────────────────────

    m.attr("COLOR_ON")        = static_cast<int>(ln::kColorOn);
    m.attr("COLOR_OFF")       = static_cast<int>(ln::kColorOff);
    m.attr("COLOR_ESC")       = static_cast<int>(ln::kColorEsc);
    m.attr("COLOR_INV")       = static_cast<int>(ln::kColorInv);
    m.attr("COLOR_ADDR")      = static_cast<int>(ln::kColorAddr);
    m.attr("COLOR_ADDR_SIZE") = ln::kColorAddrSize;

    // ── Functions ─────────────────────────────────────────────────────────

    m.def("colstr", [](const std::string& text, ln::Color color) {
        return ln::colstr(text, color);
    }, py::arg("text"), py::arg("color"),
       "Wrap a string in color tags (equivalent to IDA's COLSTR macro).");

    m.def("tag_remove", [](const std::string& tagged_text) {
        return ln::tag_remove(tagged_text);
    }, py::arg("tagged_text"),
       "Remove all color tags from a tagged string, returning plain text.");

    m.def("tag_advance", [](const std::string& tagged_text, int pos) {
        return ln::tag_advance(tagged_text, pos);
    }, py::arg("tagged_text"), py::arg("pos"),
       "Advance past a color tag at the given position.");

    m.def("tag_strlen", [](const std::string& tagged_text) {
        return ln::tag_strlen(tagged_text);
    }, py::arg("tagged_text"),
       "Get the visible (non-tag) character length of a tagged string.");

    m.def("make_addr_tag", [](int item_index) {
        return ln::make_addr_tag(item_index);
    }, py::arg("item_index"),
       "Build a COLOR_ADDR item reference tag.");

    m.def("decode_addr_tag", [](const std::string& tagged_text, std::size_t pos) {
        return ln::decode_addr_tag(tagged_text, pos);
    }, py::arg("tagged_text"), py::arg("pos"),
       "Decode a COLOR_ADDR tag at the given position. Returns -1 if invalid.");
}
