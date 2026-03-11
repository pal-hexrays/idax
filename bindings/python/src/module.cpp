#include <pybind11/pybind11.h>
#include "helpers.hpp"

namespace py = pybind11;

PYBIND11_MODULE(_idax, m) {
    m.doc() = "Python bindings for the IDA SDK via idax";
    m.attr("BAD_ADDRESS") = ida::BadAddress;
    register_idax_exception(m);

    // Submodules — uncomment as each is implemented
    init_database(m);
    init_address(m);
    init_segment(m);
    // init_function(m);
    // init_instruction(m);
    // init_name(m);
    // init_xref(m);
    // init_comment(m);
    // init_data(m);
    // init_search(m);
    // init_analysis(m);
    // init_types(m);
    // init_entry(m);
    // init_fixup(m);
    // init_event(m);
    // init_storage(m);
    // init_decompiler(m);
    // init_diagnostics(m);
    // init_lumina(m);
    // init_lines(m);
}
