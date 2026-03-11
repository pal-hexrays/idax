#ifndef IDAX_PYTHON_HELPERS_HPP
#define IDAX_PYTHON_HELPERS_HPP

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <ida/error.hpp>
#include <ida/address.hpp>

namespace py = pybind11;

static PyObject* IdaxError = nullptr;

inline void register_idax_exception(py::module_& m) {
    IdaxError = PyErr_NewExceptionWithDoc(
        "idax.IdaxError",
        "Error from the IDA SDK via idax.",
        PyExc_RuntimeError, nullptr);
    m.attr("IdaxError") = py::handle(IdaxError);
}

[[noreturn]] inline void throw_idax_error(const ida::Error& err) {
    py::object exc = py::handle(IdaxError)(err.message);
    const char* cat = "Internal";
    switch (err.category) {
        case ida::ErrorCategory::Validation:  cat = "Validation"; break;
        case ida::ErrorCategory::NotFound:    cat = "NotFound"; break;
        case ida::ErrorCategory::Conflict:    cat = "Conflict"; break;
        case ida::ErrorCategory::Unsupported: cat = "Unsupported"; break;
        case ida::ErrorCategory::SdkFailure:  cat = "SdkFailure"; break;
        case ida::ErrorCategory::Internal:    cat = "Internal"; break;
    }
    exc.attr("category") = cat;
    exc.attr("code") = err.code;
    exc.attr("context") = err.context;
    PyErr_SetObject(IdaxError, exc.ptr());
    throw py::error_already_set();
}

template<typename T>
T unwrap(ida::Result<T>&& result) {
    if (!result) throw_idax_error(result.error());
    return std::move(*result);
}

inline void check_status(ida::Status status) {
    if (!status) throw_idax_error(status.error());
}

// Forward declarations
void init_database(py::module_& m);
void init_address(py::module_& m);
void init_segment(py::module_& m);
void init_function(py::module_& m);
void init_instruction(py::module_& m);
void init_name(py::module_& m);
void init_xref(py::module_& m);
void init_comment(py::module_& m);
void init_data(py::module_& m);
void init_search(py::module_& m);
void init_analysis(py::module_& m);
void init_types(py::module_& m);
void init_entry(py::module_& m);
void init_fixup(py::module_& m);
void init_event(py::module_& m);
void init_storage(py::module_& m);
void init_decompiler(py::module_& m);
void init_diagnostics(py::module_& m);
void init_lumina(py::module_& m);
void init_lines(py::module_& m);

#endif
