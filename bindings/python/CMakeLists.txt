cmake_minimum_required(VERSION 3.27)

project(idax-python LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Locate pybind11 ─────────────────────────────────────────────────────

find_package(pybind11 CONFIG REQUIRED)

# ── Locate idax ──────────────────────────────────────────────────────────

# idax lives two directories up from bindings/python
set(IDAX_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(IDAX_INCLUDE_DIR "${IDAX_ROOT}/include")

if(NOT EXISTS "${IDAX_INCLUDE_DIR}/ida/idax.hpp")
    message(FATAL_ERROR "Cannot find idax headers at ${IDAX_INCLUDE_DIR}")
endif()

# ── Locate idax static library ───────────────────────────────────────────

# Try the build directory first, then installed locations
set(IDAX_LIB_SEARCH_PATHS
    "${IDAX_ROOT}/build"
    "${IDAX_ROOT}/build/Release"
    "${IDAX_ROOT}/build/Debug"
    "${IDAX_ROOT}/build/RelWithDebInfo"
    "${CMAKE_INSTALL_PREFIX}/lib"
)

find_library(IDAX_LIBRARY
    NAMES idax libidax
    PATHS ${IDAX_LIB_SEARCH_PATHS}
    NO_DEFAULT_PATH
)

if(NOT IDAX_LIBRARY)
    message(WARNING "idax static library not found. The module will compile but not link until idax is built.")
    set(IDAX_LIBRARY "")
endif()

# ── IDA SDK headers (needed transitively by idax) ────────────────────────

if(DEFINED ENV{IDASDK})
    set(IDASDK_DIR "$ENV{IDASDK}")
    add_compile_definitions(__EA64__)
    message(STATUS "IDA SDK: ${IDASDK_DIR}")
else()
    message(WARNING "IDASDK environment variable not set. Build may fail.")
endif()

# ── IDA installation (runtime dylibs) ────────────────────────────────────
#
# The IDA SDK ships stub dylibs with different symbol exports than the real
# IDA runtime dylibs. On macOS with two-level namespace linking, this causes
# symbols (like callui, qvector_reserve) to be bound to the wrong dylib,
# resulting in null-pointer crashes at runtime. We MUST link against the
# real IDA dylibs from the installation for correct symbol resolution.
#
# The module needs both:
#   - libidalib.dylib  (idalib entry points: open_database, etc.)
#   - libida.dylib     (IDA kernel symbols: callui, add_func_ex, etc.)

if(DEFINED ENV{IDADIR})
    set(IDA_INSTALL_DIR "$ENV{IDADIR}")
elseif(APPLE)
    # Try common macOS locations.
    foreach(_ver 9.3 9.2 9.1 9.0)
        set(_try "/Applications/IDA Professional ${_ver}.app/Contents/MacOS")
        if(EXISTS "${_try}/libidalib.dylib")
            set(IDA_INSTALL_DIR "${_try}")
            break()
        endif()
    endforeach()
    # Also check the hexrays development build.
    if(NOT IDA_INSTALL_DIR)
        set(_dev_try "$ENV{HOME}/hexrays/ida/bin/arm64_mac_clang_opt/ida.app/Contents/MacOS")
        if(EXISTS "${_dev_try}/libidalib.dylib")
            set(IDA_INSTALL_DIR "${_dev_try}")
        endif()
    endif()
endif()

if(NOT IDA_INSTALL_DIR)
    message(WARNING "IDA installation not found. Set IDADIR environment variable.\n"
                    "The module will compile but fail to load at runtime.")
else()
    message(STATUS "IDA installation: ${IDA_INSTALL_DIR}")
endif()

# Locate the two required dylibs.
if(IDA_INSTALL_DIR)
    find_library(IDALIB_LIBRARY
        NAMES idalib libidalib
        PATHS "${IDA_INSTALL_DIR}"
        NO_DEFAULT_PATH
    )
    find_library(LIBIDA_LIBRARY
        NAMES ida libida
        PATHS "${IDA_INSTALL_DIR}"
        NO_DEFAULT_PATH
    )

    if(IDALIB_LIBRARY)
        message(STATUS "idalib: ${IDALIB_LIBRARY}")
    else()
        message(WARNING "libidalib.dylib not found in ${IDA_INSTALL_DIR}")
    endif()
    if(LIBIDA_LIBRARY)
        message(STATUS "libida: ${LIBIDA_LIBRARY}")
    else()
        message(WARNING "libida.dylib not found in ${IDA_INSTALL_DIR}")
    endif()

endif()

if(MSVC AND IDASDK_DIR AND (NOT IDALIB_LIBRARY OR NOT LIBIDA_LIBRARY OR NOT LIBPRO_LIBRARY))
    set(IDA_LIB_DIR "${IDASDK_DIR}/lib/x64_win_vc_64")
    if(NOT IDALIB_LIBRARY)
        find_library(IDALIB_LIBRARY NAMES idalib PATHS "${IDA_LIB_DIR}" NO_DEFAULT_PATH)
    endif()
    if(NOT LIBIDA_LIBRARY)
        find_library(LIBIDA_LIBRARY NAMES ida PATHS "${IDA_LIB_DIR}" NO_DEFAULT_PATH)
    endif()
    if(NOT LIBPRO_LIBRARY)
        find_library(LIBPRO_LIBRARY NAMES pro PATHS "${IDA_LIB_DIR}" NO_DEFAULT_PATH)
    endif()

    if(IDALIB_LIBRARY)
        message(STATUS "idalib.lib: ${IDALIB_LIBRARY}")
    else()
        message(WARNING "idalib.lib not found in ${IDA_LIB_DIR}")
    endif()
    if(LIBIDA_LIBRARY)
        message(STATUS "ida.lib: ${LIBIDA_LIBRARY}")
    else()
        message(WARNING "ida.lib not found in ${IDA_LIB_DIR}")
    endif()
    if(LIBPRO_LIBRARY)
        message(STATUS "pro.lib: ${LIBPRO_LIBRARY}")
    endif()
endif()

# ── pybind11 module target ───────────────────────────────────────────────

set(BINDING_SOURCES
    src/module.cpp
    src/database_bind.cpp
    src/address_bind.cpp
    src/segment_bind.cpp
)

pybind11_add_module(_idax ${BINDING_SOURCES})

target_include_directories(_idax PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${IDAX_INCLUDE_DIR}
)

if(IDASDK_DIR)
    target_include_directories(_idax PRIVATE "${IDASDK_DIR}/include")
endif()

if(IDAX_LIBRARY)
    target_link_libraries(_idax PRIVATE ${IDAX_LIBRARY})
endif()

# Link against the real IDA dylibs for symbol resolution.
if(IDALIB_LIBRARY)
    target_link_libraries(_idax PRIVATE ${IDALIB_LIBRARY})
endif()
if(LIBIDA_LIBRARY)
    target_link_libraries(_idax PRIVATE ${LIBIDA_LIBRARY})
endif()
if(LIBPRO_LIBRARY)
    target_link_libraries(_idax PRIVATE ${LIBPRO_LIBRARY})
endif()

# idalib definition — idax uses this to select idalib-specific code paths.
target_compile_definitions(_idax PRIVATE IDALIB_IMPL)

# Set rpath so the module can find IDA dylibs at runtime.
if(APPLE AND IDA_INSTALL_DIR)
    set_target_properties(_idax PROPERTIES
        BUILD_RPATH "${IDA_INSTALL_DIR}"
        INSTALL_RPATH "${IDA_INSTALL_DIR}"
    )
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(_idax PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(_idax PRIVATE /W4 /permissive-)
    target_compile_options(_idax PRIVATE /Zc:__cplusplus)
endif()

install(TARGETS _idax DESTINATION idax)
