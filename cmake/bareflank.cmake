#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# This file contains a set of macros that all Bareflank projects need to
# function "internally". These are not intended to be exposed to the user.

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ------------------------------------------------------------------------------
# Color
# ------------------------------------------------------------------------------

string(ASCII 27 Esc)
set(BF_RESET   "${Esc}[m")
set(BF_RED     "${Esc}[91m")
set(BF_GREEN   "${Esc}[92m")
set(BF_YELLOW  "${Esc}[93m")
set(BF_BLUE    "${Esc}[94m")
set(BF_MAGENTA "${Esc}[95m")
set(BF_CYAN    "${Esc}[96m")
set(BF_WHITE   "${Esc}[97m")

set(BF_ENABLED "${BF_GREEN}enabled${BF_RESET}")
set(BF_DISABLED "${BF_YELLOW}disabled${BF_RESET}")

# ------------------------------------------------------------------------------
# Info
# ------------------------------------------------------------------------------

add_custom_target(
    info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta "  ___   _   ___ ___ ___ _      _   _  _ _  __ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | _ ) /_\\ | _ \\ __| __| |    /_\\ | \\| | |/ / "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | _ \\/ _ \\|   / _|| _|| |__ / _ \\| .` | ' <  "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " |___/_/ \\_\\_|_\\___|_| |____/_/ \\_\\_|\\_|_|\\_\\ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Please give us a star on: ${BF_WHITE}https://github.com/Bareflank "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --blue    " ------------------------------------------------------ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

# ------------------------------------------------------------------------------
# bf_error
# ------------------------------------------------------------------------------

# Error
#
# Prints an error message, and then errors out to stop processing.
#
# MSG: The message to show when erroring out
#
macro(bf_error MSG)
    message(FATAL_ERROR "${BF_RED}${MSG}${BF_RESET}")
endmacro(bf_error)

# ------------------------------------------------------------------------------
# bf_configuration_error
# ------------------------------------------------------------------------------

# Configuration Error
#
# Prints an error message, shows the configuration options, and then errors
# out to stop processing.
#
# MSG: The message to show when erroring out
#
macro(bf_configuration_error MSG)
    bf_error(${MSG})
endmacro(bf_configuration_error)

# ------------------------------------------------------------------------------
# bf_find_program
# ------------------------------------------------------------------------------

# Find Program
#
# The only difference between this function and find_program() is that is
# makes sure that the program is found. If it is not, it will error out.
#
macro(bf_find_program VAR NAME URL)
    find_program(${VAR} ${NAME})
    if(NOT ${VAR})
        bf_error("Unable to locate: ${NAME} - ${URL}")
    endif()
endmacro(bf_find_program)

# ------------------------------------------------------------------------------
# default build type
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL Release)
    set(CMAKE_BUILD_TYPE RELEASE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(CMAKE_BUILD_TYPE DEBUG)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE DEBUG)
endif()

if(NOT CMAKE_BUILD_TYPE STREQUAL RELEASE AND
   NOT CMAKE_BUILD_TYPE STREQUAL DEBUG AND
   NOT CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY AND
   NOT CMAKE_BUILD_TYPE STREQUAL PERFORCE AND
   NOT CMAKE_BUILD_TYPE STREQUAL SONARCLOUD AND
   NOT CMAKE_BUILD_TYPE STREQUAL ASAN AND
   NOT CMAKE_BUILD_TYPE STREQUAL UBSAN AND
   NOT CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    bf_error("Unknown CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
endif()

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Supported CMake Build Types:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=RELEASE            compile in release mode"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=DEBUG              compile in debug mode"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=CLANG_TIDY         compile with Clang Tidy checks"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=PERFORCE           compile with Perforce checks"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=SONARCLOUD         compile with SonarCloud"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=ASAN               compile with Google ASAN"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=UBSAN              compile with Google UBSAN"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=COVERAGE           compile with LCOV coverage"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

message(STATUS "Build type: ${BF_CYAN}${CMAKE_BUILD_TYPE}${BF_RESET}")

# ------------------------------------------------------------------------------
# additional info
# ------------------------------------------------------------------------------

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Basic Commands:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make info                             shows this help info"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make -j<# cores>                      builds the project"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make install                          installs the project on your system"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Supported Build Targets:"
    VERBATIM
)

# ------------------------------------------------------------------------------
# examples
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL RELEASE OR
   CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL PERFORCE OR
   CMAKE_BUILD_TYPE STREQUAL SONARCLOUD OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN)
    if(NOT DEFINED BUILD_EXAMPLES)
        set(BUILD_EXAMPLES ON)
    endif()
endif()

if(BUILD_EXAMPLES)
    message(STATUS "Build examples: ${BF_ENABLED}")
else()
    message(STATUS "Build examples: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# tests
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL DEBUG OR
   CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY OR
   CMAKE_BUILD_TYPE STREQUAL SONARCLOUD OR
   CMAKE_BUILD_TYPE STREQUAL ASAN OR
   CMAKE_BUILD_TYPE STREQUAL UBSAN OR
   CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(NOT DEFINED BUILD_TESTS)
        set(BUILD_TESTS ON)
    endif()
endif()

if(BUILD_TESTS)
    include(CTest)
    if(CMAKE_BUILD_TYPE STREQUAL COVERAGE)
        add_custom_target(
            unittest
            COMMAND lcov --zerocounters --directory . -q
            COMMAND ctest --output-on-failure
        )
    else()
        add_custom_target(
            unittest
            COMMAND ctest --output-on-failure
        )
    endif()
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make unittest                         run the project's unit tests"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make memcheck                         run the project's unit tests under valgrind"
        VERBATIM
    )
    message(STATUS "Build tests: ${BF_ENABLED}")
else()
    message(STATUS "Build tests: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# compiler
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    if(NOT CMAKE_CXX_COMPILER MATCHES "clang")
        bf_configuration_error("Static analysis requires clang++")
    endif()
endif()

if(CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(CMAKE_CXX_COMPILER MATCHES "clang")
        bf_configuration_error("Coverage analysis requires g++")
    endif()
endif()

# ------------------------------------------------------------------------------
# clang tidy
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL CLANG_TIDY)
    if(NOT DEFINED ENABLE_CLANG_TIDY)
        set(ENABLE_CLANG_TIDY ON)
    endif()
endif()

if(ENABLE_CLANG_TIDY)
    bf_find_program(CMAKE_CXX_CLANG_TIDY "clang-tidy" "https://clang.llvm.org/extra/clang-tidy/")
    message(STATUS "Tool [Clang Tidy]: ${BF_ENABLED} - ${CMAKE_CXX_CLANG_TIDY}")
endif()

# ------------------------------------------------------------------------------
# clang format
# ------------------------------------------------------------------------------

FILE(GLOB_RECURSE BF_HEADERS_EXAMPLES ${CMAKE_SOURCE_DIR}/examples/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_EXAMPLES ${CMAKE_SOURCE_DIR}/examples/*.cpp)
FILE(GLOB_RECURSE BF_HEADERS_INCLUDE ${CMAKE_SOURCE_DIR}/include/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_INCLUDE ${CMAKE_SOURCE_DIR}/include/*.cpp)
FILE(GLOB_RECURSE BF_HEADERS_TESTS ${CMAKE_SOURCE_DIR}/tests/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_TESTS ${CMAKE_SOURCE_DIR}/tests/*.cpp)
FILE(GLOB_RECURSE BF_HEADERS_SRC ${CMAKE_SOURCE_DIR}/src/*.hpp)
FILE(GLOB_RECURSE BF_SOURCES_SRC ${CMAKE_SOURCE_DIR}/src/*.cpp)

if(NOT CMAKE_BUILD_TYPE STREQUAL RELEASE)
    if(NOT DEFINED ENABLE_CLANG_FORMAT)
        set(ENABLE_CLANG_FORMAT ON)
    endif()
endif()

if(ENABLE_CLANG_FORMAT)
    bf_find_program(BF_CLANG_FORMAT "clang-format" "https://clang.llvm.org/docs/ClangFormat.html")
    add_custom_target(
        format
        COMMAND ${BF_CLANG_FORMAT} -i
        ${BF_HEADERS_EXAMPLES} ${BF_SOURCES_EXAMPLES}
        ${BF_HEADERS_INCLUDE} ${BF_SOURCES_INCLUDE}
        ${BF_HEADERS_TESTS} ${BF_SOURCES_TESTS}
        ${BF_HEADERS_SRC} ${BF_SOURCES_SRC}
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make format                           formats the source code"
        VERBATIM
    )
    message(STATUS "Tool [Clang Format]: ${BF_ENABLED} - ${BF_CLANG_FORMAT}")
else()
    message(STATUS "Tool [Clang Format]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# sonar build wrapper
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL SONARCLOUD)
    if(NOT DEFINED ENABLE_SONAR_BUILD_WRAPPER)
        set(ENABLE_SONAR_BUILD_WRAPPER ON)
    endif()
endif()

if(ENABLE_SONAR_BUILD_WRAPPER)
    bf_find_program(BF_SONAR_BUILD_WRAPPER "build-wrapper-linux-x86-64" "https://docs.sonarqube.org/latest/analysis/languages/cfamily/")
    add_custom_target(
        sonar-build
        COMMAND ${BUILD_WRAPPER} --out-dir ${CMAKE_BINARY_DIR}/bw_output make clean all
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make sonar-build                      builds the project for sonar cloud"
        VERBATIM
    )
    message(STATUS "Tool [Sonar Build Wrapper]: ${BF_ENABLED} - ${BF_SONAR_BUILD_WRAPPER}")
else()
    message(STATUS "Tool [Sonar Build Wrapper]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# sonar scanner
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL SONARCLOUD)
    if(NOT DEFINED ENABLE_SONAR_SCANNER)
        set(ENABLE_SONAR_SCANNER ON)
    endif()
endif()

if(ENABLE_SONAR_SCANNER)
    bf_find_program(BF_SONAR_SCANNER "sonar-scanner" "https://docs.sonarqube.org/latest/analysis/languages/cfamily/")
    add_custom_target(
        sonar-upload
        COMMAND ${CMAKE_COMMAND} --build . --target sonar-build
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} ${SONAR_SCANNER}
        -Dsonar.login=81bb5447bd6ef44979b75e67ab255e7364408418
        -Dproject.settings=.sonarsource
        -Dsonar.cfamily.build-wrapper-output=${CMAKE_BINARY_DIR}/bw_output
    )
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make sonar-upload                     uploads static analysis results to sonar cloud"
        VERBATIM
    )
    message(STATUS "Tool [Sonar Scanner]: ${BF_ENABLED} - ${BF_SONAR_SCANNER}")
else()
    message(STATUS "Tool [Sonar Scanner]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# lcov
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL COVERAGE)
    if(NOT DEFINED ENABLE_COVERAGE)
        set(ENABLE_COVERAGE ON)
    endif()
endif()

if(ENABLE_COVERAGE)
    bf_find_program(BF_COVERAGE "lcov" "http://ltp.sourceforge.net/coverage/lcov.php")
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make coverage                         generates a code coverage report"
        VERBATIM
    )
    add_custom_target(
        coverage_info
        COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND lcov --zerocounters --directory . -q
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND ctest --output-on-failure
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND lcov --capture --directory . --output-file ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '/usr/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '${CMAKE_BINARY_DIR}/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '${CMAKE_SOURCE_DIR}/tests/*' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
        COMMAND lcov --remove ${CMAKE_BINARY_DIR}/coverage.info '${CMAKE_SOURCE_DIR}/include/bsl/autosar.hpp' --output-file ${CMAKE_BINARY_DIR}/coverage.info -q
    )

    add_custom_target(
        coverage
        COMMAND ${CMAKE_COMMAND} --build . --target coverage_info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND genhtml -o site ${CMAKE_BINARY_DIR}/coverage.info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND ${CMAKE_COMMAND} -E chdir site python -m "http.server"
    )

    add_custom_target(
        coverage_upload
        COMMAND ${CMAKE_COMMAND} --build . --target coverage_info
        COMMAND ${CMAKE_COMMAND} -E echo "================================================================================"
        COMMAND curl -s https://codecov.io/bash > ${CMAKE_BINARY_DIR}/codecov.sh
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR}
        bash ${CMAKE_BINARY_DIR}/codecov.sh -t 3127698f-3d70-4a23-a00f-cd7e54768434 -f ${CMAKE_BINARY_DIR}/coverage.info
    )
    message(STATUS "Tool [LCOV]: ${BF_ENABLED} - ${BF_COVERAGE}")
else()
    message(STATUS "Tool [LCOV]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# asan
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL ASAN AND UNIX)
    if(NOT DEFINED ENABLE_ASAN)
        set(ENABLE_ASAN ON)
    endif()
endif()

if(ENABLE_ASAN)
    message(STATUS "Tool [Google's ASAN]: ${BF_ENABLED}")
else()
    message(STATUS "Tool [Google's ASAN]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# ubsan
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL UBSAN AND UNIX)
    if(NOT DEFINED ENABLE_UBSAN)
        set(ENABLE_UBSAN ON)
    endif()
endif()

if(ENABLE_UBSAN)
    message(STATUS "Tool [Google's UBSAN]: ${BF_ENABLED}")
else()
    message(STATUS "Tool [Google's UBSAN]: ${BF_DISABLED}")
endif()

# ------------------------------------------------------------------------------
# c++ flags
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_RELEASE "-O3 -DNDEBUG -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-Og -g -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_DEBUG "-Og -g -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_CLANG_TIDY "-O0 -Werror -Weverything -fcomment-block-commands=include -Wno-c++98-compat -Wno-padded -Wno-weak-vtables")
set(CMAKE_LINKER_FLAGS_CLANG_TIDY "-O0 -Werror -Weverything -fcomment-block-commands=include -Wno-c++98-compat -Wno-padded -Wno-weak-vtables")
set(CMAKE_CXX_FLAGS_PERFORCE "-O0 -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_PERFORCE "-O0 -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_SONARCLOUD "-O0 -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_SONARCLOUD "-O0 -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_UBSAN "-Og -g -fsanitize=undefined -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_UBSAN "-Og -g -fsanitize=undefined -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_COVERAGE "-O0 --coverage -fprofile-arcs -ftest-coverage -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_COVERAGE "-O0 --coverage -fprofile-arcs -ftest-coverage -Wall -Wextra -Wpedantic")

if(NOT DEFINED CMAKE_CXX_FLAGS OR CMAKE_CXX_FLAGS STREQUAL "")
    set(CMAKE_CXX_FLAGS "-ffreestanding -fno-exceptions -fno-rtti")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}=-ffreestanding -fno-exceptions -fno-rtti")
endif()

message(STATUS "CXX Flags: ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}")

# ------------------------------------------------------------------------------
# info done
# ------------------------------------------------------------------------------

add_custom_command(TARGET info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

# ------------------------------------------------------------------------------
# default definitions
# ------------------------------------------------------------------------------

add_custom_target(doxygen
    COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} doxygen .doxygen
    VERBATIM
)

# ------------------------------------------------------------------------------
# default definitions
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL PERFORCE)
    set(BSL_DEBUG_LEVEL "debug_level_t::verbosity_level_3")
endif()

if(NOT DEFINED BSL_OUTPUT_TID_WHEN_DEBUGGING)
    set(BSL_OUTPUT_TID_WHEN_DEBUGGING false)
endif()

if(NOT DEFINED BSL_THREAD_ID)
    set(BSL_THREAD_ID "")
endif()

if(NOT DEFINED BSL_DEBUG_LEVEL)
    set(BSL_DEBUG_LEVEL "debug_level_t::verbosity_level_0")
endif()

if(CMAKE_BUILD_TYPE STREQUAL RELEASE)
    set(BSL_DISABLE_DEBUGGING true)
else()
    set(BSL_DISABLE_DEBUGGING false)
endif()

if(CMAKE_BUILD_TYPE STREQUAL PERFORCE)
    set(BSL_BUILTIN_FILE "\"file\"")
    set(BSL_BUILTIN_FUNCTION "\"function\"")
    set(BSL_BUILTIN_LINE "0")
else()
    set(BSL_BUILTIN_FILE "__builtin_FILE()")
    set(BSL_BUILTIN_FUNCTION "__builtin_FUNCTION()")
    set(BSL_BUILTIN_LINE "__builtin_LINE()")
endif()

list(APPEND BSL_DEFAULT_DEFINES
    BSL_OUTPUT_TID_WHEN_DEBUGGING=${BSL_OUTPUT_TID_WHEN_DEBUGGING}
    BSL_THREAD_ID=${BSL_THREAD_ID}
    BSL_DEBUG_LEVEL=${BSL_DEBUG_LEVEL}
    BSL_DISABLE_DEBUGGING=${BSL_DISABLE_DEBUGGING}
    BSL_BUILTIN_FILE=${BSL_BUILTIN_FILE}
    BSL_BUILTIN_FUNCTION=${BSL_BUILTIN_FUNCTION}
    BSL_BUILTIN_LINE=${BSL_BUILTIN_LINE}
)

# ------------------------------------------------------------------------------
# bf_generate_defines
# ------------------------------------------------------------------------------

# Generate Defines
#
# This function takes the default defines and merges it with any defines that
# that are provided for a target. This is capable of handling defines that
# include a value or simply are defined, as well as defines that are similar
# in name. If a target provides a define that is also in the defaults list,
# the target's define wins.
#
# NAME the name of of the target to set the merged defines.
# DEFINES the defines to provide the target that either override a default
#    or provide above and beyond the defaults.
#
function(bf_generate_defines NAME)
    set(multiValueArgs DEFINES)
    cmake_parse_arguments(ARGS "" "" "${multiValueArgs}" ${ARGN})

    foreach(d ${BSL_DEFAULT_DEFINES})
        string(REPLACE "=" ";" d "${d}")
        list(GET d 0 FIELD_NAME)
        list(APPEND BSL_DEFAULT_DEFINES_FIELDS ${FIELD_NAME})
    endforeach(d)

    foreach(d ${ARGS_DEFINES})
        string(REPLACE "=" ";" d "${d}")
        list(GET d 0 FIELD_NAME)
        list(APPEND ARGS_DEFINES_FIELDS ${FIELD_NAME})
    endforeach(d)

    list(APPEND ALL_FIELDS ${ARGS_DEFINES_FIELDS} ${BSL_DEFAULT_DEFINES_FIELDS})
    list(REMOVE_DUPLICATES ALL_FIELDS)

    foreach(f ${ALL_FIELDS})
        set(FOUND 0)

        foreach(d ${ARGS_DEFINES})
            set(fd "${d}=")
            string(REPLACE "=" ";" fd "${fd}")
            list(GET fd 0 fd)
            if(f STREQUAL fd)
                list(APPEND GENERATED_DEFINED ${d})
                set(FOUND 1)
                break()
            endif()
        endforeach(d)

        if(FOUND)
            continue()
        endif()

        foreach(d ${BSL_DEFAULT_DEFINES})
            set(fd "${d}=")
            string(REPLACE "=" ";" fd "${fd}")
            list(GET fd 0 fd)
            if(f STREQUAL fd)
                list(APPEND GENERATED_DEFINED ${d})
                set(FOUND 1)
                break()
            endif()
        endforeach(d)
    endforeach(f)
    target_compile_definitions(${NAME} PRIVATE ${GENERATED_DEFINED})
endfunction(bf_generate_defines)

# ------------------------------------------------------------------------------
# bf_add_example
# ------------------------------------------------------------------------------

# Add Test
#
# Adds a test case given a name. Note that this will disable C++ access
# controls, assisting in unit testing.
#
# NAME: The name of the test case to add
#
macro(bf_add_example NAME)
    set(multiValueArgs DEFINES)
    cmake_parse_arguments(ARGS "" "" "${multiValueArgs}" ${ARGN})

    file(RELATIVE_PATH REL_NAME ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_LIST_DIR})
    file(TO_CMAKE_PATH "${REL_NAME}" REL_NAME)
    string(REPLACE "/" "_" REL_NAME ${REL_NAME})

    add_executable(${REL_NAME}_${NAME} ${NAME}.cpp)
    target_include_directories(${REL_NAME}_${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(WIN32)
        target_link_libraries(${REL_NAME}_${NAME} libcmt.lib)
    endif()
    bf_generate_defines(${REL_NAME}_${NAME} ${ARGN})
endmacro(bf_add_example)

# ------------------------------------------------------------------------------
# bf_add_test
# ------------------------------------------------------------------------------

# Add Test
#
# Adds a test case given a name. Note that this will disable C++ access
# controls, assisting in unit testing.
#
# NAME: The name of the test case to add
#
macro(bf_add_test NAME)
    set(multiValueArgs DEFINES)
    cmake_parse_arguments(ARGS "" "" "${multiValueArgs}" ${ARGN})

    file(RELATIVE_PATH REL_NAME ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_LIST_DIR})
    file(TO_CMAKE_PATH "${REL_NAME}" REL_NAME)
    string(REPLACE "/" "_" REL_NAME ${REL_NAME})

    add_executable(${REL_NAME}_${NAME} ${NAME}.cpp)
    target_include_directories(${REL_NAME}_${NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    if(WIN32)
        target_link_libraries(${REL_NAME}_${NAME} libcmt.lib)
    endif()
    target_compile_options(${REL_NAME}_${NAME} PRIVATE -fno-access-control)
    add_test(${REL_NAME}_${NAME} ${REL_NAME}_${NAME})
    bf_generate_defines(${REL_NAME}_${NAME} ${ARGN})
endmacro(bf_add_test)

#locate dot
#locate doxygen
