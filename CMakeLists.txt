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

cmake_minimum_required(VERSION 3.13)
project(bsl CXX)

set(CMAKE_CXX_STANDARD 17)

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

option(BUILD_EXAMPLES "Build example programs" ON)
option(BUILD_TESTS "Build test programs" ON)

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

find_package(fmt REQUIRED)

# ------------------------------------------------------------------------------
# Development Mode
# ------------------------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS OFF)
    message(STATUS "[enabled]: CMake's Release mode")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: CMake's Debug mode")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: Clang Tidy")
    message(STATUS "[enabled]: CppCheck")
    message(STATUS "[enabled]: Clang's -Weverything")
    message(STATUS "[enabled]: Google's UBSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "ASAN")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: Google's ASAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "MSAN")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: Google's MSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "TSAN")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: Google's TSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "UBSAN")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: Google's UBSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "COVERAGE")
    set(BUILD_EXAMPLES OFF)
    set(BUILD_TESTS ON)
    message(STATUS "[enabled]: LCOV Coverage Tools")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-Werror -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_RELEASE "-Werror -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_STATIC_ANALYSIS "-Og -g -Werror -Weverything -Wno-c++98-compat -Wno-padded")
set(CMAKE_LINKER_FLAGS_STATIC_ANALYSIS "-Og -g -Werror -Weverything -Wno-c++98-compat -Wno-padded")
set(CMAKE_CXX_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_LINKER_FLAGS_ASAN "-Og -g -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_CXX_FLAGS_MSAN "-Og -g -fno-omit-frame-pointer -fsanitize=memory")
set(CMAKE_LINKER_FLAGS_MSAN "-Og -g -fno-omit-frame-pointer -fsanitize=memory")
set(CMAKE_CXX_FLAGS_TSAN "-Og -g -fsanitize=thread")
set(CMAKE_LINKER_FLAGS_TSAN "-Og -g -fsanitize=thread")
set(CMAKE_CXX_FLAGS_UBSAN "-Og -g -fsanitize=undefined")
set(CMAKE_LINKER_FLAGS_UBSAN "-Og -g -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_COVERAGE "-O0 -g --coverage -fprofile-arcs -ftest-coverage")
set(CMAKE_LINKER_FLAGS_COVERAGE "-O0 -g --coverage -fprofile-arcs -ftest-coverage")

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS "-fdiagnostics-color=auto")

# ------------------------------------------------------------------------------
# Static Analysis Tools
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
    list(APPEND CMAKE_CXX_CLANG_TIDY
        clang-tidy
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
    list(APPEND CMAKE_CXX_CPPCHECK
        cppcheck
        --enable=all
        --error-exitcode=1
        --quiet
        --inline-suppr
        --suppress=unmatchedSuppression         # Handle different versions of CppCheck
        --suppress=missingInclude               # Noisy warning
        --suppress=operatorEq                   # Mutually exclusive with Clang Tidy
        --template="{file}:{line}: {severity}: {id}: {message}"
    )
endif()

# ------------------------------------------------------------------------------
# Sub Directories
# ------------------------------------------------------------------------------

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(BUILD_TESTS)
    include(CTest)
    add_subdirectory(tests)
endif()

# ------------------------------------------------------------------------------
# Install
# ------------------------------------------------------------------------------

install(FILES include/bsl.h DESTINATION include/bsl)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    format
    COMMAND find ${CMAKE_SOURCE_DIR}/examples -iname *.h -o -iname *.cpp | xargs clang-format -i
    COMMAND find ${CMAKE_SOURCE_DIR}/include -iname *.h -o -iname *.cpp | xargs clang-format -i
    COMMAND find ${CMAKE_SOURCE_DIR}/tests -iname *.h -o -iname *.cpp | xargs clang-format -i
)

# ------------------------------------------------------------------------------
# Info
# ------------------------------------------------------------------------------

string(ASCII 27 Esc)
set(COLOR_E "${Esc}[m")
set(COLOR_G "${Esc}[1;92m")
set(COLOR_Y "${Esc}[1;93m")
set(COLOR_M "${Esc}[1;95m")
set(COLOR_W "${Esc}[1;97m")

message(STATUS "${COLOR_M}  ____    ____    _      ${COLOR_E}")
message(STATUS "${COLOR_M} | __ )  / ___|  | |     ${COLOR_E}")
message(STATUS "${COLOR_M} |  _ \\  \\___ \\  | |  ${COLOR_E}")
message(STATUS "${COLOR_M} | |_) |  ___) | | |___  ${COLOR_E}")
message(STATUS "${COLOR_M} |____/  |____/  |_____| ${COLOR_E}")
message(STATUS "")
message(STATUS "${COLOR_G} Please give us a star on: ${White}https://github.com/Bareflank/bsl${COLOR_E}")
message(STATUS "")
message(STATUS "${COLOR_G} CMake configuration options:${COLOR_E}")
message(STATUS "${COLOR_Y}   -DBUILD_EXAMPLES=ON                   ${COLOR_E}build the examples")
message(STATUS "${COLOR_Y}   -DBUILD_TESTS=ON                      ${COLOR_E}build the unittests")
message(STATUS "")

message(STATUS "${COLOR_G} BSL build types:${COLOR_E}")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=Release            ${COLOR_E}compile in release mode")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=Debug              ${COLOR_E}compile in debug mode")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=STATIC_ANALYSIS    ${COLOR_E}compile with Clang Tidy and CppCheck")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=ASAN               ${COLOR_E}compile with Google's ASAN")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=MSAN               ${COLOR_E}compile with Google's MSAN")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=TSAN               ${COLOR_E}compile with Google's TSAN")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=UBSAN              ${COLOR_E}compile with Google's UBSAN")
message(STATUS "${COLOR_Y}   -DCMAKE_BUILD_TYPE=COVERAGE           ${COLOR_E}compile with LCOV coverage")
message(STATUS "")

message(STATUS "${COLOR_G} BSL build targets:${COLOR_E}")
message(STATUS "${COLOR_Y}   make format                           ${COLOR_E}formats the source code")
message(STATUS "${COLOR_Y}   make unittest                         ${COLOR_E}runs the unittests")
message(STATUS "${COLOR_Y}   make memcheck                         ${COLOR_E}runs the unittests with Valgrind")
message(STATUS "${COLOR_Y}   make coverage                         ${COLOR_E}runs the unittests with LCOV")
message(STATUS "${COLOR_Y}   make flexlint                         ${COLOR_E}runs flexlint")
message(STATUS "")

message(STATUS "${COLOR_G} BSL installation:${COLOR_E}")
message(STATUS "${COLOR_Y}   make install                          ${COLOR_E}installs BSL on your system")
message(STATUS "")
