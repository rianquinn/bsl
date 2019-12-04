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
# Dependencies
# ------------------------------------------------------------------------------

find_package(fmt REQUIRED)

# ------------------------------------------------------------------------------
# Development Mode
# ------------------------------------------------------------------------------

if(NOT UNIX)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled CMake's Release mode")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled CMake's Debug mode")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
    find_program(CLANG_TIDY clang-tidy)
    if(CLANG_TIDY STREQUAL "CLANG_TIDY-NOTFOUND")
        message(FATAL_ERROR "Unable to locate clang-tidy")
    endif()
    find_program(CPPCHECK cppcheck)
    if(CPPCHECK STREQUAL "CPPCHECK-NOTFOUND")
        message(FATAL_ERROR "Unable to locate cppcheck")
    endif()
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    if(NOT CMAKE_CXX_COMPILER MATCHES "clang")
        message(FATAL_ERROR "Static analysis requires clang++")
    endif()
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled Clang Tidy")
    message(STATUS "Enabled CppCheck")
    message(STATUS "Enabled Include What You Use")
    message(STATUS "Enabled Clang's -Weverything")
    message(STATUS "Enabled Google's UBSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "SONARCLOUD" AND UNIX)
    find_program(SONAR_SCANNER sonar-scanner)
    if(SONAR_SCANNER STREQUAL "SONAR_SCANNER-NOTFOUND")
        message(FATAL_ERROR "Unable to locate sonar-scanner")
    endif()
    find_program(BUILD_WRAPPER build-wrapper-linux-x86-64)
    if(BUILD_WRAPPER STREQUAL "BUILD_WRAPPER-NOTFOUND")
        message(FATAL_ERROR "Unable to locate build-wrapper-linux-x86-64")
    endif()
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled SonarCloud Targets")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "ASAN" AND UNIX)
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled Google's ASAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "MSAN")
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled Google's MSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "TSAN")
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled Google's TSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "UBSAN")
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled Google's UBSAN")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "COVERAGE")
    find_program(LCOV lcov)
    if(LCOV STREQUAL "LCOV-NOTFOUND")
        message(FATAL_ERROR "Unable to locate lcov")
    endif()
    if(NOT UNIX)
        message(FATAL_ERROR "Build type \"${CMAKE_BUILD_TYPE}\" only supported on Linux")
    endif()
    set(BUILD_EXAMPLES OFF)
    set(BUILD_TESTS ON)
    set(BSL_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    message(STATUS "Enabled LCOV Coverage Tools")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_RELEASE "-O3 -DNDEBUG -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_STATIC_ANALYSIS "-Og -g -Werror -Weverything -Wno-c++98-compat -Wno-padded -Wno-weak-vtables")
set(CMAKE_LINKER_FLAGS_STATIC_ANALYSIS "-Og -g -Werror -Weverything -Wno-c++98-compat -Wno-padded -Wno-weak-vtables")
set(CMAKE_CXX_FLAGS_SONARCLOUD "-Og -g -Werror -Wall -Wextra -Wpedantic")
set(CMAKE_LINKER_FLAGS_SONARCLOUD "-Og -g -Werror -Wall -Wextra -Wpedantic")
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

if(NOT BSL_BUILD_TYPE)
    message(FATAL_ERROR "Unknown build type \"${CMAKE_BUILD_TYPE}\"")
endif()

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

set(CMAKE_CXX_FLAGS "-fdiagnostics-color=auto")

# ------------------------------------------------------------------------------
# Static Analysis Tools
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
    list(APPEND CMAKE_CXX_CLANG_TIDY
        ${CLANG_TIDY}
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
    list(APPEND CMAKE_CXX_CPPCHECK
        ${CPPCHECK}
        --enable=all
        --error-exitcode=1
        --quiet
        --inline-suppr
        --suppress=unmatchedSuppression             # Handle different versions of CppCheck
        --suppress=missingInclude                   # Noisy warning
        --suppress=operatorEq                       # Mutually exclusive with Clang Tidy
        --suppress=throwInNoexceptFunction          # False positive, and duplicate with Clang Tidy
        --suppress=identicalConditionAfterEarlyExit # False positive with constexpr
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
# Format
# ------------------------------------------------------------------------------

find_program(CLANG_FORMAT clang-format)
if(NOT CLANG_FORMAT STREQUAL "CLANG_FORMAT-NOTFOUND")
    add_custom_target(
        format
        COMMAND find ${CMAKE_SOURCE_DIR}/examples -iname *.hpp -o -iname *.cpp | xargs clang-format -i
        COMMAND find ${CMAKE_SOURCE_DIR}/include -iname *.hpp -o -iname *.cpp | xargs clang-format -i
        COMMAND find ${CMAKE_SOURCE_DIR}/tests -iname *.hpp -o -iname *.cpp | xargs clang-format -i
    )
endif()

# ------------------------------------------------------------------------------
# Sonar Cloud
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "SONARCLOUD")
    add_custom_target(
        sonar-build
        COMMAND ${BUILD_WRAPPER} --out-dir ${CMAKE_BINARY_DIR}/bw_output make clean all
    )

    add_custom_target(
        sonar-upload
        COMMAND ${CMAKE_COMMAND} --build . --target sonar-build
        COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_SOURCE_DIR} ${SONAR_SCANNER}
        -Dsonar.login=81bb5447bd6ef44979b75e67ab255e7364408418
        -Dproject.settings=.sonarsource
        -Dsonar.cfamily.build-wrapper-output=${CMAKE_BINARY_DIR}/bw_output
    )
endif()

# ------------------------------------------------------------------------------
# Valgrind
# ------------------------------------------------------------------------------

find_program(VALGRIND valgrind)

# ------------------------------------------------------------------------------
# Flexlint
# ------------------------------------------------------------------------------

find_program(FLEXLINT flexlint)

# ------------------------------------------------------------------------------
# Info
# ------------------------------------------------------------------------------

add_custom_target(
    info
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta "  ____    ____    _     "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | __ )  / ___|  | |    "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " |  _ \\  \\___ \\  | | "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " | |_) |  ___) | | |___ "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta " |____/  |____/  |_____|"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --magenta ""
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " Please give us a star on: ${White}https://github.com/Bareflank/bsl$"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " BSL installation:"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make install                          installs BSL on your system"
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
    VERBATIM
)

if(UNIX)
    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " BSL build types:"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=Release            compile in release mode"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=Debug              compile in debug mode"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=STATIC_ANALYSIS    compile with Clang Tidy and CppCheck"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=SONARCLOUD         compile with SonarCloud"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=ASAN               compile with Google ASAN"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=MSAN               compile with Google MSAN"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=TSAN               compile with Google TSAN"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=UBSAN              compile with Google UBSAN"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   -DCMAKE_BUILD_TYPE=COVERAGE           compile with LCOV coverage"
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --green   " BSL build targets:"
        VERBATIM
    )

    if(NOT CLANG_FORMAT STREQUAL "CLANG_FORMAT-NOTFOUND")
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make format                           formats the source code"
            VERBATIM
        )
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "SONARCLOUD")
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make sonar-build                      build source for SonarCloud"
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make sonar-upload                     build/upload source for/to SonarCloud"
            VERBATIM
        )
    endif()

    if(BUILD_TESTS)
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make unittest                         runs the unittests"
            VERBATIM
        )
    endif()

    if(BUILD_TESTS AND NOT VALGRIND STREQUAL "VALGRIND-NOTFOUND")
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make memcheck                         runs the unittests with Valgrind"
            VERBATIM
        )
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "COVERAGE")
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make coverage                         runs the unittests with LCOV"
            VERBATIM
        )
    endif()

    if(UNIX AND NOT FLEXLINT STREQUAL "FLEXLINT-NOTFOUND")
        add_custom_command(TARGET info
            COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --yellow  "   make flexlint                         runs flexlint"
            VERBATIM
        )
    endif()

    add_custom_command(TARGET info
        COMMAND ${CMAKE_COMMAND} -E cmake_echo_color " "
        VERBATIM
    )
endif()
