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

# ------------------------------------------------------------------------------
# C++ Standard
# ------------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)

# ------------------------------------------------------------------------------
# default build type
# ------------------------------------------------------------------------------

if(NOT UNIX)
    set(CMAKE_BUILD_TYPE Release)   # we only support Release in Windows
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------

    find_program(CLANG_TIDY clang-tidy)
    if(CLANG_TIDY STREQUAL "CLANG_TIDY-NOTFOUND")
        message(FATAL_ERROR "Unable to locate clang-tidy")
    endif()

# ------------------------------------------------------------------------------
# Development Mode
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS OFF)
    message(STATUS "Enabled CMake's Release mode")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BUILD_EXAMPLES ON)
    set(BUILD_TESTS ON)
    message(STATUS "Enabled CMake's Debug mode")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "STATIC_ANALYSIS")
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
set(CMAKE_CXX_FLAGS_STATIC_ANALYSIS "-Og -g -Werror -Weverything -Wno-c++98-compat -Wno-padded -Wno-weak-vtables -Wno-missing-noreturn")
set(CMAKE_LINKER_FLAGS_STATIC_ANALYSIS "-Og -g -Werror -Weverything -Wno-c++98-compat -Wno-padded -Wno-weak-vtables -Wno-missing-noreturn")
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
