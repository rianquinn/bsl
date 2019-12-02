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

macro(bf_add_test NAME)
    add_executable(test_${NAME} ${NAME}.cpp)
    target_compile_options(test_${NAME} PRIVATE -fno-access-control)
    target_link_libraries(test_${NAME} PRIVATE fmt::fmt-header-only)
    add_test(test_${NAME} test_${NAME})
endmacro(bf_add_test)

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

# add_subdirectory(autosar)
add_subdirectory(contracts)
add_subdirectory(debug)
add_subdirectory(finally)
add_subdirectory(int)
add_subdirectory(source_location)
add_subdirectory(ut)

# ------------------------------------------------------------------------------
# Coverage Targets
# ------------------------------------------------------------------------------

if(CMAKE_BUILD_TYPE STREQUAL "COVERAGE")
    add_custom_target(
        unittest
        COMMAND lcov --zerocounters --directory . -q
        COMMAND ${CMAKE_COMMAND} -E chdir .. ctest --output-on-failure
    )

    add_custom_target(
        memcheck
        COMMAND lcov --zerocounters --directory . -q
        COMMAND ${CMAKE_COMMAND} -E chdir .. ctest --output-on-failure -T memcheck
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
else()
    add_custom_target(
        unittest
        COMMAND ${CMAKE_COMMAND} -E chdir .. ctest --output-on-failure
    )

    add_custom_target(
        memcheck
        COMMAND ${CMAKE_COMMAND} -E chdir .. ctest --output-on-failure -T memcheck
    )
endif()
