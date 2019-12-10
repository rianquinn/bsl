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

bf_add_test(arithmetic)
target_compile_definitions(test_arithmetic PRIVATE BSL_AUTOSAR_COMPLIANT)
target_compile_definitions(test_arithmetic PRIVATE BSL_BUILD_LEVEL=2)

bf_add_test(constructors)
target_compile_definitions(test_constructors PRIVATE BSL_AUTOSAR_COMPLIANT)
target_compile_definitions(test_constructors PRIVATE BSL_BUILD_LEVEL=2)

bf_add_test(is_integer)
target_compile_definitions(test_is_integer PRIVATE BSL_AUTOSAR_COMPLIANT)
target_compile_definitions(test_is_integer PRIVATE BSL_BUILD_LEVEL=2)

bf_add_test(convert)
target_compile_definitions(test_convert PRIVATE BSL_AUTOSAR_COMPLIANT)
target_compile_definitions(test_convert PRIVATE BSL_BUILD_LEVEL=2)

bf_add_test(rational)
target_compile_definitions(test_rational PRIVATE BSL_AUTOSAR_COMPLIANT)
target_compile_definitions(test_rational PRIVATE BSL_BUILD_LEVEL=2)
