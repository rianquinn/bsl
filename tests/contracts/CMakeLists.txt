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

bf_add_test(autosar_compliant_0
    DEFINES BSL_BUILD_LEVEL=2
    DEFINES BSL_EXIT_INSTEAD_OF_ABORT=true
)

bf_add_test(autosar_compliant_1
    DEFINES BSL_BUILD_LEVEL=2
    DEFINES BSL_AUTOSAR_COMPLIANT=true
)

bf_add_test(build_level_0
    DEFINES BSL_BUILD_LEVEL=0
    DEFINES BSL_CONTRACTS_THROW_ON_VIOLATION
)

bf_add_test(build_level_1
    DEFINES BSL_BUILD_LEVEL=1
    DEFINES BSL_CONTRACTS_THROW_ON_VIOLATION
)

bf_add_test(build_level_2
    DEFINES BSL_BUILD_LEVEL=2
    DEFINES BSL_CONTRACTS_THROW_ON_VIOLATION
)

bf_add_test(continue_option_0
    DEFINES BSL_BUILD_LEVEL=2
    DEFINES BSL_EXIT_INSTEAD_OF_ABORT=true
    DEFINES BSL_CONTRACTS_THROW_ON_VIOLATION
)

bf_add_test(continue_option_1
    DEFINES BSL_BUILD_LEVEL=2
    DEFINES BSL_CONTINUE_OPTION
    DEFINES BSL_CONTRACTS_THROW_ON_VIOLATION
)
