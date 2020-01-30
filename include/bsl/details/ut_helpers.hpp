/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef BSL_DETAILS_UT_HELPERS_HPP
#define BSL_DETAILS_UT_HELPERS_HPP

#include "../color.hpp"
#include "../cstr_type.hpp"
#include "../discard.hpp"
#include "../forward.hpp"
#include "../main.hpp"
#include "../new.hpp"
#include "../source_location.hpp"

#include <cstdio>     // PRQA S 5188
#include <cstdlib>    // PRQA S 5188

namespace bsl
{
    namespace details
    {
        using ut_test_handler_type = void (*)();

        template<typename T = void>
        cstr_type &
        ut_current_test_case() noexcept
        {
            static cstr_type s_ut_current_test_case{};
            return s_ut_current_test_case;
        }

        template<typename T = void>
        ut_test_handler_type &
        ut_reset_handler() noexcept
        {
            static ut_test_handler_type s_ut_reset_handler{};
            return s_ut_reset_handler;
        }

        template<typename T = void>
        void
        ut_output_here(sloc_type const &sloc) noexcept
        {
            printf("  --> ");
            printf("%s%s%s", yellow, sloc.file_name(), reset_color);
            printf(": ");
            printf("%s%d%s", cyan, sloc.line(), reset_color);
            printf("\n");
        }
    }
}

#endif
