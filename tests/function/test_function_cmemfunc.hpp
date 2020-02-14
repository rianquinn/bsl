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

#ifndef BSL_TEST_FUNCTION_CMEMFUNC_HPP
#define BSL_TEST_FUNCTION_CMEMFUNC_HPP

#include <bsl/cstdint.hpp>

namespace bsl
{
    /// @class bsl::test_function_cmemfunc
    ///
    /// <!-- description -->
    ///   @brief A simple class for testing bsl::function
    ///
    class test_function_cmemfunc final
    {
        /// @brief the answer to all questions.
        bsl::int32 m_answer{42};

    public:
        /// <!-- description -->
        ///   @brief Test function for bsl::function
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param answer the answer to all questions
        ///   @return true if answer is the answer to all questions
        ///
        [[nodiscard]] constexpr bool
        is_answer(bsl::int32 const &answer) const noexcept
        {
            if (answer == m_answer) {
                return true;
            }

            return false;
        }
    };
}

#endif
