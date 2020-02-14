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

#ifndef BSL_TEST_BIND_APIS_IMPL_HPP
#define BSL_TEST_BIND_APIS_IMPL_HPP

#include <bsl/cstdint.hpp>
#include <bsl/result.hpp>

namespace bsl
{
    /// @class bsl::test_bind_apis_impl
    ///
    /// <!-- description -->
    ///   @brief Defines a test class for the bind_apis API.
    ///
    /// <!-- template parameters -->
    ///   @tparam IMPL defines the implementation's type
    ///
    class test_bind_apis_impl final
    {
    public:
        /// <!-- description -->
        ///   @brief Tests a constructor that takes arguments
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param answer the answer to all of life's questions.
        ///
        explicit test_bind_apis_impl(bsl::int32 const answer) noexcept    // --
            : m_answer{answer}
        {}

        /// <!-- description -->
        ///   @brief Tests a constructor that takes arguments, and is capable
        ///     of returning an error. Note that if a constructor always
        ///     needs to return an error, the default constructor should be
        ///     marked as private to ensure "make" is always used. In this
        ///     examples we do not do that so that we can test the non-error
        ///     case.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param answer the answer to all of life's questions.
        ///
        static bsl::result<test_bind_apis_impl>
        make(bsl::int32 const answer) noexcept
        {
            if (answer == 42) {
                return {bsl::in_place, answer};
            }

            return {bsl::errc_failure, bsl::here()};
        }

        /// <!-- description -->
        ///   @brief Tests a static function
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param answer the answer to all of life's questions.
        ///   @return true if the answer is correct, false otherwise.
        ///
        static constexpr bool
        static_func_example(bsl::int32 const answer) noexcept
        {
            if (answer == 42) {
                return true;
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Tests a const member function
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param answer the answer to all of life's questions.
        ///   @return true if the answer is correct, false otherwise.
        ///
        constexpr bool
        member_func_example(bsl::int32 const answer) const noexcept
        {
            if (answer == m_answer) {
                return true;
            }

            return false;
        }

    private:
        bsl::int32 m_answer;
    };
}

#endif
