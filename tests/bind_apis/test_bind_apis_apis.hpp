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

#ifndef BSL_TEST_BIND_APIS_APIS_HPP
#define BSL_TEST_BIND_APIS_APIS_HPP

#include <bsl/cstdint.hpp>
#include <bsl/bind_apis.hpp>

namespace bsl
{
    /// @class bsl::test_bind_apis_apis
    ///
    /// <!-- description -->
    ///   @brief Defines a test class for the bind_apis API.
    ///
    /// <!-- template parameters -->
    ///   @tparam IMPL defines the implementation's type
    ///
    template<typename IMPL>
    class test_bind_apis_apis
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        constexpr test_bind_apis_apis() noexcept = default;

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
        [[nodiscard]] static constexpr bool
        static_func_example(bsl::int32 const answer) noexcept
        {
            return IMPL::impl_type::static_func_example(answer);
        }

        /// <!-- description -->
        ///   @brief Tests a member function
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param answer the answer to all of life's questions.
        ///   @return true if the answer is correct, false otherwise.
        ///
        [[nodiscard]] constexpr bool
        member_func_example(bsl::int32 const answer) noexcept
        {
            return IMPL::impl(*this).member_func_example(answer);
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
        [[nodiscard]] constexpr bool
        member_func_example(bsl::int32 const answer) const noexcept
        {
            return IMPL::impl(*this).member_func_example(answer);
        }

    protected:
        /// <!-- description -->
        ///   @brief default destructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~test_bind_apis_apis() noexcept = default;

        /// <!-- description -->
        ///   @brief default copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr test_bind_apis_apis(test_bind_apis_apis const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief default move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr test_bind_apis_apis(test_bind_apis_apis &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief default copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr test_bind_apis_apis &
        operator=(test_bind_apis_apis const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief default move assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr test_bind_apis_apis &
        operator=(test_bind_apis_apis &&o) &noexcept = default;
    };

    /// @brief defines the test_bind_apis type
    template<typename D>
    using test_bind_apis = bind_apis<test_bind_apis_apis, D>;
}

#endif
