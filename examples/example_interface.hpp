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

#ifndef BSL_EXAMPLE_INTERACE_HPP
#define BSL_EXAMPLE_INTERACE_HPP

#include <bsl/cstdint.hpp>
#include <bsl/bind_apis.hpp>

namespace bsl
{
    /// @class bsl::example_interface
    ///
    /// <!-- description -->
    ///   @brief Defines an example interface for the bind_apis API.
    ///
    /// <!-- template parameters -->
    ///   @tparam IMPL defines the implementation's type
    ///
    template<typename IMPL>
    class example_interface
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        constexpr example_interface() noexcept = default;

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
            return IMPL::impl_type::static_func_example(answer);
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
        ~example_interface() noexcept = default;

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
        constexpr example_interface(example_interface const &o) noexcept = default;

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
        constexpr example_interface(example_interface &&o) noexcept = default;

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
        [[maybe_unused]] constexpr example_interface &
        operator=(example_interface const &o) &noexcept = default;

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
        [[maybe_unused]] constexpr example_interface &
        operator=(example_interface &&o) &noexcept = default;
    };
}

#endif
