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

#ifndef BSL_DETAILS_INVOKE_RESULT_BASE_HPP
#define BSL_DETAILS_INVOKE_RESULT_BASE_HPP

#include "invoke_impl.hpp"
#include "../declval.hpp"
#include "../type_identity.hpp"
#include "../void_t.hpp"

namespace bsl
{
    namespace details
    {
        template<typename F, typename... ARGS>
        using invoke_impl_type = decltype(invoke_impl(declval<F>(), declval<ARGS>()...));

        template<typename AlwaysVoid, typename F, typename... ARGS>
        class invoke_result_base
        {
        protected:
            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr invoke_result_base(invoke_result_base const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr invoke_result_base(invoke_result_base &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr invoke_result_base &    // --
            operator=(invoke_result_base const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr invoke_result_base &    // --
            operator=(invoke_result_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_result_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~invoke_result_base() noexcept = default;
        };

        template<typename F, typename... ARGS>
        class invoke_result_base<void_t<invoke_impl_type<F, ARGS...>>, F, ARGS...> :
            public type_identity<invoke_impl_type<F, ARGS...>>
        {
        protected:
            /// <!-- description -->
            ///   @brief copy constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///
            constexpr invoke_result_base(invoke_result_base const &o) noexcept = default;

            /// <!-- description -->
            ///   @brief move constructor
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///
            constexpr invoke_result_base(invoke_result_base &&o) noexcept = default;

            /// <!-- description -->
            ///   @brief copy assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being copied
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr invoke_result_base &    // --
            operator=(invoke_result_base const &o) &noexcept = default;

            /// <!-- description -->
            ///   @brief move assignment
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            /// <!-- inputs/outputs -->
            ///   @param o the object being moved
            ///   @return a reference to *this
            ///
            [[maybe_unused]] constexpr invoke_result_base &    // --
            operator=(invoke_result_base &&o) &noexcept = default;

            /// <!-- description -->
            ///   @brief Destroyes a previously created bsl::invoke_result_base
            ///
            /// <!-- contracts -->
            ///   @pre none
            ///   @post none
            ///
            ~invoke_result_base() noexcept = default;
        };
    }
}

#endif
