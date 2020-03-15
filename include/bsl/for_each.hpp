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
///
/// @file for_each.hpp
///

#ifndef BSL_FOREACH_HPP
#define BSL_FOREACH_HPP

#include "cstdint.hpp"
#include "enable_if.hpp"
#include "forward.hpp"
#include "invoke.hpp"
#include "is_invocable.hpp"
#include "is_nothrow_invocable.hpp"

namespace bsl
{
    // clang-format off

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Not that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the size of the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param f the function f to call
    ///   @return void
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr enable_if_t<is_invocable<FUNC, T &, bsl::uintmax>::value, void>
    for_each(T (&array)[N], FUNC && f)    // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T &, bsl::uintmax>::value)
    {
        for (bsl::uintmax i{}; i < N; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    /// <!-- description -->
    ///   @brief Loops through the array, and for each element in the array,
    ///     calls the provided function "f" with a reference to the array
    ///     element as well as the index of the element. Not that this version
    ///     loops through the array from 0 to N - 1.
    ///   @include example_for_each_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the array's element type
    ///   @tparam N the size of the array
    ///   @tparam FUNC The type the defines the function "f"
    ///   @param array the array to loop over
    ///   @param f the function f to call
    ///   @return void
    ///
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr enable_if_t<is_invocable<FUNC, T const &, bsl::uintmax>::value, void>
    for_each(T const (&array)[N], FUNC && f)    // NOLINT
        noexcept(is_nothrow_invocable<FUNC, T const &, bsl::uintmax>::value)
    {
        for (bsl::uintmax i{}; i < N; ++i) {
            invoke(bsl::forward<FUNC>(f), array[i], i);
        }
    }

    // clang-format on
}

#endif
