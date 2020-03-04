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
/// @file swap.hpp
///

#ifndef BSL_SWAP_HPP
#define BSL_SWAP_HPP

#include "move.hpp"
#include "enable_if.hpp"
#include "is_move_assignable.hpp"
#include "is_move_constructible.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Exchanges the given values.
    ///   @include swap/overview.cpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type that defines the values being swapped
    ///   @param lhs the value being swapped with b
    ///   @param rhs the value being swapped with a
    ///
    template<
        typename T,
        enable_if_t<is_move_assignable<T>::value> = true,
        enable_if_t<is_move_constructible<T>::value> = true>
    constexpr void
    swap(T &lhs, T &rhs) noexcept
    {
        T tmp{bsl::move(lhs)};
        lhs = bsl::move(rhs);
        rhs = bsl::move(tmp);
    }
}

//    template <typename T>
//     constexpr auto swap(T& x, T& y) noexcept
//         -> enable_if_ty<is_move_constructible_v<T> && is_move_assignable_v<T>>
//     {
//         auto t = T(bml::move(x));
//         x = bml::move(y);
//         y = bml::move(t);
//     }

//     template <typename T, ::ptrdiff_t N>
//     constexpr auto swap(T (&x)[N], T (&y)[N]) noexcept -> enable_if_ty<is_swappable<T>::value>;

//     // Forward declaration of the swap overload for array to allow swap_ranges to deal with nested
//     // arrays.
//     template <typename T>
//     struct is_swappable;

//     template <typename ForwardIt1, typename ForwardIt2>
//     constexpr auto swap_ranges(ForwardIt1 first1, ForwardIt1 last1, ForwardIt2 first2) noexcept
//         -> ForwardIt2
//     {
//         while (first1 != last1)
//         {
//             // Note: ADL for swap explicitly wanted here to find user-defined swaps.
//             swap(*first1, *first2);

//             static_cast<void>(++first1);
//             static_cast<void>(++first2);
//         }

//         return first2;
//     }

//     template <typename T, ::ptrdiff_t N>
//     constexpr auto swap(T (&x)[N], T (&y)[N]) noexcept -> enable_if_ty<is_swappable<T>::value>
//     {
//         static_cast<void>(bml::swap_ranges(x, x + N, y));
//     }

//     namespace detail::is_swappable_with_detail
//     {
//         // Note: ADL for swap is explicitly wanted here to find user-defined swaps.
//         template <typename T, typename U>
//         using check = decltype(swap(bml::declval<T>(), bml::declval<U>()));
//     }

//     template <typename T, typename U>
//     struct is_swappable_with : bool_constant<
//            is_detected_v<detail::is_swappable_with_detail::check, T, U>
//         && is_detected_v<detail::is_swappable_with_detail::check, U, T>>
//     {};

//     template <typename T, typename U>
//     inline constexpr auto is_swappable_with_v = bool(is_swappable_with<T, U>::value);

//     template <typename T>
//     struct is_swappable
//         : is_swappable_with<add_lvalue_reference_ty<T>, add_lvalue_reference_ty<T>> {};

//     template <typename T>
//     inline constexpr auto is_swappable_v = bool(is_swappable<T>::value);
#endif
