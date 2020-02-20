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
/// @file is_destructible.hpp
///

#ifndef BSL_IS_DESTRUCTIBLE_HPP
#define BSL_IS_DESTRUCTIBLE_HPP

#include "declval.hpp"
#include "is_detected.hpp"
#include "is_function.hpp"
#include "is_reference.hpp"
#include "is_scalar.hpp"
#include "is_unbounded_array.hpp"
#include "is_void.hpp"
#include "remove_all_extents.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief defines a destructor type
        template<typename T>
        using destructor_type = decltype(bsl::declval<T &>().~T());
    }

    /// @class bsl::is_destructible
    ///
    /// <!-- description -->
    ///   @brief If the provided type is destructible, provides the
    ///     member constant value equal to true. Otherwise the member constant
    ///     value is false.
    ///   @include is_destructible/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<
        typename T,
        bool = is_function<T>::value || is_void<T>::value || is_unbounded_array<T>::value,
        bool = is_reference<T>::value || is_scalar<T>::value>
    struct is_destructible final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{
            is_detected<details::destructor_type, remove_all_extents_t<T>>::value};
    };

    /// @cond --

    template<typename T, bool B>
    struct is_destructible<T, true, B> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{false};
    };

    template<typename T, bool B>
    struct is_destructible<T, B, true> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    /// @endcond --
}

#endif
