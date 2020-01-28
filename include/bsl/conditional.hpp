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
/// @file conditional.hpp
///

#ifndef BSL_CONDITIONAL_HPP
#define BSL_CONDITIONAL_HPP

#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::conditional
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T
    ///     if B is true, otherwise is the same as U
    ///   @include conditional/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam B the conditional parameter
    ///   @tparam T the type to return if B is true
    ///   @tparam U the type to return if B is false
    ///
    template<bool B, typename T, typename U>
    class conditional final
    {};

    /// @brief a helper that reduces the verbosity of bsl::conditional
    template<bool B, typename T, typename U>
    using conditional_t = typename conditional<B, T, U>::type;

    /// @cond

    template<typename T, typename U>
    class conditional<true, T, U> final : public type_identity<T>
    {};

    template<typename T, typename U>
    class conditional<false, T, U> final : public type_identity<U>
    {};

    /// @endcond
}

#endif