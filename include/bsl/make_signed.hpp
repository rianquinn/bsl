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
/// @file make_signed.hpp
///

#ifndef BSL_MAKE_SIGNED_HPP
#define BSL_MAKE_SIGNED_HPP

#include "cstdint.hpp"
#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::make_signed
    ///
    /// <!-- description -->
    ///   @brief If the provided type is an unsigned type (taking into account
    ///     const qualifications), Provides the member typedef type which is
    ///     the same as T, except that the type is signed
    ///   @include make_signed/overview.cpp
    ///
    /// <!-- notes -->
    ///   @note We only support the cstdint.hpp basic fixed-width types
    ///     which is different compared to the standard library version of
    ///     this type trait. This is because, the fixed-width types are the
    ///     only types that we support.
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class make_signed final
    {};

    /// @brief a helper that reduces the verbosity of bsl::make_signed
    template<typename T>
    using make_signed_t = typename make_signed<T>::type;

    /// @cond

    template<>
    class make_signed<bsl::uint8> final : public type_identity<bsl::int8>
    {};

    template<>
    class make_signed<bsl::uint8 const> final : public type_identity<bsl::int8 const>
    {};

    template<>
    class make_signed<bsl::uint16> final : public type_identity<bsl::int16>
    {};

    template<>
    class make_signed<bsl::uint16 const> final : public type_identity<bsl::int16 const>
    {};

    template<>
    class make_signed<bsl::uint32> final : public type_identity<bsl::int32>
    {};

    template<>
    class make_signed<bsl::uint32 const> final : public type_identity<bsl::int32 const>
    {};

    template<>
    class make_signed<bsl::uint64> final : public type_identity<bsl::int64>
    {};

    template<>
    class make_signed<bsl::uint64 const> final : public type_identity<bsl::int64 const>
    {};

    /// @endcond
}

#endif
