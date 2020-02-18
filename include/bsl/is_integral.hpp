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
/// @file is_integral.hpp
///

#ifndef BSL_IS_INTEGRAL_HPP
#define BSL_IS_INTEGRAL_HPP

#include "cstdint.hpp"

namespace bsl
{
    /// @class bsl::is_integral
    ///
    /// <!-- description -->
    ///   @brief If the provided type is an integral type (taking into account
    ///     const qualifications), provides the member constant value
    ///     equal to true. Otherwise the member constant value is false.
    ///   @include is_integral/overview.cpp
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
    struct is_integral final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{false};
    };

    /// @cond

    template<>
    struct is_integral<bool> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bool const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int8> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int8 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int16> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int16 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int32> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int32 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int64> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::int64 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint8> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint8 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint16> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint16 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint32> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint32 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint64> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    template<>
    struct is_integral<bsl::uint64 const> final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{true};
    };

    /// @endcond
}

#endif
