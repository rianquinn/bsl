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

#ifndef BSL_NUMERIC_LIMITS_HPP
#define BSL_NUMERIC_LIMITS_HPP

#include "cstdint.hpp"

namespace bsl
{
    /// @class bsl::numeric_limits
    ///
    /// <!-- description -->
    ///   @brief Provides an interface similar to a std::numeric_limits.
    ///     Since we do not support floating point, most of this class is
    ///     not needed. We do, however, provide support for all of the
    ///     fixed width types as well as the built-in types that AUTOSAR
    ///     states are valid to use. Also note that the entire interface
    ///     is written using static variables (i.e., there are no
    ///     static member functions) as these cannot coexist with AUTOSAR,
    ///     and there is no reason for min(), max() to be a function.
    ///   @include numeric_limits/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to get information about
    ///
    template<typename T>
    struct numeric_limits final
    {
        /// @brief stores whether or not this is a specialization
        static constexpr bool is_specialized{false};
        /// @brief stores whether or not T is signed
        static constexpr bool is_signed{false};
        /// @brief stores the min value of T
        static constexpr T min{};
        /// @brief stores the max value of T
        static constexpr T max{};
    };

    /// @cond --

    template<>
    struct numeric_limits<bool> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bool min{false};
        static constexpr bool max{true};
    };

    template<>
    struct numeric_limits<bsl::int8> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bsl::int8 min{-0x7F - 1};
        static constexpr bsl::int8 max{0x7F};
    };

    template<>
    struct numeric_limits<bsl::int16> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bsl::int16 min{-0x7F'FF - 1};
        static constexpr bsl::int16 max{0x7F'FF};
    };

    template<>
    struct numeric_limits<bsl::int32> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bsl::int32 min{-0x7F'FF'FF'FF - 1};
        static constexpr bsl::int32 max{0x7F'FF'FF'FF};
    };

    template<>
    struct numeric_limits<bsl::int64> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bsl::int64 min{-0x7F'FF'FF'FF'FF'FF'FF'FF - 1};
        static constexpr bsl::int64 max{0x7F'FF'FF'FF'FF'FF'FF'FF};
    };

    template<>
    struct numeric_limits<bsl::uint8> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bsl::uint8 min{0U};
        static constexpr bsl::uint8 max{0xFFU};
    };

    template<>
    struct numeric_limits<bsl::uint16> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bsl::uint16 min{0U};
        static constexpr bsl::uint16 max{0xFF'FFU};
    };

    template<>
    struct numeric_limits<bsl::uint32> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bsl::uint32 min{0U};
        static constexpr bsl::uint32 max{0xFF'FF'FF'FFU};
    };

    template<>
    struct numeric_limits<bsl::uint64> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bsl::uint64 min{0U};
        static constexpr bsl::uint64 max{0xFF'FF'FF'FF'FF'FF'FF'FFU};
    };

    /// @endcond --
}

#endif
