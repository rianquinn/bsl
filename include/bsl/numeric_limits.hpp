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
        /// @brief stores whether or not T is an integer
        static constexpr bool is_integer{false};
        /// @brief stores whether or not T is exact
        static constexpr bool is_exact{false};
        /// @brief stores whether or not
        static constexpr bool has_infinity{false};
        /// @brief stores whether or not
        static constexpr bool has_quiet_NaN{false};
        /// @brief stores whether or not
        static constexpr bool has_signaling_NaN{false};
        /// @brief stores whether or not
        static constexpr bool has_denorm{false};
        /// @brief stores whether or not
        static constexpr bool has_denorm_loss{false};
        /// @brief stores whether or not
        static constexpr bool round_style{false};
        /// @brief stores whether or not
        static constexpr bool is_iec559{false};
        /// @brief stores whether or not
        static constexpr bool round_style{false};
        /// @brief stores whether or not T is bounded
        static constexpr bool is_bounded{false};
        /// @brief stores whether or not T is modulo
        static constexpr bool is_modulo{false};



identifies the floating-point types that detect loss of precision as denormalization loss rather than inexact result
(public static member constant)


[static]

identifies the rounding style used by the type
(public static member constant)


[static]

identifies the IEC 559/IEEE 754 floating-point types
(public static member constant)
is_bounded

[static]

identifies types that represent a finite set of values
(public static member constant)
is_modulo

[static]

identifies types that handle overflows with modulo arithmetic
(public static member constant)
digits

[static]

number of radix digits that can be represented without change
(public static member constant)
digits10

[static]

number of decimal digits that can be represented without change
(public static member constant)
max_digits10

[static](C++11)

number of decimal digits necessary to differentiate all values of this type
(public static member constant)
radix

[static]

the radix or integer base used by the representation of the given type
(public static member constant)
min_exponent

[static]

one more than the smallest negative power of the radix that is a valid normalized floating-point value
(public static member constant)
min_exponent10

[static]

the smallest negative power of ten that is a valid normalized floating-point value
(public static member constant)
max_exponent

[static]

one more than the largest integer power of the radix that is a valid finite floating-point value
(public static member constant)
max_exponent10

[static]

the largest integer power of 10 that is a valid finite floating-point value
(public static member constant)
traps

[static]

identifies types which can cause arithmetic operations to trap
(public static member constant)
tinyness_before

[static]

identifies floating-point types that detect tinyness before rounding
(public static member constant)














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
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{false};
        static constexpr bool min{false};
        static constexpr bool max{true};
    };

    template<>
    struct numeric_limits<bsl::int8> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::int8 min{-0x7F - 1};
        static constexpr bsl::int8 max{0x7F};
    };

    template<>
    struct numeric_limits<bsl::int16> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::int16 min{-0x7F'FF - 1};
        static constexpr bsl::int16 max{0x7F'FF};
    };

    template<>
    struct numeric_limits<bsl::int32> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::int32 min{-0x7F'FF'FF'FF - 1};
        static constexpr bsl::int32 max{0x7F'FF'FF'FF};
    };

    template<>
    struct numeric_limits<bsl::int64> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{true};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::int64 min{-0x7F'FF'FF'FF'FF'FF'FF'FF - 1};
        static constexpr bsl::int64 max{0x7F'FF'FF'FF'FF'FF'FF'FF};
    };

    template<>
    struct numeric_limits<bsl::uint8> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::uint8 min{0U};
        static constexpr bsl::uint8 max{0xFFU};
    };

    template<>
    struct numeric_limits<bsl::uint16> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::uint16 min{0U};
        static constexpr bsl::uint16 max{0xFF'FFU};
    };

    template<>
    struct numeric_limits<bsl::uint32> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::uint32 min{0U};
        static constexpr bsl::uint32 max{0xFF'FF'FF'FFU};
    };

    template<>
    struct numeric_limits<bsl::uint64> final
    {
        static constexpr bool is_specialized{true};
        static constexpr bool is_signed{false};
        static constexpr bool is_integer{true};
        static constexpr bool is_exact{true};
        static constexpr bool is_bounded{true};
        static constexpr bool is_modulo{true};
        static constexpr bsl::uint64 min{0U};
        static constexpr bsl::uint64 max{0xFF'FF'FF'FF'FF'FF'FF'FFU};
    };

    /// @endcond --
}

#endif
