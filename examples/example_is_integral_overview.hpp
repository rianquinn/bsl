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

#ifndef EXAMPLE_IS_INTEGRAL_OVERVIEW_HPP
#define EXAMPLE_IS_INTEGRAL_OVERVIEW_HPP

#include <bsl/cstdint.hpp>
#include <bsl/is_integral.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    inline void
    example_is_integral_overview() noexcept
    {
        static_assert(bsl::is_integral<bool>::value);
        static_assert(bsl::is_integral<bool const>::value);

        static_assert(bsl::is_integral<bsl::int8>::value);
        static_assert(bsl::is_integral<bsl::int16>::value);
        static_assert(bsl::is_integral<bsl::int32>::value);
        static_assert(bsl::is_integral<bsl::int64>::value);
        static_assert(bsl::is_integral<bsl::int8 const>::value);
        static_assert(bsl::is_integral<bsl::int16 const>::value);
        static_assert(bsl::is_integral<bsl::int32 const>::value);
        static_assert(bsl::is_integral<bsl::int64 const>::value);

        static_assert(bsl::is_integral<bsl::uint8>::value);
        static_assert(bsl::is_integral<bsl::uint16>::value);
        static_assert(bsl::is_integral<bsl::uint32>::value);
        static_assert(bsl::is_integral<bsl::uint64>::value);
        static_assert(bsl::is_integral<bsl::uint8 const>::value);
        static_assert(bsl::is_integral<bsl::uint16 const>::value);
        static_assert(bsl::is_integral<bsl::uint32 const>::value);
        static_assert(bsl::is_integral<bsl::uint64 const>::value);

        static_assert(bsl::is_integral<bsl::int_least8>::value);
        static_assert(bsl::is_integral<bsl::int_least16>::value);
        static_assert(bsl::is_integral<bsl::int_least32>::value);
        static_assert(bsl::is_integral<bsl::int_least64>::value);
        static_assert(bsl::is_integral<bsl::int_least8 const>::value);
        static_assert(bsl::is_integral<bsl::int_least16 const>::value);
        static_assert(bsl::is_integral<bsl::int_least32 const>::value);
        static_assert(bsl::is_integral<bsl::int_least64 const>::value);

        static_assert(bsl::is_integral<bsl::uint_least8>::value);
        static_assert(bsl::is_integral<bsl::uint_least16>::value);
        static_assert(bsl::is_integral<bsl::uint_least32>::value);
        static_assert(bsl::is_integral<bsl::uint_least64>::value);
        static_assert(bsl::is_integral<bsl::uint_least8 const>::value);
        static_assert(bsl::is_integral<bsl::uint_least16 const>::value);
        static_assert(bsl::is_integral<bsl::uint_least32 const>::value);
        static_assert(bsl::is_integral<bsl::uint_least64 const>::value);

        static_assert(bsl::is_integral<bsl::int_fast8>::value);
        static_assert(bsl::is_integral<bsl::int_fast16>::value);
        static_assert(bsl::is_integral<bsl::int_fast32>::value);
        static_assert(bsl::is_integral<bsl::int_fast64>::value);
        static_assert(bsl::is_integral<bsl::int_fast8 const>::value);
        static_assert(bsl::is_integral<bsl::int_fast16 const>::value);
        static_assert(bsl::is_integral<bsl::int_fast32 const>::value);
        static_assert(bsl::is_integral<bsl::int_fast64 const>::value);

        static_assert(bsl::is_integral<bsl::uint_fast8>::value);
        static_assert(bsl::is_integral<bsl::uint_fast16>::value);
        static_assert(bsl::is_integral<bsl::uint_fast32>::value);
        static_assert(bsl::is_integral<bsl::uint_fast64>::value);
        static_assert(bsl::is_integral<bsl::uint_fast8 const>::value);
        static_assert(bsl::is_integral<bsl::uint_fast16 const>::value);
        static_assert(bsl::is_integral<bsl::uint_fast32 const>::value);
        static_assert(bsl::is_integral<bsl::uint_fast64 const>::value);

        static_assert(bsl::is_integral<bsl::intptr>::value);
        static_assert(bsl::is_integral<bsl::uintptr>::value);
        static_assert(bsl::is_integral<bsl::intptr const>::value);
        static_assert(bsl::is_integral<bsl::uintptr const>::value);

        static_assert(bsl::is_integral<bsl::intmax>::value);
        static_assert(bsl::is_integral<bsl::uintmax>::value);
        static_assert(bsl::is_integral<bsl::intmax const>::value);
        static_assert(bsl::is_integral<bsl::uintmax const>::value);

        static_assert(!bsl::is_integral<void>::value);
        static_assert(!bsl::is_integral<void const>::value);
    }
}

#endif
