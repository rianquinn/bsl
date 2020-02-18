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

#ifndef EXAMPLE_IS_SIGNED__OVERVIEW_HPP
#define EXAMPLE_IS_SIGNED__OVERVIEW_HPP

#include <bsl/discard.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/arguments.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/is_signed.hpp>
#include <bsl/make_signed.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments passed to the application
    ///   @return exit_success on success, exit_failure otherwise
    ///
    [[maybe_unused]] inline bsl::exit_code
    example_is_signed__overview(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);

        static_assert(bsl::is_signed<bsl::int8>::value);
        static_assert(bsl::is_signed<bsl::int16>::value);
        static_assert(bsl::is_signed<bsl::int32>::value);
        static_assert(bsl::is_signed<bsl::int64>::value);
        static_assert(bsl::is_signed<bsl::int8 const>::value);
        static_assert(bsl::is_signed<bsl::int16 const>::value);
        static_assert(bsl::is_signed<bsl::int32 const>::value);
        static_assert(bsl::is_signed<bsl::int64 const>::value);

        static_assert(!bsl::is_signed<bsl::uint8>::value);
        static_assert(!bsl::is_signed<bsl::uint16>::value);
        static_assert(!bsl::is_signed<bsl::uint32>::value);
        static_assert(!bsl::is_signed<bsl::uint64>::value);
        static_assert(!bsl::is_signed<bsl::uint8 const>::value);
        static_assert(!bsl::is_signed<bsl::uint16 const>::value);
        static_assert(!bsl::is_signed<bsl::uint32 const>::value);
        static_assert(!bsl::is_signed<bsl::uint64 const>::value);

        static_assert(bsl::is_signed<bsl::int_least8>::value);
        static_assert(bsl::is_signed<bsl::int_least16>::value);
        static_assert(bsl::is_signed<bsl::int_least32>::value);
        static_assert(bsl::is_signed<bsl::int_least64>::value);
        static_assert(bsl::is_signed<bsl::int_least8 const>::value);
        static_assert(bsl::is_signed<bsl::int_least16 const>::value);
        static_assert(bsl::is_signed<bsl::int_least32 const>::value);
        static_assert(bsl::is_signed<bsl::int_least64 const>::value);

        static_assert(!bsl::is_signed<bsl::uint_least8>::value);
        static_assert(!bsl::is_signed<bsl::uint_least16>::value);
        static_assert(!bsl::is_signed<bsl::uint_least32>::value);
        static_assert(!bsl::is_signed<bsl::uint_least64>::value);
        static_assert(!bsl::is_signed<bsl::uint_least8 const>::value);
        static_assert(!bsl::is_signed<bsl::uint_least16 const>::value);
        static_assert(!bsl::is_signed<bsl::uint_least32 const>::value);
        static_assert(!bsl::is_signed<bsl::uint_least64 const>::value);

        static_assert(bsl::is_signed<bsl::int_fast8>::value);
        static_assert(bsl::is_signed<bsl::int_fast16>::value);
        static_assert(bsl::is_signed<bsl::int_fast32>::value);
        static_assert(bsl::is_signed<bsl::int_fast64>::value);
        static_assert(bsl::is_signed<bsl::int_fast8 const>::value);
        static_assert(bsl::is_signed<bsl::int_fast16 const>::value);
        static_assert(bsl::is_signed<bsl::int_fast32 const>::value);
        static_assert(bsl::is_signed<bsl::int_fast64 const>::value);

        static_assert(!bsl::is_signed<bsl::uint_fast8>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast16>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast32>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast64>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast8 const>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast16 const>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast32 const>::value);
        static_assert(!bsl::is_signed<bsl::uint_fast64 const>::value);

        static_assert(bsl::is_signed<bsl::intptr>::value);
        static_assert(!bsl::is_signed<bsl::uintptr>::value);
        static_assert(bsl::is_signed<bsl::intptr const>::value);
        static_assert(!bsl::is_signed<bsl::uintptr const>::value);

        static_assert(bsl::is_signed<bsl::intmax>::value);
        static_assert(!bsl::is_signed<bsl::uintmax>::value);
        static_assert(bsl::is_signed<bsl::intmax const>::value);
        static_assert(!bsl::is_signed<bsl::uintmax const>::value);

        static_assert(!bsl::is_signed<bool>::value);
        static_assert(!bsl::is_signed<bool const>::value);

        static_assert(!bsl::is_signed<void>::value);
        static_assert(!bsl::is_signed<void const>::value);

        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint8>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint16>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint32>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint64>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint8 const>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint16 const>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint32 const>>::value);
        static_assert(bsl::is_signed<bsl::make_signed_t<bsl::uint64 const>>::value);

        return bsl::exit_code::exit_success;
    }
}

#endif
