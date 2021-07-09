/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
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

#include "behavior_arithmetic.hpp"
#include "behavior_binary.hpp"
#include "behavior_make_safe.hpp"
#include "behavior_members.hpp"
#include "behavior_rational.hpp"
#include "behavior_shift.hpp"

/// <!-- description -->
///   @brief Main function for this unit test. If a call to bsl::ut_check() fails
///     the application will fast fail. If all calls to bsl::ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    static_assert(bsl::tests_arithmetic<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_arithmetic<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_arithmetic<bsl::uint8>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint16>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint32>());
    bsl::discard(bsl::tests_arithmetic<bsl::uint64>());
    bsl::discard(bsl::tests_arithmetic<bsl::uintmax>());
    bsl::discard(bsl::tests_arithmetic<bsl::int8>());
    bsl::discard(bsl::tests_arithmetic<bsl::int16>());
    bsl::discard(bsl::tests_arithmetic<bsl::int32>());
    bsl::discard(bsl::tests_arithmetic<bsl::int64>());
    bsl::discard(bsl::tests_arithmetic<bsl::intmax>());

    static_assert(bsl::tests_binary<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_binary<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_binary<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_binary<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_binary<bsl::uintmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_binary<bsl::uint8>());
    bsl::discard(bsl::tests_binary<bsl::uint16>());
    bsl::discard(bsl::tests_binary<bsl::uint32>());
    bsl::discard(bsl::tests_binary<bsl::uint64>());
    bsl::discard(bsl::tests_binary<bsl::uintmax>());

    static_assert(bsl::tests_make_safe<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_make_safe<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_make_safe<bsl::uint8>());
    bsl::discard(bsl::tests_make_safe<bsl::uint16>());
    bsl::discard(bsl::tests_make_safe<bsl::uint32>());
    bsl::discard(bsl::tests_make_safe<bsl::uint64>());
    bsl::discard(bsl::tests_make_safe<bsl::uintmax>());
    bsl::discard(bsl::tests_make_safe<bsl::int8>());
    bsl::discard(bsl::tests_make_safe<bsl::int16>());
    bsl::discard(bsl::tests_make_safe<bsl::int32>());
    bsl::discard(bsl::tests_make_safe<bsl::int64>());
    bsl::discard(bsl::tests_make_safe<bsl::intmax>());

    static_assert(bsl::tests_members<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_members<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_members<bsl::uint8>());
    bsl::discard(bsl::tests_members<bsl::uint16>());
    bsl::discard(bsl::tests_members<bsl::uint32>());
    bsl::discard(bsl::tests_members<bsl::uint64>());
    bsl::discard(bsl::tests_members<bsl::uintmax>());
    bsl::discard(bsl::tests_members<bsl::int8>());
    bsl::discard(bsl::tests_members<bsl::int16>());
    bsl::discard(bsl::tests_members<bsl::int32>());
    bsl::discard(bsl::tests_members<bsl::int64>());
    bsl::discard(bsl::tests_members<bsl::intmax>());

    static_assert(bsl::tests_rational<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::uintmax>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int8>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int16>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int32>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::int64>() == bsl::ut_success());
    static_assert(bsl::tests_rational<bsl::intmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_rational<bsl::uint8>());
    bsl::discard(bsl::tests_rational<bsl::uint16>());
    bsl::discard(bsl::tests_rational<bsl::uint32>());
    bsl::discard(bsl::tests_rational<bsl::uint64>());
    bsl::discard(bsl::tests_rational<bsl::uintmax>());
    bsl::discard(bsl::tests_rational<bsl::int8>());
    bsl::discard(bsl::tests_rational<bsl::int16>());
    bsl::discard(bsl::tests_rational<bsl::int32>());
    bsl::discard(bsl::tests_rational<bsl::int64>());
    bsl::discard(bsl::tests_rational<bsl::intmax>());

    static_assert(bsl::tests_shift<bsl::uint8>() == bsl::ut_success());
    static_assert(bsl::tests_shift<bsl::uint16>() == bsl::ut_success());
    static_assert(bsl::tests_shift<bsl::uint32>() == bsl::ut_success());
    static_assert(bsl::tests_shift<bsl::uint64>() == bsl::ut_success());
    static_assert(bsl::tests_shift<bsl::uintmax>() == bsl::ut_success());

    bsl::discard(bsl::tests_shift<bsl::uint8>());
    bsl::discard(bsl::tests_shift<bsl::uint16>());
    bsl::discard(bsl::tests_shift<bsl::uint32>());
    bsl::discard(bsl::tests_shift<bsl::uint64>());
    bsl::discard(bsl::tests_shift<bsl::uintmax>());

    return bsl::ut_success();
}
