//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "../../include/bsl/int.hpp"
#include "../../include/bsl/ut.hpp"

constexpr const bsl::uint64_t g_i1{bsl::magic_64b_42u};
constexpr const bsl::uint64_t g_i2{bsl::magic_64b_23u};

static_assert(!(g_i1 == g_i2));
static_assert(g_i1 != g_i2);
static_assert(g_i1 > g_i2);
static_assert(g_i1 >= g_i2);
static_assert(!(g_i1 < g_i2));
static_assert(!(g_i1 <= g_i2));

auto
main() -> int
{
    // -------------------------------------------------------------------------
    // bsl::integer
    // -------------------------------------------------------------------------

    bsl::test_case("bsl::uint64_t == bsl::uint32_t") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::uint32_t i3{bsl::magic_23u};
        bsl::check(i1 == i2);
        bsl::check_false(i1 == i3);
    };

    bsl::test_case("bsl::uint64_t != bsl::uint32_t") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::uint32_t i3{bsl::magic_23u};
        bsl::check_false(i1 != i2);
        bsl::check(i1 != i3);
    };

    bsl::test_case("bsl::uint64_t > bsl::uint32_t") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::uint32_t i3{bsl::magic_23u};
        bsl::check_false(i1 > i2);
        bsl::check(i1 > i3);
    };

    bsl::test_case("bsl::uint64_t >= bsl::uint32_t") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::uint32_t i3{bsl::magic_23u};
        bsl::check(i1 >= i2);
        bsl::check(i1 >= i3);
    };

    bsl::test_case("bsl::uint64_t < bsl::uint32_t") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::uint32_t i3{bsl::magic_23u};
        bsl::check_false(i1 < i2);
        bsl::check_false(i1 < i3);
    };

    bsl::test_case("bsl::uint64_t <= bsl::uint32_t") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::uint32_t i3{bsl::magic_23u};
        bsl::check(i1 <= i2);
        bsl::check_false(i1 <= i3);
    };

    // -------------------------------------------------------------------------

    bsl::test_case("bsl::uint8_t == bsl::int32_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check(i1 == i2);
        bsl::check_false(i1 == i3);
        bsl::check_false(i1 == i4);
    };

    bsl::test_case("bsl::uint8_t != bsl::int32_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check_false(i1 != i2);
        bsl::check(i1 != i3);
        bsl::check(i1 != i4);
    };

    bsl::test_case("bsl::uint8_t < bsl::int32_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check_false(i1 < i2);
        bsl::check_false(i1 < i3);
        bsl::check_false(i1 < i4);
    };

    bsl::test_case("bsl::uint8_t <= bsl::int32_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check(i1 <= i2);
        bsl::check_false(i1 <= i3);
        bsl::check_false(i1 <= i4);
    };

    bsl::test_case("bsl::uint8_t > bsl::int32_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check_false(i1 > i2);
        bsl::check(i1 > i3);
        bsl::check(i1 > i4);
    };

    bsl::test_case("bsl::uint8_t >= bsl::int32_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check(i1 >= i2);
        bsl::check(i1 >= i3);
        bsl::check(i1 >= i4);
    };

    // -------------------------------------------------------------------------

    bsl::test_case("bsl::int32_t == bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check(i2 == i1);
        bsl::check_false(i3 == i1);
        bsl::check_false(i4 == i1);
    };

    bsl::test_case("bsl::int32_t != bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check_false(i2 != i1);
        bsl::check(i3 != i1);
        bsl::check(i4 != i1);
    };

    bsl::test_case("bsl::int32_t < bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check_false(i2 < i1);
        bsl::check(i3 < i1);
        bsl::check(i4 < i1);
    };

    bsl::test_case("bsl::int32_t <= bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check(i2 <= i1);
        bsl::check(i3 <= i1);
        bsl::check(i4 <= i1);
    };

    bsl::test_case("bsl::int32_t > bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check_false(i2 > i1);
        bsl::check_false(i3 > i1);
        bsl::check_false(i4 > i1);
    };

    bsl::test_case("bsl::int32_t >= bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::int32_t i2{bsl::magic_42};
        bsl::int32_t i3{bsl::magic_23};
        bsl::int32_t i4{-bsl::magic_23};
        bsl::check(i2 >= i1);
        bsl::check_false(i3 >= i1);
        bsl::check_false(i4 >= i1);
    };

    // -------------------------------------------------------------------------
    // literals
    // -------------------------------------------------------------------------

    bsl::test_case("bsl::uint64_t == unsigned literal") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::check(i1 == bsl::magic_42u);
        bsl::check_false(i1 == bsl::magic_23u);
    };

    bsl::test_case("bsl::uint64_t != unsigned literal") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::check_false(i1 != bsl::magic_42u);
        bsl::check(i1 != bsl::magic_23u);
    };

    bsl::test_case("bsl::uint64_t > unsigned literal") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::check_false(i1 > bsl::magic_42u);
        bsl::check(i1 > bsl::magic_23u);
    };

    bsl::test_case("bsl::uint64_t >= unsigned literal") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::check(i1 >= bsl::magic_42u);
        bsl::check(i1 >= bsl::magic_23u);
    };

    bsl::test_case("bsl::uint64_t < unsigned literal") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::check_false(i1 < bsl::magic_42u);
        bsl::check_false(i1 < bsl::magic_23u);
    };

    bsl::test_case("bsl::uint64_t <= unsigned literal") = [] {
        bsl::uint64_t i1{bsl::magic_64b_42u};
        bsl::check(i1 <= bsl::magic_42u);
        bsl::check_false(i1 <= bsl::magic_23u);
    };

    // -------------------------------------------------------------------------

    bsl::test_case("bsl::uint8_t == signed literal") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check(i1 == bsl::magic_42);
        bsl::check_false(i1 == bsl::magic_23);
        bsl::check_false(i1 == -bsl::magic_23);
    };

    bsl::test_case("bsl::uint8_t != signed literal") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check_false(i1 != bsl::magic_42);
        bsl::check(i1 != bsl::magic_23);
        bsl::check(i1 != -bsl::magic_23);
    };

    bsl::test_case("bsl::uint8_t < signed literal") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check_false(i1 < bsl::magic_42);
        bsl::check_false(i1 < bsl::magic_23);
        bsl::check_false(i1 < -bsl::magic_23);
    };

    bsl::test_case("bsl::uint8_t <= signed literal") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check(i1 <= bsl::magic_42);
        bsl::check_false(i1 <= bsl::magic_23);
        bsl::check_false(i1 <= -bsl::magic_23);
    };

    bsl::test_case("bsl::uint8_t > signed literal") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check_false(i1 > bsl::magic_42);
        bsl::check(i1 > bsl::magic_23);
        bsl::check(i1 > -bsl::magic_23);
    };

    bsl::test_case("bsl::uint8_t >= signed literal") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check(i1 >= bsl::magic_42);
        bsl::check(i1 >= bsl::magic_23);
        bsl::check(i1 >= -bsl::magic_23);
    };

    // -------------------------------------------------------------------------

    bsl::test_case("signed literal == bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check(bsl::magic_42 == i1);
        bsl::check_false(bsl::magic_23 == i1);
        bsl::check_false(-bsl::magic_23 == i1);
    };

    bsl::test_case("signed literal != bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check_false(bsl::magic_42 != i1);
        bsl::check(bsl::magic_23 != i1);
        bsl::check(-bsl::magic_23 != i1);
    };

    bsl::test_case("signed literal < bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check_false(bsl::magic_42 < i1);
        bsl::check(bsl::magic_23 < i1);
        bsl::check(-bsl::magic_23 < i1);
    };

    bsl::test_case("signed literal <= bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check(bsl::magic_42 <= i1);
        bsl::check(bsl::magic_23 <= i1);
        bsl::check(-bsl::magic_23 <= i1);
    };

    bsl::test_case("signed literal > bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check_false(bsl::magic_42 > i1);
        bsl::check_false(bsl::magic_23 > i1);
        bsl::check_false(-bsl::magic_23 > i1);
    };

    bsl::test_case("signed literal >= bsl::uint8_t") = [] {
        bsl::uint8_t i1{bsl::magic_8b_42u};
        bsl::check(bsl::magic_42 >= i1);
        bsl::check_false(bsl::magic_23 >= i1);
        bsl::check_false(-bsl::magic_23 >= i1);
    };

    // -------------------------------------------------------------------------

    return bsl::check_results();
}
