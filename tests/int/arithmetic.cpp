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

constexpr const bsl::uint32_t g_uint32_max{bsl::uint32_t::max()};
constexpr const bsl::uint32_t g_uint32_min{bsl::uint32_t::min()};
constexpr const bsl::uint32_t g_uint32_max_m_1{bsl::uint32_t::max() - 1};
constexpr const bsl::uint32_t g_uint32_min_p_1{bsl::uint32_t::min() + 1};
constexpr const bsl::uint32_t g_uint32_min_s_1{bsl::uint32_t::max() >> 1U};
constexpr const bsl::uint32_t g_uint32_magic42{bsl::magic_42u};

static_assert(g_uint32_magic42 == g_uint32_magic42);    // NOLINT
static_assert(g_uint32_magic42 != g_uint32_max);        // NOLINT
static_assert(g_uint32_magic42 > g_uint32_min);
static_assert(g_uint32_magic42 >= g_uint32_magic42);    // NOLINT
static_assert(g_uint32_magic42 < g_uint32_max);
static_assert(g_uint32_magic42 <= g_uint32_magic42);    // NOLINT
static_assert(g_uint32_max_m_1 + 1U == g_uint32_max);
static_assert(g_uint32_min_p_1 - 1U == g_uint32_min);
static_assert(g_uint32_magic42 * g_uint32_magic42 != 0);
static_assert(g_uint32_magic42 / g_uint32_magic42 == 1);    // NOLINT
static_assert(g_uint32_magic42 % g_uint32_magic42 == 0);    // NOLINT
static_assert((g_uint32_min_s_1 << 1) == bsl::uint32_t::max() - 1);
static_assert((g_uint32_min_s_1 >> (bsl::uint32_t::digits() - 1)) == 0);
static_assert((g_uint32_magic42 & g_uint32_magic42) != 0); // NOLINT
static_assert((g_uint32_magic42 | g_uint32_magic42) != 0); // NOLINT
static_assert((g_uint32_magic42 ^ g_uint32_magic42) == 0);    // NOLINT
static_assert(~g_uint32_magic42 == ~bsl::magic_42u);
static_assert(+g_uint32_magic42 == bsl::magic_64b_42u);

constexpr const bsl::int32_t g_int32_max{bsl::int32_t::max()};
constexpr const bsl::int32_t g_int32_min{bsl::int32_t::min()};
constexpr const bsl::int32_t g_int32_max_m_1{bsl::int32_t::max() - 1};
constexpr const bsl::int32_t g_int32_min_p_1{bsl::int32_t::min() + 1};
constexpr const bsl::int32_t g_int32_magic42{bsl::magic_42};

static_assert(g_int32_magic42 == g_int32_magic42);    // NOLINT
static_assert(g_int32_magic42 != g_int32_max);        // NOLINT
static_assert(g_int32_magic42 > g_int32_min);
static_assert(g_int32_magic42 >= g_int32_magic42);    // NOLINT
static_assert(g_int32_magic42 < g_int32_max);
static_assert(g_int32_magic42 <= g_int32_magic42);    // NOLINT
static_assert(g_int32_max_m_1 + 1 == g_int32_max);
static_assert(g_int32_min_p_1 - 1 == g_int32_min);
static_assert(g_int32_magic42 * g_int32_magic42 != 0);
static_assert(g_int32_magic42 / g_int32_magic42 == 1);    // NOLINT
static_assert(g_int32_magic42 % g_int32_magic42 == 0);    // NOLINT
static_assert(-g_int32_magic42 == -bsl::magic_42);
static_assert(+g_int32_magic42 == bsl::magic_64b_42);

auto
main() -> int
{

    // -------------------------------------------------------------------------
    // - signed addition
    // -------------------------------------------------------------------------

    bsl::test_case("int32_t + magic success") = [] {
        bsl::int32_t i{bsl::magic_42};
        bsl::check(i + bsl::magic_42 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("magic success + int32_t") = [] {
        bsl::int32_t i{bsl::magic_42};
        bsl::check(bsl::magic_42 + i == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int32_t + int32_t success") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int32_t + int32_t lhs max") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int32_t + int32_t rhs max") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int32_t + int32_t both max") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int32_t - int32_t success lhs neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == -bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t success rhs neg") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check(i1 + i2 == 0);
    };

    bsl::test_case("int32_t - int32_t success both neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check(i1 + i2 == -bsl::magic_42 - bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t lhs max lhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::int32_t::min() + bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t lhs max rhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check(i1 + i2 == bsl::int32_t::max() - bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t lhs max both neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int32_t - int32_t rhs max lhs neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check(i1 + i2 == -bsl::magic_42 + bsl::int32_t::max());
    };

    bsl::test_case("int32_t - int32_t rhs max rhs neg") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::int32_t::min());
    };

    bsl::test_case("int32_t - int32_t rhs max both neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int32_t - int32_t both max lhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check(i1 + i2 == bsl::int32_t::min() + bsl::int32_t::max());
    };

    bsl::test_case("int32_t - int32_t both max rhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check(i1 + i2 == bsl::int32_t::max() + bsl::int32_t::min());
    };

    bsl::test_case("int32_t - int32_t both max both neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    // -------------------------------------------------------------------------
    // - unsigned addition
    // -------------------------------------------------------------------------

    bsl::test_case("uint32_t + magic success") = [] {
        bsl::uint32_t i{bsl::magic_42u};
        bsl::check(i + bsl::magic_42u == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("magic success + uint32_t") = [] {
        bsl::uint32_t i{bsl::magic_42u};
        bsl::check(bsl::magic_42u + i == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("uint32_t + uint32_t success") = [] {
        bsl::uint32_t i1{bsl::magic_42u};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("uint32_t + uint32_t lhs max") = [] {
        bsl::uint32_t i1{bsl::uint32_t::max()};
        bsl::uint32_t i2{bsl::magic_42u};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("uint32_t + uint32_t rhs max") = [] {
        bsl::uint32_t i1{bsl::magic_42u};
        bsl::uint32_t i2{bsl::uint32_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("uint32_t + uint32_t both max") = [] {
        bsl::uint32_t i1{bsl::uint32_t::max()};
        bsl::uint32_t i2{bsl::uint32_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    // -------------------------------------------------------------------------
    // - signed subtract
    // -------------------------------------------------------------------------

    // bsl::test_case("int32_t - magic success") = [] {
    //     bsl::int32_t i{bsl::magic_42};
    //     bsl::check(i - bsl::magic_42 == bsl::magic_42 - bsl::magic_42);
    // };

    // bsl::test_case("magic success - int32_t") = [] {
    //     bsl::int32_t i{bsl::magic_42};
    //     bsl::check(bsl::magic_42 - i == bsl::magic_42 - bsl::magic_42);
    // };

    // bsl::test_case("int32_t - int32_t success") = [] {
    //     bsl::int32_t i1{bsl::magic_42};
    //     bsl::int32_t i2{bsl::magic_42};
    //     bsl::check(i1 - i2 == bsl::magic_42 - bsl::magic_42);
    // };

    bsl::test_case("int32_t - int32_t lhs max") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check(i1 - i2 == bsl::int32_t::max() - bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t rhs max") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check(i1 - i2 == bsl::magic_42 - bsl::int32_t::max());
    };

    bsl::test_case("int32_t - int32_t both max") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check(i1 - i2 == 0);
    };

    bsl::test_case("int32_t - int32_t success lhs neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check(i1 - i2 == -bsl::magic_42 - bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t success rhs neg") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check(i1 - i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t success both neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check(i1 - i2 == 0);
    };

    bsl::test_case("int32_t - int32_t lhs max lhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 - i2);
        });
    };

    bsl::test_case("int32_t - int32_t lhs max rhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 - i2);
        });
    };

    bsl::test_case("int32_t - int32_t lhs max both neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{-bsl::magic_42};
        bsl::check(i1 - i2 == bsl::int32_t::min() + bsl::magic_42);
    };

    bsl::test_case("int32_t - int32_t rhs max lhs neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 - i2);
        });
    };

    bsl::test_case("int32_t - int32_t rhs max rhs neg") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 - i2);
        });
    };

    bsl::test_case("int32_t - int32_t rhs max both neg") = [] {
        bsl::int32_t i1{-bsl::magic_42};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check(i1 - i2 == -bsl::magic_42 - bsl::int32_t::min());
    };

    bsl::test_case("int32_t - int32_t both max lhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{bsl::int32_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 - i2);
        });
    };

    bsl::test_case("int32_t - int32_t both max rhs neg") = [] {
        bsl::int32_t i1{bsl::int32_t::max()};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 - i2);
        });
    };

    bsl::test_case("int32_t - int32_t both max both neg") = [] {
        bsl::int32_t i1{bsl::int32_t::min()};
        bsl::int32_t i2{bsl::int32_t::min()};
        bsl::check(i1 - i2 == 0);
    };

    return bsl::check_results();
}
