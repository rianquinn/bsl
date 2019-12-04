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

auto
main() -> int
{
    // -------------------------------------------------------------------------
    // - signed addition
    // -------------------------------------------------------------------------

    bsl::test_case("int64_t + magic success") = [] {
        bsl::int64_t i{bsl::magic_42};
        bsl::check(i + bsl::magic_42 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("magic success + int64_t") = [] {
        bsl::int64_t i{bsl::magic_42};
        bsl::check(bsl::magic_42 + i == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int64_t + int64_t success") = [] {
        bsl::int64_t i1{bsl::magic_42};
        bsl::int64_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int8_t + int64_t success") = [] {
        bsl::int8_t i1{bsl::magic_42};
        bsl::int64_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int64_t + int8_t success") = [] {
        bsl::int64_t i1{bsl::magic_42};
        bsl::int8_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int64_t + int64_t lhs max") = [] {
        bsl::int64_t i1{bsl::int64_t::max()};
        bsl::int64_t i2{bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int64_t + int64_t rhs max") = [] {
        bsl::int64_t i1{bsl::magic_42};
        bsl::int64_t i2{bsl::int64_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int64_t + int64_t both max") = [] {
        bsl::int64_t i1{bsl::int64_t::max()};
        bsl::int64_t i2{bsl::int64_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int64_t - int64_t success lhs neg") = [] {
        bsl::int64_t i1{-bsl::magic_42};
        bsl::int64_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == -bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("int64_t - int64_t success rhs neg") = [] {
        bsl::int64_t i1{bsl::magic_42};
        bsl::int64_t i2{-bsl::magic_42};
        bsl::check(i1 + i2 == 0);
    };

    bsl::test_case("int64_t - int64_t success both neg") = [] {
        bsl::int64_t i1{-bsl::magic_42};
        bsl::int64_t i2{-bsl::magic_42};
        bsl::check(i1 + i2 == -bsl::magic_42 - bsl::magic_42);
    };

    bsl::test_case("int64_t - int64_t lhs max lhs neg") = [] {
        bsl::int64_t i1{-bsl::int64_t::max()};
        bsl::int64_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == -bsl::int64_t::max() + bsl::magic_42);
    };

    bsl::test_case("int64_t - int64_t lhs max rhs neg") = [] {
        bsl::int64_t i1{bsl::int64_t::max()};
        bsl::int64_t i2{-bsl::magic_42};
        bsl::check(i1 + i2 == bsl::int64_t::max() - bsl::magic_42);
    };

    bsl::test_case("int64_t - int64_t lhs max both neg") = [] {
        bsl::int64_t i1{-bsl::int64_t::max()};
        bsl::int64_t i2{-bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int64_t - int64_t rhs max lhs neg") = [] {
        bsl::int64_t i1{-bsl::magic_42};
        bsl::int64_t i2{bsl::int64_t::max()};
        bsl::check(i1 + i2 == bsl::int64_t::max() - bsl::magic_42);
    };

    bsl::test_case("int64_t - int64_t rhs max rhs neg") = [] {
        bsl::int64_t i1{bsl::magic_42};
        bsl::int64_t i2{-bsl::int64_t::max()};
        bsl::check(i1 + i2 == -bsl::int64_t::max() + bsl::magic_42);
    };

    bsl::test_case("int64_t - int64_t rhs max both neg") = [] {
        bsl::int64_t i1{-bsl::magic_42};
        bsl::int64_t i2{-bsl::int64_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("int64_t - int64_t both max lhs neg") = [] {
        bsl::int64_t i1{-bsl::int64_t::max()};
        bsl::int64_t i2{bsl::int64_t::max()};
        bsl::check(i1 + i2 == 0);
    };

    bsl::test_case("int64_t - int64_t both max rhs neg") = [] {
        bsl::int64_t i1{bsl::int64_t::max()};
        bsl::int64_t i2{-bsl::int64_t::max()};
        bsl::check(i1 + i2 == 0);
    };

    bsl::test_case("int64_t - int64_t both max both neg") = [] {
        bsl::int64_t i1{-bsl::int64_t::max()};
        bsl::int64_t i2{-bsl::int64_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    // -------------------------------------------------------------------------
    // - unsigned addition
    // -------------------------------------------------------------------------

    bsl::test_case("uint64_t + magic success") = [] {
        bsl::uint64_t i{bsl::magic_42};
        bsl::check(i + bsl::magic_42u == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("magic success + uint64_t") = [] {
        bsl::uint64_t i{bsl::magic_42};
        bsl::check(bsl::magic_42u + i == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("uint64_t + uint64_t success") = [] {
        bsl::uint64_t i1{bsl::magic_42};
        bsl::uint64_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("uint8_t + uint64_t success") = [] {
        bsl::uint8_t i1{bsl::magic_42};
        bsl::uint64_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("uint64_t + uint8_t success") = [] {
        bsl::uint64_t i1{bsl::magic_42};
        bsl::uint8_t i2{bsl::magic_42};
        bsl::check(i1 + i2 == bsl::magic_42 + bsl::magic_42);
    };

    bsl::test_case("uint64_t + uint64_t lhs max") = [] {
        bsl::uint64_t i1{bsl::uint64_t::max()};
        bsl::uint64_t i2{bsl::magic_42};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("uint64_t + uint64_t rhs max") = [] {
        bsl::uint64_t i1{bsl::magic_42};
        bsl::uint64_t i2{bsl::uint64_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    bsl::test_case("uint64_t + uint64_t both max") = [] {
        bsl::uint64_t i1{bsl::uint64_t::max()};
        bsl::uint64_t i2{bsl::uint64_t::max()};
        bsl::check_throws([&i1, &i2] {
            bsl::discard(i1 + i2);
        });
    };

    return bsl::check_results();
}
