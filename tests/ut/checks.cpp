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

#include "../../include/bsl/ut.hpp"

auto
main() -> int
{
    bsl::test_case("check") = [] {
        bsl::check(true);
        bsl::check(false);
    };

    bsl::test_case("check_false") = [] {
        bsl::check_false(true);
        bsl::check_false(false);
    };

    bsl::test_case("check_nothrow") = [] {
        bsl::check_nothrow([] {});
        bsl::check_nothrow([] {
            throw bsl::checked_error{};
        });
    };

    bsl::test_case("check_throws") = [] {
        bsl::check_throws([] {});
        bsl::check_throws([] {
            throw bsl::checked_error{};
        });
    };

    bsl::test_case("check_throws_checked") = [] {
        bsl::check_throws_checked([] {
            throw bsl::unchecked_error{};
        });
        bsl::check_throws_checked([] {
            throw bsl::checked_error{};
        });
    };

    bsl::test_case("check_throws_unchecked") = [] {
        bsl::check_throws_unchecked([] {
            throw bsl::unchecked_error{};
        });
        bsl::check_throws_unchecked([] {
            throw bsl::checked_error{};
        });
    };

    bsl::test_case("check_nodeath") = [] {
        bsl::check_nodeath([] {});
        bsl::check_nodeath([] {
            std::exit(0);
        });
    };

    bsl::test_case("check_death") = [] {
        bsl::check_death([] {});
        bsl::check_death([] {
            std::exit(0);
        });
    };

    constexpr const std::int32_t total_assertions = 16;
    constexpr const std::int32_t failed_assertions = 8;

    bsl::test_case("verify_checks") = [] {
        bsl::require(bsl::details::ut::total_assertions == total_assertions);
        bsl::require(bsl::details::ut::failed_assertions == failed_assertions);
    };

    return 0;
}
