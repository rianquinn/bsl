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

#include "../../include/bsl/ut.h"

auto
main() -> int
{
    bsl::test_case("checks") = [] {
        bsl::check(true);
        bsl::check(false);

        bsl::check_false(true);
        bsl::check_false(false);

        bsl::check_nothrow([] {});
        bsl::check_nothrow([] {
            throw std::runtime_error("error");
        });
        bsl::check_nothrow([] {
            throw 42;    // NOLINT
        });

        bsl::check_throws([] {});
        bsl::check_throws([] {
            throw std::runtime_error("error");
        });

        bsl::check_throws_checked([] {
            throw std::logic_error("error");
        });
        bsl::check_throws_checked([] {
            throw std::logic_error("error");
        });
        bsl::check_throws_checked([] {
            throw std::runtime_error("error");
        });

        bsl::check_throws_unchecked([] {
            throw std::logic_error("error");
        });
        bsl::check_throws_unchecked([] {
            throw std::logic_error("error");
        });
        bsl::check_throws_unchecked([] {
            throw std::runtime_error("error");
        });

        bsl::check_nodeath([] {});
        bsl::check_nodeath([] {
            std::exit(0);
        });

        bsl::check_death([] {});
        bsl::check_death([] {
            std::exit(0);
        });
    };

    bsl::test_case("verify_checks") = [] {
        bsl::require(bsl::details::ut::total_assertions == 19);
        bsl::require(bsl::details::ut::failed_assertions == 10);
    };

    return 0;
}
