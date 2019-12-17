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

/// NOSONAR: NOLINT:
/// - We must test to make sure we can catch any type of exception, so we turn
///   of this check.

auto
main() -> int
{
    bsl::check(bsl::check_results() != EXIT_FAILURE);

    bsl::skip | bsl::test_case("skip") = [] {
        bsl::check(false);
    };

    bsl::test_case("verify skipped") = [] {
        bsl::require(bsl::check_results() == EXIT_SUCCESS);
    };

    bsl::test_case("failed test") = [] {
        bsl::check(false);
    };

    bsl::skip | bsl::test_case("skip with failure") = [] {
        bsl::check(false);
    };

    bsl::test_case("verify skipped") = [] {
        bsl::require(bsl::check_results() == EXIT_FAILURE);
    };

    bsl::test_case("uncaught exception") = [] {
        throw bsl::checked_error{};
    };

    bsl::test_case("verify uncaught exception") = [] {
        bsl::require(bsl::check_results() == EXIT_FAILURE);
    };

    bsl::test_case("uncaught exception") = [] {
        throw 0;    // NOLINT //NOSONAR
    };

    bsl::test_case("verify uncaught exception") = [] {
        bsl::require(bsl::check_results() == EXIT_FAILURE);
    };

    bsl::scenario("1") = [] {
        bsl::given("2") = [] {
            bsl::when("3") = [] {
                bsl::then("4") = [] {
                    bsl::check(true);
                };
            };
        };
    };

    bsl::test_case("1") = [] {
        bsl::section("2") = [] {
            bsl::check(true);
        };
    };

    return bsl::check_results().get();
}
