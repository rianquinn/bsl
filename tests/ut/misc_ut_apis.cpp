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
    if (bsl::check_results() != EXIT_FAILURE) {
        std::exit(1);
    }

    bsl::skip | bsl::test_case("skip") = [] {
        bsl::check(false);
    };

    bsl::test_case("verify skipped") = [&] {
        bsl::require(bsl::check_results() == EXIT_SUCCESS);
    };

    bsl::test_case("failed test") = [] {
        bsl::check(false);
    };

    bsl::skip | bsl::test_case("skip with failure") = [] {
        bsl::check(false);
    };

    bsl::test_case("verify skipped") = [&] {
        bsl::require(bsl::check_results() == EXIT_FAILURE);
    };

    bsl::test_case("uncaught exception") = [&] {
        throw std::runtime_error("error");
    };

    bsl::test_case("verify uncaught exception") = [&] {
        bsl::require(bsl::check_results() == EXIT_FAILURE);
    };

    bsl::test_case("uncaught exception") = [&] {
        throw 42;    // NOLINT
    };

    bsl::test_case("verify uncaught exception") = [&] {
        bsl::require(bsl::check_results() == EXIT_FAILURE);
    };

    bool caught = false;
    try {
        bsl::check(false);
    }
    catch (...) {
        caught = true;
    }

    bsl::test_case("verify assertion without test") = [&] {
        bsl::require(caught);
    };

    bsl::scenario("vectors can be sized and resized") = [] {
        bsl::given("A vector with some items") = [] {
            std::vector<int> v(5);

            bsl::require(v.size() == 5);
            bsl::require(v.capacity() >= 5);

            bsl::when("the size is increased") = [=]() mutable {
                v.resize(10);

                bsl::then("the size and capacity change") = [=] {
                    bsl::require(v.size() == 10);
                    bsl::require(v.capacity() >= 10);
                };
            };

            bsl::when("the size is reduced") = [=]() mutable {
                v.resize(0);

                bsl::then("the size changes but not capacity") = [=] {
                    bsl::require(v.empty());
                    bsl::require(v.capacity() == 0);
                };
            };

            bsl::when("more capacity is reserved") = [=]() mutable {
                v.reserve(10);

                bsl::then("the capacity changes but not the size") = [=] {
                    bsl::require(v.size() == 5);
                    bsl::require(v.capacity() >= 5);
                };
            };

            bsl::when("less capacity is reserved") = [=]() mutable {
                v.reserve(0);

                bsl::then("neither size nor capacity are changed") = [=] {
                    bsl::require(v.size() == 5);
                    bsl::require(v.capacity() >= 5);
                };
            };
        };
    };

    bsl::test_case("vectors can be sized and resized") = [] {
        std::vector<int> v(5);

        bsl::require(v.size() == 5);
        bsl::require(v.capacity() >= 5);

        bsl::section("the size is increased") = [=]() mutable {
            v.resize(10);

            bsl::require(v.size() == 10);
            bsl::require(v.capacity() >= 10);
        };

        bsl::section("the size is reduced") = [=]() mutable {
            v.resize(0);

            bsl::require(v.empty());
            bsl::require(v.capacity() == 5);
        };

        bsl::section("more capacity is reserved") = [=]() mutable {
            v.reserve(10);

            bsl::require(v.size() == 5);
            bsl::require(v.capacity() >= 10);
        };

        bsl::section("less capacity is reserved") = [=]() mutable {
            v.reserve(0);

            bsl::require(v.size() == 5);
            bsl::require(v.capacity() >= 5);
        };
    };

    return bsl::check_results();
}
