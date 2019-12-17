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
    bsl::test_case("require") = [] {
        bsl::check_nodeath([] {
            bsl::require(true);
        });
        bsl::check_death([] {
            bsl::require(false);
        });
    };

    bsl::test_case("require_false") = [] {
        bsl::check_death([] {
            bsl::require_false(true);
        });
        bsl::check_nodeath([] {
            bsl::require_false(false);
        });
    };

    bsl::test_case("require_nothrow") = [] {
        bsl::check_nodeath([] {
            bsl::require_nothrow([] {});
        });
        bsl::check_death([] {
            bsl::require_nothrow([] {
                throw bsl::checked_error{};
            });
        });
        bsl::check_death([] {
            bsl::require_nothrow([] {
                throw bsl::unchecked_error{};
            });
        });
    };

    bsl::test_case("require_throws") = [] {
        bsl::check_death([] {
            bsl::require_throws([] {});
        });
        bsl::check_nodeath([] {
            bsl::require_throws([] {
                throw bsl::checked_error{};
            });
        });
    };

    bsl::test_case("require_throws_as") = [] {
        bsl::check_nodeath([] {
            bsl::require_throws_as<bsl::unchecked_error>([] {
                throw bsl::unchecked_error{};
            });
        });
        bsl::check_death([] {
            bsl::require_throws_as<bsl::unchecked_error>([] {
                throw bsl::checked_error{};
            });
        });
    };

    bsl::test_case("require_nodeath") = [] {
        bsl::check_nodeath([] {
            bsl::require_nodeath([] {});
        });
        bsl::check_death([] {
            bsl::require_nodeath([] {
                std::exit(0);
            });
        });
    };

    bsl::test_case("require_death") = [] {
        bsl::check_death([] {
            bsl::require_death([] {});
        });
        bsl::check_nodeath([] {
            bsl::require_death([] {
                std::exit(0);
            });
        });
    };

    bsl::test_case("require nested level 1") = [] {
        bsl::test_case("require nested level 2") = [] {
            bsl::test_case("require nested level 3") = [] {
                bsl::check_nodeath([] {
                    bsl::require(true);
                });
            };
        };
    };

    bsl::test_case("throw from death test") = [] {
        bsl::check_nodeath([] {
            throw bsl::unchecked_error{};
        });
    };

    // Note
    //
    // - The magic here is that each death test is its own process, so
    //   even though an assertion is occuring inside the check, that
    //   assertion is changing the stats of a test in another process. The
    //   stats for this process (the one we care about), is only affected
    //   by the the top level checks. This allows us to test our own
    //   unit test library using our unit test library.
    //

    return bsl::check_results().get();
}
