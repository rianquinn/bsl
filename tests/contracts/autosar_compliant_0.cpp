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

#define BSL_AUTOSAR_COMPLIANT 0
#define BSL_BUILD_LEVEL 2
#define BSL_CONTRACTS_ABORT std::exit(0)

#include "../../include/bsl/contracts.hpp"
#include "../../include/bsl/ut.hpp"

auto
main() -> int
{
    bsl::test_case("expects") = [] {
        bsl::check_nodeath([] {
            bsl::expects(true);
        });
        bsl::check_death([] {
            bsl::expects(false);
        });
    };

    bsl::test_case("ensures") = [] {
        bsl::check_nodeath([] {
            bsl::ensures(true);
        });
        bsl::check_death([] {
            bsl::ensures(false);
        });
    };

    bsl::test_case("assert") = [] {
        bsl::check_nodeath([] {
            bsl::assert(true);
        });
        bsl::check_death([] {
            bsl::assert(false);
        });
    };

    bsl::test_case("expects_audit") = [] {
        bsl::check_nodeath([] {
            bsl::expects_audit(true);
        });
        bsl::check_death([] {
            bsl::expects_audit(false);
        });
    };

    bsl::test_case("ensures_audit") = [] {
        bsl::check_nodeath([] {
            bsl::ensures_audit(true);
        });
        bsl::check_death([] {
            bsl::ensures_audit(false);
        });
    };

    bsl::test_case("assert_audit") = [] {
        bsl::check_nodeath([] {
            bsl::assert_audit(true);
        });
        bsl::check_death([] {
            bsl::assert_audit(false);
        });
    };

    bsl::test_case("expects_axiom") = [] {
        bsl::check_nodeath([] {
            bsl::expects_axiom(true);
        });
        bsl::check_nodeath([] {
            bsl::expects_axiom(false);
        });
    };

    bsl::test_case("ensures_axiom") = [] {
        bsl::check_nodeath([] {
            bsl::ensures_axiom(true);
        });
        bsl::check_nodeath([] {
            bsl::ensures_axiom(false);
        });
    };

    bsl::test_case("assert_axiom") = [] {
        bsl::check_nodeath([] {
            bsl::assert_axiom(true);
        });
        bsl::check_nodeath([] {
            bsl::assert_axiom(false);
        });
    };

    return bsl::check_results();
}
