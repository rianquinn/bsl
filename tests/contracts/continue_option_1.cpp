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

#define BSL_BUILD_LEVEL 2
#define BSL_CONTINUE_OPTION 1
#include "../../include/bsl/contracts.h"

#include "boost/ut.hpp"
using namespace boost::ut;

auto
main() -> int
{
    bsl::set_violation_handler([](auto info) {
        bsl::discard(info);
    });

    "expects"_test = [] {
        expect(nothrow([] {
            bsl::expects(true);
        }));
        expect(nothrow([] {
            bsl::expects(false);
        }));
    };

    "ensures"_test = [] {
        expect(nothrow([] {
            bsl::ensures(true);
        }));
        expect(nothrow([] {
            bsl::ensures(false);
        }));
    };

    "assert"_test = [] {
        expect(nothrow([] {
            bsl::assert(true);
        }));
        expect(nothrow([] {
            bsl::assert(false);
        }));
    };

    "expects_audit"_test = [] {
        expect(nothrow([] {
            bsl::expects_audit(true);
        }));
        expect(nothrow([] {
            bsl::expects_audit(false);
        }));
    };

    "ensures_audit"_test = [] {
        expect(nothrow([] {
            bsl::ensures_audit(true);
        }));
        expect(nothrow([] {
            bsl::ensures_audit(false);
        }));
    };

    "assert_audit"_test = [] {
        expect(nothrow([] {
            bsl::assert_audit(true);
        }));
        expect(nothrow([] {
            bsl::assert_audit(false);
        }));
    };

    "expects_axiom"_test = [] {
        expect(nothrow([] {
            bsl::expects_axiom(true);
        }));
        expect(nothrow([] {
            bsl::expects_axiom(false);
        }));
    };

    "ensures_axiom"_test = [] {
        expect(nothrow([] {
            bsl::ensures_axiom(true);
        }));
        expect(nothrow([] {
            bsl::ensures_axiom(false);
        }));
    };

    "assert_axiom"_test = [] {
        expect(nothrow([] {
            bsl::assert_axiom(true);
        }));
        expect(nothrow([] {
            bsl::assert_axiom(false);
        }));
    };
}