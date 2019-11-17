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

#include "../../include/bsl/source_location.h"
#include "../../include/bsl/ut.h"

auto
main() -> int
{
    bsl::test_case("default constructor") = [] {
        auto loc = bsl::source_location{};
        bsl::check(loc.file_name() == nullptr);
        bsl::check(loc.function_name() == nullptr);
        bsl::check(loc.line() == 0);
    };

    bsl::test_case("current") = [] {
        auto loc = bsl::source_location::current();
        bsl::check(loc.file_name() != nullptr);
        bsl::check(loc.function_name() != nullptr);
        bsl::check(loc.line() == 36);    // NOLINT
    };

    bsl::test_case("column") = [] {
        bsl::check(bsl::source_location::column() == 0);
    };

    return bsl::check_results();
}