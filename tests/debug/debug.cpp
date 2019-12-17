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

#include "../../include/bsl/debug.hpp"
#include "../../include/bsl/ut.hpp"

auto
thread_id() noexcept -> std::uint64_t
{
    return 1;
}

auto
main() -> int
{
    bsl::test_case("format error") = [] {
        bsl::check_nothrow([] {
            bsl::debug("Hello {f}", "World");
        });
    };

    bsl::test_case("print") = [] {
        bsl::print("Hello {}", "World");
        bsl::print<V>("Hello {}", "World");
        bsl::print<VV>("Hello {}", "World");
        bsl::print<VVV>("Hello {}", "World");
    };

    bsl::test_case("debug") = [] {
        bsl::debug("Hello {}", "World");
        bsl::debug<V>("Hello {}", "World");
        bsl::debug<VV>("Hello {}", "World");
        bsl::debug<VVV>("Hello {}", "World");
    };

    bsl::test_case("alert") = [] {
        bsl::alert("Hello {}", "World");
        bsl::alert<V>("Hello {}", "World");
        bsl::alert<VV>("Hello {}", "World");
        bsl::alert<VVV>("Hello {}", "World");
    };

    bsl::test_case("error") = [] {
        bsl::error("Hello {}", "World");
        bsl::error<V>("Hello {}", "World");
        bsl::error<VV>("Hello {}", "World");
        bsl::error<VVV>("Hello {}", "World");
    };

    struct my_error : bsl::unchecked_error
    {};

    bsl::test_case("fatal") = [] {
        bsl::check_death([] {
            bsl::fatal("Hello {}", "World");
        });
        bsl::check_death([] {
            bsl::fatal<my_error>("Hello {}", "World");
        });
    };

    bsl::test_case("print here") = [] {
        bsl::debug("{}", bsl::here());
    };

    return bsl::check_results().get();
}
