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
    bsl::test_case("int64_t max to int32_t") = [] {
        bsl::int64_t i{bsl::int64_t::max()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::int32_t>());
        });
    };

    bsl::test_case("uint64_t max to uint32_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::max()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::uint32_t>());
        });
    };

    bsl::test_case("int64_t min to int32_t") = [] {
        bsl::int64_t i{bsl::int64_t::min()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::int32_t>());
        });
    };

    bsl::test_case("uint64_t min to uint32_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint32_t>());
        });
    };

    bsl::test_case("int32_t max to int64_t") = [] {
        bsl::int32_t i{bsl::int32_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("uint32_t max to uint64_t") = [] {
        bsl::uint32_t i{bsl::uint32_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("int32_t min to int64_t") = [] {
        bsl::int32_t i{bsl::int32_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("uint32_t min to uint64_t") = [] {
        bsl::uint32_t i{bsl::uint32_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("int64_t max to uint64_t") = [] {
        bsl::int64_t i{bsl::int64_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("int64_t min to uint64_t") = [] {
        bsl::int64_t i{bsl::int64_t::min()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("uint64_t max to int64_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::max()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("uint64_t min to int64_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("int32_t max to uint64_t") = [] {
        bsl::int32_t i{bsl::int32_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("int32_t min to uint64_t") = [] {
        bsl::int32_t i{bsl::int32_t::min()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("uint32_t max to int64_t") = [] {
        bsl::uint32_t i{bsl::uint32_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("uint32_t min to int64_t") = [] {
        bsl::uint32_t i{bsl::uint32_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("int64_t max to uint32_t") = [] {
        bsl::int64_t i{bsl::int64_t::max()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::uint32_t>());
        });
    };

    bsl::test_case("int64_t min to uint32_t") = [] {
        bsl::int64_t i{bsl::int64_t::min()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::uint32_t>());
        });
    };

    bsl::test_case("uint64_t max to int32_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::max()};
        bsl::check_throws([&i] {
            bsl::discard(i.narrow<bsl::int32_t>());
        });
    };

    bsl::test_case("uint64_t min to int32_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int32_t>());
        });
    };

    bsl::test_case("int64_t max to int64_t") = [] {
        bsl::int64_t i{bsl::int64_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("int64_t min to int64_t") = [] {
        bsl::int64_t i{bsl::int64_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::int64_t>());
        });
    };

    bsl::test_case("uint64_t max to uint64_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::max()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    bsl::test_case("uint64_t min to uint64_t") = [] {
        bsl::uint64_t i{bsl::uint64_t::min()};
        bsl::check_nothrow([&i] {
            bsl::discard(i.narrow<bsl::uint64_t>());
        });
    };

    return bsl::check_results();
}
