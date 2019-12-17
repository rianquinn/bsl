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

/// NOLINT:
/// - We want to be able to use "magic numbers" in the construction of a BSL
///   integer type. The comparison should generate an error though as that is
///   a legit magic number. We silence this error so that we can test that the
///   construction does not generate an error, but the comparison does.

constexpr const bsl::uint64_t g_i1{};
constexpr const bsl::uint64_t g_i2{0xFFFFFFFFFFFFFFE0};
constexpr const bsl::uint64_t g_i3{g_i2};

static_assert(g_i1 == 0);
static_assert(g_i2 == 0xFFFFFFFFFFFFFFE0);    // NOLINT
static_assert(g_i3 == g_i2);

auto
main() -> int
{
    bsl::test_case("default constructor") = [] {
        bsl::int64_t i;
        bsl::check(i == 0);
    };

    bsl::test_case("value_type constructor") = [] {
        bsl::int32_t i{bsl::magic_42};
        bsl::check(i == bsl::magic_42);
    };

    // The following should not compile. This is because, the types must
    // be the same.
    //
    // bsl::test_case("value_type constructor") = [] {
    //     bsl::int64_t i{bsl::magic_42};
    //     bsl::check(i == bsl::magic_42);
    // };

    bsl::test_case("ptr constructor") = [] {
        void *ptr{};
        bsl::uintptr_t i{ptr};
        bsl::check(i == 0);
    };

    bsl::test_case("copy constructor") = [] {
        bsl::int32_t i1{bsl::magic_42};
        bsl::int32_t i2{i1};
        bsl::check(i1 == bsl::magic_42);
        bsl::check(i2 == bsl::magic_42);
    };

    return bsl::check_results().get();
}
