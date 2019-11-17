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

// static auto
// fn1(std::uint8_t param) noexcept -> std::uint8_t
// {
//     std::int32_t x{0}; // -Wunused-variable (clang)

//     if (param > 0) {
//         return 1;
//     }

//     return 0;
// }

// static auto
// fn2() noexcept -> std::int32_t
// {
//     std::int8_t x{10};
//     std::int8_t y{20};
//     std::int16_t result = x + y;

//     x = 0; // clang-analyzer-deadcode.DeadStores (tidy)
//     y = 0; // clang-analyzer-deadcode.DeadStores (tidy)

//     return result;
// }

// #include <array>
constexpr std::int32_t size = 5;

static auto
fn5(std::array<std::int32_t, size> &a) noexcept
{
    std::uint8_t y{0};

    for (std::int32_t i = 0; i < size; i++) {
        a.at(y) = i;
        ++y;    // FAILED - unused on final not detected
    }
}

auto
main() -> int
try {
    std::array<std::int32_t, size> a{};
    fn5(a);

    // fmt::print("{}\n", fn1(42));
    // fmt::print("{}\n", fn2());
    fmt::print("{}\n", a.at(2));
}
catch (...) {
}
