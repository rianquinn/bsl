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
try {
    // enum color_t {RED, GREEN};
    // color_t color{RED};

    // if (color <= GREEN) {
    //     fmt::print("");  // knownConditionTrueFalse (cppcheck)
    // }

    // uint8_t u8{0};

    // if (u8 >= 0U) {
    //     fmt::print("");  // knownConditionTrueFalse (cppcheck)
    // }

    // if (u8 < 0) {
    //     fmt::print("");  // knownConditionTrueFalse (cppcheck)
    // }

    // if (u8 < 0xFF) {
    //     fmt::print("");  // knownConditionTrueFalse (cppcheck)
    // }

    // int8_t s8{0};

    // if (s8 < 130) {
    //     fmt::print("");  // knownConditionTrueFalse (cppcheck)
    // }

    // if (s8 < 10 && s8 > 20) {
    //     fmt::print("");  // misc-redundant-expression (tidy)
    // }

    // if (s8 < 10 || s8 > 5) {
    //     fmt::print("");  // misc-redundant-expression (tidy)
    // }

    // if (s8 < 10) {
    //     if (s8 > 5) {
    //         fmt::print("");  // knownConditionTrueFalse (cppcheck)
    //     }
    // }
}
catch (...) {
}
