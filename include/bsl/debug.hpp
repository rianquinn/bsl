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

#ifndef BSL_DEBUG_H
#define BSL_DEBUG_H

#include "source_location.hpp"

#include <fmt/core.h>
#include <fmt/color.h>

namespace bsl::details
{
    constexpr auto black = fmt::fg(fmt::terminal_color::bright_black);
    constexpr auto blue = fmt::fg(fmt::terminal_color::bright_blue);
    constexpr auto cyan = fmt::fg(fmt::terminal_color::bright_cyan);
    constexpr auto green = fmt::fg(fmt::terminal_color::bright_green);
    constexpr auto magenta = fmt::fg(fmt::terminal_color::bright_magenta);
    constexpr auto red = fmt::fg(fmt::terminal_color::bright_red);
    constexpr auto white = fmt::fg(fmt::terminal_color::bright_white);
    constexpr auto yellow = fmt::fg(fmt::terminal_color::bright_yellow);
}    // namespace bsl::details

#endif
