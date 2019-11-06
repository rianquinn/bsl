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

#ifndef BSL_CONSOLE_COLORS_H
#define BSL_CONSOLE_COLORS_H

namespace bsl::console_color
{
#ifdef _MSC_VER
    constexpr const char *red = "";
    constexpr const char *green = "";
    constexpr const char *yellow = "";
    constexpr const char *blue = "";
    constexpr const char *magenta = "";
    constexpr const char *cyan = "";
    constexpr const char *light_red = "";
    constexpr const char *light_green = "";
    constexpr const char *light_yellow = "";
    constexpr const char *light_blue = "";
    constexpr const char *light_magenta = "";
    constexpr const char *light_cyan = "";
    constexpr const char *end = "";
#else
    constexpr const char *red = "\033[1;31m";
    constexpr const char *green = "\033[1;32m";
    constexpr const char *yellow = "\033[1;33m";
    constexpr const char *blue = "\033[1;34m";
    constexpr const char *magenta = "\033[1;35m";
    constexpr const char *cyan = "\033[1;36m";
    constexpr const char *light_red = "\033[1;91m";
    constexpr const char *light_green = "\033[1;92m";
    constexpr const char *light_yellow = "\033[1;93m";
    constexpr const char *light_blue = "\033[1;94m";
    constexpr const char *light_magenta = "\033[1;95m";
    constexpr const char *light_cyan = "\033[1;96m";
    constexpr const char *end = "\033[0m";
#endif
}    // namespace bsl::console_color

#endif
