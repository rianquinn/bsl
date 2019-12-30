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

#ifndef BSL_FMT_HPP
#define BSL_FMT_HPP

#include "types.hpp"

#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace bsl
{
    /// reset color
    constexpr cstr_type reset_color{"\033[0m"};

    /// normal foreground colors
    constexpr cstr_type black{"\033[0;90m"};
    constexpr cstr_type red{"\033[0;91m"};
    constexpr cstr_type green{"\033[0;92m"};
    constexpr cstr_type yellow{"\033[0;93m"};
    constexpr cstr_type blue{"\033[0;94m"};
    constexpr cstr_type magenta{"\033[0;95m"};
    constexpr cstr_type cyan{"\033[0;96m"};
    constexpr cstr_type white{"\033[0;97m"};

    /// bold foreground colors
    constexpr cstr_type bold_black{"\033[1;90m"};
    constexpr cstr_type bold_red{"\033[1;91m"};
    constexpr cstr_type bold_green{"\033[1;92m"};
    constexpr cstr_type bold_yellow{"\033[1;93m"};
    constexpr cstr_type bold_blue{"\033[1;94m"};
    constexpr cstr_type bold_magenta{"\033[1;95m"};
    constexpr cstr_type bold_cyan{"\033[1;96m"};
    constexpr cstr_type bold_white{"\033[1;97m"};
}    // namespace bsl

#endif
