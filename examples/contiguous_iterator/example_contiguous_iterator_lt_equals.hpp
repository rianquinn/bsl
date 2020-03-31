/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef EXAMPLE_CONTIGUOUS_ITERATOR_LT_EQUALS_HPP
#define EXAMPLE_CONTIGUOUS_ITERATOR_LT_EQUALS_HPP

#include <bsl/string_view.hpp>
#include <bsl/print.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    inline void
    example_contiguous_iterator_lt_equals() noexcept
    {
        constexpr bsl::string_view str{"Hello"};
        constexpr bsl::string_view::iterator_type iter1{str.begin()};
        constexpr bsl::string_view::iterator_type iter2{str.begin()};
        constexpr bsl::string_view::iterator_type iter3{str.end()};

        if (iter1 == iter2) {
            bsl::print("success\n");
        }

        if (iter1 != iter3) {
            bsl::print("success\n");
        }

        if (iter1 < iter3) {
            bsl::print("success\n");
        }

        if (iter1 <= iter2) {
            bsl::print("success\n");
        }

        if (iter3 > iter1) {
            bsl::print("success\n");
        }

        if (iter3 >= iter1) {
            bsl::print("success\n");
        }
    }
}

#endif
