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
///
/// @file foreach.hpp
///

#ifndef BSL_FOREACH_HPP
#define BSL_FOREACH_HPP

#include "cstdint.hpp"
#include "forward.hpp"

namespace bsl
{
    // A13-3-1 A8-4-9
    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void foreach (T (&array)[N], FUNC && func)    // PRQA S 2023, 4284  // NOLINT
        noexcept(false)
    {
        for (bsl::uintmax i{0U}; i < N; ++i) {
            bsl::forward<FUNC>(func)(array[i], i);
        }
    }

    template<typename T, bsl::uintmax N, typename FUNC>
    constexpr void foreach (T const (&array)[N], FUNC && func)    // PRQA S 2023 // NOLINT
        noexcept(false)
    {
        for (bsl::uintmax i{0U}; i < N; ++i) {
            bsl::forward<FUNC>(func)(array[i], i);
        }
    }
}

#endif
