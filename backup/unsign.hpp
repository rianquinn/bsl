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
/// @file unsign.hpp
///

#ifndef BSL_UNSIGN_HPP
#define BSL_UNSIGN_HPP

#include "contracts.hpp"

namespace bsl
{
    /// @brief unsign
    ///
    /// Converts an unsigned value, stored in a signed type as an unsigned
    /// type. The resulting value is returned as a std::uintmax_t.
    ///
    /// expects: val is unsigned and positive
    /// ensures: none
    ///
    /// @param val the value to unsign
    /// @return val as a std::uintmax_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[nodiscard]] constexpr std::uintmax_t
    unsign(std::intmax_t const &val)
    {
        bsl::expects_audit(val >= 0);
        return static_cast<std::uintmax_t>(val);
    }
}    // namespace bsl

#endif
