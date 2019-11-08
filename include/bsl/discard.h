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

#ifndef BSL_DISCARD_H
#define BSL_DISCARD_H

namespace bsl
{
    /// Discard
    ///
    /// The following will silence the compiler as well as static analysis
    /// checks complaining about unused parameters. AUTOSAR requires that such
    /// parameters do not exist, and therefore, the use of this function must
    /// be documented to explain why it is needed. Use with caution.
    ///
    /// expects:
    /// ensures:
    ///
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename... ARGS>
    constexpr auto
    discard(ARGS &&...) noexcept -> void    // NOLINT
    {}
}    // namespace bsl

#endif
