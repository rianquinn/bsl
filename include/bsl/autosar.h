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

#ifndef BSL_AUTOSAR_H
#define BSL_AUTOSAR_H

#ifndef BSL_AUTOSAR_COMPLIANT
#define BSL_AUTOSAR_COMPLIANT 0
#endif

static_assert(BSL_AUTOSAR_COMPLIANT >= 0 and BSL_AUTOSAR_COMPLIANT <= 1);

namespace bsl
{
    /// AUTOSAR C++14 Compliant (Read-Only)
    ///
    /// Set to true if AUTOSAR C++14 compliance is enabled, false
    /// (the default) otherwise.
    ///
    constexpr bool autosar_compliant = (BSL_AUTOSAR_COMPLIANT == 1);
}    // namespace bsl

#endif
