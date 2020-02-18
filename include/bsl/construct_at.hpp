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

#ifndef BSL_CONSTRUCT_AT_HPP
#define BSL_CONSTRUCT_AT_HPP

#include "new.hpp"
#include "forward.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to construct T at a specific location in memory using
    ///     a placement-new. The difference is, this function takes a void *
    ///     and returns a T *. This should be used instead of using the
    ///     placement new operator directly as it encapsulates issues with
    ///     PRQA.
    ///   @include example_construct_at__overview.hpp
    ///
    ///   SUPPRESSION: PRQA 5217 - false positive
    ///   - We suppress this because A18-5-2 states that non-placement
    ///     new and delete expressions are not allowed. This is a false
    ///     positive because this uses a placement new, which is allowed.
    ///
    ///   SUPPRESSION: PRQA 3058 - false positive
    ///   - We suppress this because M8-4-4 states that function pointers
    ///     should be preceeded by an &. In some cases, even if it is, this
    ///     rule still triggers (some sort of bug with PRQA)
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of object to initialize
    ///   @tparam ARGS the types of args to initialize T with
    ///   @param ptr a pointer to the object to initialize
    ///   @param args the args to initialize T with
    ///   @return returns ptr
    ///
    /// <!-- exceptions -->
    ///   @throw throws if T throws during construction
    ///
    template<typename T, typename... ARGS>
    [[maybe_unused]] constexpr T *
    construct_at(void *const ptr, ARGS &&... args)
    {
        return new (ptr) T{bsl::forward<ARGS>(args)...};    // PRQA S 5217, 3058
    }
}

#endif
