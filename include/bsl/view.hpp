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

#ifndef BSL_VIEW_HPP
#define BSL_VIEW_HPP

#include "cstdint.hpp"

namespace bsl
{
    template<typename T>
    class view final
    {
        T m_ptr[];
        bsl::uintmax m_size;

    public:
        constexpr view() noexcept = default;

        template<bsl::uintmax N>
        explicit constexpr view(T (&arr)[N]) noexcept    // --
            : m_ptr{arr}, m_size{N}
        {}

        explicit constexpr view(T *const ptr, bsl::uintmax count) noexcept    // --
            : m_ptr{ptr}, m_size{count}
        {}

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/overview.cpp
        ///
        ///   SUPPRESSION: PRQA 4211 - false positive
        ///   - We suppress this because M9-3-3 states that if a function
        ///     doesn't modify a class member, it should be marked as const.
        ///     This function, however, returns a non-const pointer to an
        ///     object stored internal to the class, meaning it cannot be
        ///     labeled const without breaking other AUTOSAR rules. This
        ///     is no different than returning a non-const refernce which
        ///     does not trip up PRQA so this must be a bug.
        ///
        ///   SUPPRESSION: PRQA 3706 - false positive
        ///   - We suppress this because M5-0-15 states that pointer arithmetic
        ///     is not allowed, and instead direct indexing or an array should
        ///     be used. This took a while to sort out. The short story is,
        ///     this is a false positive. M5-0-15 wants you to do ptr[X]
        ///     instead of *(ptr + X), which is what we are doing here. This
        ///     example is clearly shown in the second to last line in the
        ///     example that MISRA 2008 provides. The language for this was
        ///     cleaned up in MISRA 2012 as well. PRQA should be capable of
        ///     detecting this.
        ///
        ///   SUPPRESSION: PRQA 4024 - false positive
        ///   - We suppress this because A(-3-1) states that pointer we should
        ///     not provide a non-const reference or pointer to private
        ///     member function, unless the class mimics a smart pointer or
        ///     a containter. This class mimics a container.
        ///
        /// <!-- contracts -->
        ///   @pre the view must be valid and the index must be less than the
        ///     size of the array the view is pointer to
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        constexpr T *
        at(bsl::uintmax const index) noexcept // PRQA S 4211
        {
            if ((nullptr == m_ptr) || (index >= m_size)) {
                return nullptr;
            }

            return &m_ptr[index]; // PRQA S 3706, 4024
        }

        constexpr T const *
        at(bsl::uintmax const index) const noexcept
        {
            if ((nullptr == m_ptr) || (index >= m_size)) {
                return nullptr;
            }

            return &m_ptr[index]; // PRQA S 3706 // M5-0-15
        }
    };
}

#endif
