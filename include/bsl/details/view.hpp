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
    class view
    {
        /// @brief stores a pointer to the data being viewed
        T *m_data;
        /// @brief stores the number of elements being viewed
        bsl::uintmax m_size;

    public:
        constexpr view() noexcept = default;

        template<bsl::uintmax N>
        constexpr view(T (&arr)[N]) noexcept    // --
            : m_data{arr}, m_size{N}
        {}

        constexpr view(T *const data, bsl::uintmax size) noexcept    // --
            : m_data{data}, m_size{size}
        {
            if ((nullptr == m_data) || (0 == m_size)) {
                *this = view{};
            }
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/at.cpp
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
        ///   - We suppress this because A9-3-1 states that pointer we should
        ///     not provide a non-const reference or pointer to private
        ///     member function, unless the class mimics a smart pointer or
        ///     a containter. This class mimics a container.
        ///
        /// <!-- contracts -->
        ///   @pre the view must be valid and the index must be less than the
        ///     size of the array the view is pointer to. If not, a nullptr
        ///     is returned.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr T *
        at(bsl::uintmax const index) noexcept    // PRQA S 4211
        {
            if ((nullptr == m_data) || (index >= m_size)) {
                return nullptr;
            }

            return &m_data[index];    // PRQA S 3706, 4024
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/at.cpp
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
        /// <!-- contracts -->
        ///   @pre the view must be valid and the index must be less than the
        ///     size of the array the view is pointer to. If not, a nullptr
        ///     is returned.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr T const *
        at(bsl::uintmax const index) const noexcept
        {
            if ((nullptr == m_data) || (index >= m_size)) {
                return nullptr;
            }

            return &m_data[index];    // PRQA S 3706
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/front.cpp
        ///
        /// <!-- contracts -->
        ///   @pre the view must be valid and contain data. If not, a nullptr
        ///     is returned.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr T *
        front() noexcept
        {
            return this->at(0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/front.cpp
        ///
        /// <!-- contracts -->
        ///   @pre the view must be valid and contain data. If not, a nullptr
        ///     is returned.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr T const *
        front() const noexcept
        {
            return this->at(0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include view/back.cpp
        ///
        /// <!-- contracts -->
        ///   @pre the view must be valid and contain data. If not, a nullptr
        ///     is returned.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr T *
        back() noexcept
        {
            return this->at(m_size > 0 ? m_size - 1 : 0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include view/back.cpp
        ///
        /// <!-- contracts -->
        ///   @pre the view must be valid and contain data. If not, a nullptr
        ///     is returned.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr T const *
        back() const noexcept
        {
            return this->at(m_size > 0 ? m_size - 1 : 0);
        }

        [[nodiscard]] constexpr void *
        data() noexcept
        {
            return m_data;
        }

        [[nodiscard]] constexpr void const *
        data() const noexcept
        {
            return m_data;
        }

        [[nodiscard]] constexpr bsl::uintmax
        size() const noexcept
        {
            return m_size;
        }

        [[nodiscard]] constexpr bsl::uintmax
        size_bytes() const noexcept
        {
            return m_size * sizeof(T);
        }

        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return nullptr == m_data;
        }

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::view
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~view() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr view(view const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr view(view &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr view &operator=(view const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr view &    // --
        operator=(view &&o) &noexcept = default;
    };
}

#endif
