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
/// @file view.hpp
///

#ifndef BSL_VIEW_HPP
#define BSL_VIEW_HPP

#include "contiguous_iterator.hpp"
#include "cstdint.hpp"
#include "numeric_limits.hpp"
#include "reverse_iterator.hpp"

namespace bsl
{
    /// @class bsl::view
    ///
    /// <!-- description -->
    ///   @brief Provides the base class for all view types. This class is
    ///     only used as a base class for creating view type containers.
    ///     If you need a view, either use an existing view type like a
    ///     bsl::span or bsl::string_view, or create your own.
    ///     Note that the only difference between a bsl::span and a bsl::view
    ///     is the name. The other view types add additional functionality
    ///     on top of a bsl::span. Note that there are a couple of differences
    ///     between a bsl::view (i.e., bsl::span) and a std::span:
    ///     - We do not provide the conversion constructors for array types as
    ///       they are not compliant with AUTOSAR. If you need an array, use
    ///       a bsl::array.
    ///     - We do not provide any of the accessor functions as defined by
    ///       the standard library. Instead we provide _if() versions which
    ///       return a pointer to the element being requested. If the element
    ///       does not exist, a nullptr is returned, providing a means to
    ///       check for logic errors without the need for exceptions or
    ///       failing fast which is not compliant with AUTOSAR.
    ///     - We provide the iter() function which is similar to begin() and
    ///       end(), but allowing you to get an iterator from any position in
    ///       the view.
    ///     - As noted in the documentation for the contiguous_iterator,
    ///       iterators are not allowed to go beyond their bounds which the
    ///       Standard Library does not ensure. It is still possible for an
    ///       iterator to be invalid as you cannot dereference end() (fixing
    ///       this would break compatiblity with existing APIs when AUTOSAR
    ///       compliance is disabled), but you can be rest assured that an
    ///       iterator's index is always within bounds or == end(). Note
    ///       that for invalid views, begin() and friends always return an
    ///       interator to end().
    ///     It should also be noted that like a std::span, a bsl::view is
    ///     non-owning. Other view types like a bsl::array own the array
    ///     being viewed while types like bsl::string_view and bsl::span do
    ///     not, and must not outlive the array they are viewing.
    ///   @include example_view_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being viewed.
    ///
    template<typename T>
    class view    // NOLINT
    {
    public:
        /// @brief alias for: T
        using value_type = T;
        /// @brief alias for: bsl::uintmax
        using size_type = bsl::uintmax;
        /// @brief alias for: bsl::uintmax
        using difference_type = bsl::uintmax;
        /// @brief alias for: T &
        using reference = T &;
        /// @brief alias for: T const &
        using const_reference = T const &;
        /// @brief alias for: T *
        using pointer = T *;
        /// @brief alias for: T const *
        using const_pointer = T const *;
        /// @brief alias for: contiguous_iterator<T>
        using iterator = contiguous_iterator<T>;
        /// @brief alias for: contiguous_iterator<T const>
        using const_iterator = contiguous_iterator<T const>;

        /// <!-- description -->
        ///   @brief Default constructor that creates a view with
        ///     data() == nullptr and size() == 0. It should be noted that
        ///     we specifically do not initialize m_ptr and m_count, which
        ///     ensures this is a POD type, allowing subclasses to be used
        ///     as a global resource.
        ///   @include view/example_view_default_constructor.hpp
        ///
        constexpr view() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a view given a pointer to an array, and the
        ///     number of elements in the array. Note that the array must be
        ///     contiguous in memory and [ptr, ptr + count) must be a valid
        ///     range.
        ///   @include view/example_view_ptr_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param ptr a pointer to the array being viewed.
        ///   @param count the number of elements in the array being viewed.
        ///
        constexpr view(pointer const ptr, size_type const count) noexcept    // --
            : m_ptr{ptr}, m_count{count}
        {
            if ((nullptr == m_ptr) || (0U == m_count)) {
                *this = view{};
            }
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/example_view_at_if.hpp
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
        ///   - We suppress this because A9-3-1 states that we should
        ///     not provide a non-const reference or pointer to private
        ///     member function, unless the class mimics a smart pointer or
        ///     a containter. This class mimics a container.
        ///
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer
        at_if(size_type const index) noexcept    // PRQA S 4211
        {
            if ((nullptr == m_ptr) || (index >= m_count)) {
                return nullptr;
            }

            return &m_ptr[index];    // PRQA S 3706, 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/example_view_at_if.hpp
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
        /// <!-- inputs/outputs -->
        ///   @param index the index of the instance to return
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "index". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer
        at_if(size_type const index) const noexcept
        {
            if ((nullptr == m_ptr) || (index >= m_count)) {
                return nullptr;
            }

            return &m_ptr[index];    // PRQA S 3706 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/example_view_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer
        front_if() noexcept
        {
            return this->at_if(0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///   @include view/example_view_front_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "0". If the index is out of bounds, or the view is invalid,
        ///     this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer
        front_if() const noexcept
        {
            return this->at_if(0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include view/example_view_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer
        back_if() noexcept
        {
            return this->at_if(m_count > 0 ? m_count - 1 : 0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///   @include view/example_view_back_if.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at index
        ///     "size() - 1". If the index is out of bounds, or the view is
        ///     invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer
        back_if() const noexcept
        {
            return this->at_if(m_count > 0 ? m_count - 1 : 0);
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///   @include view/example_view_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///
        [[nodiscard]] constexpr pointer
        data() noexcept
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///   @include view/example_view_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being viewed. If this is
        ///     a default constructed view, or the view was constructed in
        ///     error, this will return a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer
        data() const noexcept
        {
            return m_ptr;
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include view/example_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr iterator
        begin() noexcept
        {
            return iterator{m_ptr, m_count, 0U};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include view/example_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr const_iterator
        begin() const noexcept
        {
            return const_iterator{m_ptr, m_count, 0U};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the first element of the view.
        ///   @include view/example_view_begin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the first element of the view.
        ///
        [[nodiscard]] constexpr const_iterator
        cbegin() const noexcept
        {
            return const_iterator{m_ptr, m_count, 0U};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include view/example_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr iterator
        iter(size_type const i) noexcept
        {
            return iterator{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include view/example_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr const_iterator
        iter(size_type const i) const noexcept
        {
            return const_iterator{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to the element "i" in the view.
        ///   @include view/example_view_iter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to the element "i" in the view.
        ///
        [[nodiscard]] constexpr const_iterator
        citer(size_type const i) const noexcept
        {
            return const_iterator{m_ptr, m_count, i};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include view/example_view_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr iterator
        end() noexcept
        {
            return iterator{m_ptr, m_count, m_count};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include view/example_view_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr const_iterator
        end() const noexcept
        {
            return const_iterator{m_ptr, m_count, m_count};
        }

        /// <!-- description -->
        ///   @brief Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///   @include view/example_view_end.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns an iterator to one past the last element of the
        ///     view. If you attempt to access this iterator, a nullptr will
        ///     always be returned.
        ///
        [[nodiscard]] constexpr const_iterator
        cend() const noexcept
        {
            return const_iterator{m_ptr, m_count, m_count};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<iterator>
        rbegin() noexcept
        {
            return reverse_iterator<iterator>{this->end()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<const_iterator>
        rbegin() const noexcept
        {
            return reverse_iterator<const_iterator>{this->end()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator to one past the last element
        ///     of the view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_rbegin.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator to the last element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<const_iterator>
        crbegin() const noexcept
        {
            return reverse_iterator<const_iterator>{this->cend()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<iterator>
        riter(size_type const i) noexcept
        {
            size_type ai{i >= m_count ? m_count : i + 1};
            return reverse_iterator<iterator>{this->iter(ai)};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<const_iterator>
        riter(size_type const i) const noexcept
        {
            size_type ai{i >= m_count ? m_count : i + 1};
            return reverse_iterator<const_iterator>{this->iter(ai)};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator element "i" in the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_riter.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator element "i" in the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<const_iterator>
        criter(size_type const i) const noexcept
        {
            size_type ai{i >= m_count ? m_count : i + 1};
            return reverse_iterator<const_iterator>{this->citer(ai)};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<iterator>
        rend() noexcept
        {
            return reverse_iterator<iterator>{this->begin()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<const_iterator>
        rend() const noexcept
        {
            return reverse_iterator<const_iterator>{this->begin()};
        }

        /// <!-- description -->
        ///   @brief Returns a reverse iterator first element of the
        ///     view. When accessing the iterator, the iterator will
        ///     always return the element T[internal index - 1], providing
        ///     access to the range [size() - 1, 0) while internally storing the
        ///     range [size(), 1) with element 0 representing the end(). For more
        ///     information, see the bsl::reverse_iterator documentation.
        ///   @include view/example_view_rend.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reverse iterator first element of the
        ///     view.
        ///
        [[nodiscard]] constexpr reverse_iterator<const_iterator>
        crend() const noexcept
        {
            return reverse_iterator<const_iterator>{this->cbegin()};
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the array being
        ///     viewed. If this is a default constructed view, or the view
        ///     was constructed in error, this will return 0.
        ///   @include view/example_view_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the array being
        ///     viewed. If this is a default constructed view, or the view
        ///     was constructed in error, this will return 0.
        ///
        [[nodiscard]] constexpr size_type
        size() const noexcept
        {
            return m_count;
        }

        /// <!-- description -->
        ///   @brief Returns the max number of elements the BSL supports.
        ///   @include view/example_view_max_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max number of elements the BSL supports.
        ///
        [[nodiscard]] constexpr size_type
        max_size() const noexcept
        {
            return numeric_limits<size_type>::max() / sizeof(T);
        }

        /// <!-- description -->
        ///   @brief Returns size() * sizeof(T)
        ///   @include view/example_view_size_bytes.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() * sizeof(T)
        ///
        [[nodiscard]] constexpr size_type
        size_bytes() const noexcept
        {
            return m_count * sizeof(T);
        }

        /// <!-- description -->
        ///   @brief Returns size() == 0
        ///   @include view/example_view_empty.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns size() == 0
        ///
        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return 0U == m_count;
        }

    protected:
        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::view
        ///
        ~view() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr view(view const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr view(view &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        constexpr view &operator=(view const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        constexpr view &operator=(view &&o) &noexcept = default;

    private:
        /// @brief stores a pointer to the array being viewed
        T *m_ptr;
        /// @brief stores the number of elements in the array being viewed
        size_type m_count;
    };
}

#endif
