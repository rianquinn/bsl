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
/// @file reverse_iterator.hpp
///

#ifndef BSL_REVERSE_ITERATOR_HPP
#define BSL_REVERSE_ITERATOR_HPP

#include "cstdint.hpp"

// TODO
// - We need to implement the remianing functions that are part of the
//   reverse iterator specification. Specifically, the increment and
//   decrement by "n" functions as they all require the safe_int class
//   to be effective at preventing wrapping, overruns and underruns.
//   Currently we only support the ++/-- functions as those are simple
//   to implement without the need for safe_int. Also note that we would
//   need some extra logic to ensure the iterator stays in-bounds.
//

namespace bsl
{
    /// @class
    ///
    /// <!-- description -->
    ///   @brief Provides a reverse iterator as defined by the C++
    ///     specification, with the follwing differences:
    ///     - The difference type that we use is a bsl::uintmax instead of a
    ///       signed type, which causes a lot of problems with AUTOSAR
    ///       compliance as signed/unsigned conversions and overflow are a
    ///       huge problem with the standard library. This iterator type is
    ///       used by all of the "view" type containers including the
    ///       bsl::span, bsl::array and bsl::string_view
    ///     - We do not provide any of the *, -> or [] accessors as none of
    ///       these accessors are compliant with AUTOSAR. Instead, we provide
    ///       a get_if() function, which returns a pointer to the element
    ///       being accessed by the iterator, or a nullptr if the iterator is
    ///       invalid or is the same as end(). As a result, ranged based for
    ///       loops are not supported, and instead, use a view's for_each
    ///       function which will perform the same action, with less overhead,
    ///       and better safety.
    ///     - The iterator is always inbounds, equal to end() or is invalid.
    ///       Traditional iterators can be anything, they can overrun,
    ///       underrun, and everyting in between. If this iterator is valid,
    ///       the index is always bounded by the size of the array it is
    ///       pointing to, or is equal to end(). Wrapping, overruns, and
    ///       underruns are not possible.
    ///     - We do not provide the protected member "current" as this class
    ///       cannot be subclassed.
    ///   @include example_reverse_iterator_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam Iter The type of iterator to reverse
    ///
    template<typename Iter>
    class reverse_iterator final
    {
    public:
        /// @brief alias for: typename Iter::value_type
        using value_type = typename Iter::value_type;
        /// @brief alias for: bsl::uintmax
        using size_type = bsl::uintmax;
        /// @brief alias for: bsl::uintmax
        using difference_type = bsl::uintmax;
        /// @brief alias for: typename Iter::value_type &
        using reference = typename Iter::value_type &;
        /// @brief alias for: typename Iter::value_type const &
        using const_reference = typename Iter::value_type const &;
        /// @brief alias for: typename Iter::value_type *
        using pointer = typename Iter::value_type *;
        /// @brief alias for: typename Iter::value_type const *
        using const_pointer = typename Iter::value_type const *;

        /// <!-- description -->
        ///   @brief Default constructor that creates a reverse iterator
        ///     with get_if() == nullptr. It should be noted that we
        ///     specifically do not initialize m_i which ensures this is a
        ///     POD typethe reverse iterator to be used as a global resource.
        ///   @include reverse_iterator/example_reverse_iterator_default_constructor.hpp
        ///
        constexpr reverse_iterator() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a reverse iterator given a an iterator to reverse.
        ///     It should be noted that you should not call this directly,
        ///     but instead should call rbegin() or rend() for your given
        ///     container.
        ///   @include reverse_iterator/example_reverse_iterator_ptr_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the iterator to use
        ///
        explicit constexpr reverse_iterator(Iter const &i) noexcept    // --
            : m_i{i}
        {}

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include reverse_iterator/example_reverse_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr Iter
        base() const noexcept
        {
            return m_i;
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the array being iterated
        ///   @include contiguous_iterator/example_contiguous_iterator_data.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the array being iterated
        ///
        [[nodiscard]] constexpr const_pointer
        data() const noexcept
        {
            return m_i.data();
        }

        /// <!-- description -->
        ///   @brief Returns the number of elements in the array being iterated
        ///   @include contiguous_iterator/example_contiguous_iterator_size.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the number of elements in the array being iterated
        ///
        [[nodiscard]] constexpr size_type
        size() const noexcept
        {
            return m_i.size();
        }

        /// <!-- description -->
        ///   @brief Returns the iterator's current index. If the iterator is
        ///     at the end, this function returns size().
        ///   @include contiguous_iterator/example_contiguous_iterator_index.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the iterator's current index
        ///
        [[nodiscard]] constexpr size_type
        index() const noexcept
        {
            if (m_i.index() == 0U) {
                return m_i.size();
            }

            return m_i.index() - 1U;
        }

        /// <!-- description -->
        ///   @brief Returns true if the iterator is valid (i.e., points to
        ///     an array). Default constructed iterators, or iterators that
        ///     are constructed with invalid arguments are invalid.
        ///   @include contiguous_iterator/example_contiguous_iterator_index.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the iterator's current index
        ///
        [[nodiscard]] constexpr bool
        valid() const noexcept
        {
            return m_i.valid();
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include contiguous_iterator/example_contiguous_iterator_get_if.hpp
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
        /// <!-- inputs/outputs -->
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr pointer
        get_if() noexcept    // PRQA S 4211
        {
            if (nullptr == m_i.data()) {
                return nullptr;
            }

            if (m_i.index() == 0U) {
                return nullptr;
            }

            return &m_i.data()[m_i.index() - 1U];    // PRQA S 3706, 4024 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///   @include contiguous_iterator/example_contiguous_iterator_get_if.hpp
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
        ///   @return Returns a pointer to the instance of T stored at the
        ///     iterator's current index. If the index is out of bounds,
        ///     or the iterator is invalid, this function returns a nullptr.
        ///
        [[nodiscard]] constexpr const_pointer
        get_if() const noexcept
        {
            if (nullptr == m_i.data()) {
                return nullptr;
            }

            if (m_i.index() == 0) {
                return nullptr;
            }

            return &m_i.data()[m_i.index() - 1];    // PRQA S 3706 // NOLINT
        }

        /// <!-- description -->
        ///   @brief Increments the iterator
        ///   @include reverse_iterator/example_reverse_iterator_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr reverse_iterator &
        operator++() noexcept
        {
            --m_i;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Increments the iterator (postfix)
        ///   @include reverse_iterator/example_reverse_iterator_increment.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr reverse_iterator
        operator++(int) noexcept
        {
            reverse_iterator tmp{*this};
            --m_i;
            return tmp;
        }

        /// <!-- description -->
        ///   @brief Decrements the iterator
        ///   @include reverse_iterator/example_reverse_iterator_decrement.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr reverse_iterator &
        operator--() noexcept
        {
            ++m_i;
            return *this;
        }

        /// <!-- description -->
        ///   @brief Decrements the iterator
        ///   @include reverse_iterator/example_reverse_iterator_decrement.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr reverse_iterator
        operator--(int) noexcept
        {
            reverse_iterator tmp{*this};
            ++m_i;
            return tmp;
        }

    private:
        /// @brief Stores the iterator being reversed.
        Iter m_i;
    };

    /// <!-- description -->
    ///   @brief Returns lhs.base() == rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_equals.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() == rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator==(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() == rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() != rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_equals.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() != rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator!=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() < rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_lt.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() < rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator<(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() < rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() <= rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_lt_assign.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() <= rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator<=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() <= rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() > rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_gt.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() > rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator>(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() > rhs.base();
    }

    /// <!-- description -->
    ///   @brief Returns lhs.base() >= rhs.base()
    ///   @include reverse_iterator/example_reverse_iterator_gt_assign.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T the type of element being iterated.
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the rhs hand side of the operation
    ///   @return Returns lhs.base() >= rhs.base()
    ///
    template<typename T>
    [[nodiscard]] constexpr bool
    operator>=(reverse_iterator<T> const &lhs, reverse_iterator<T> const &rhs) noexcept
    {
        return lhs.base() >= rhs.base();
    }

    /// <!-- description -->
    ///   @brief Constructs a reverse_iterator for a given provided iterator.
    ///   @include reverse_iterator/example_reverse_iterator_make_reverse_iterator.hpp
    ///   @related bsl::reverse_iterator
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam Iter the type of iterator to make the reverse iterator from.
    ///   @param i the iterator to make the reverse iterator from.
    ///   @return a newly constructed reverse iterator.
    ///
    template<typename Iter>
    constexpr reverse_iterator<Iter>
    make_reverse_iterator(Iter const &i) noexcept
    {
        return {i};
    }
}

#endif
