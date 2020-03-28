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
/// @file span.hpp
///

#ifndef BSL_SPAN_HPP
#define BSL_SPAN_HPP

#include "contiguous_iterator.hpp"
#include "cstdint.hpp"
#include "min.hpp"
#include "npos.hpp"
#include "reverse_iterator.hpp"
#include "view.hpp"

namespace bsl
{
    /// @class bsl::span
    ///
    /// <!-- description -->
    ///   @brief A bsl::span is a non-owning view of an array type. Unlike
    ///     a bsl::array, the bsl::span does not own the memory it accesses
    ///     and therefore cannot outlive whatever array you give it. The
    ///     bsl::span is also very similar to a gsl::span and a std::span
    ///     with some key differences.
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
    ///     - We do not provide any of the as_byte helper functions as they
    ///       would all require a reinterpret_cast which is not allowed
    ///       by AUTOSAR.
    ///     - A bsl::span is always a dynamic_extent type. The reason the
    ///       dynamic_extent type exists in a std::span is to optimize away
    ///       the need to store the size of the array the span is viewing.
    ///       This is only useful for C-style arrays which are not supported
    ///       as they are not compliant with AUTOSAR. If you need a C-style
    ///       array, use a bsl::array, in which case you have no need for a
    ///       bsl::span. Instead, a bsl::span is useful when you have an
    ///       array in memory that is not in your control (for example, a
    ///       device's memory).
    ///   @include example_view_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of element being viewed.
    ///
    template<typename T>
    class span final : public view<T>
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
        /// @brief alias for: T &
        using const_reference = T &;
        /// @brief alias for: T *
        using pointer = T *;
        /// @brief alias for: T const *
        using const_pointer = T *;
        /// @brief alias for: contiguous_iterator<T>
        using iterator = contiguous_iterator<T>;
        /// @brief alias for: contiguous_iterator<T const>
        using const_iterator = contiguous_iterator<T>;

        /// <!-- description -->
        ///   @brief Default constructor that creates a span with
        ///     data() == nullptr and size() == 0. All accessors
        ///     will return a nullptr if used. Note that like other view types
        ///     in the BSL, the bsl::span is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::span, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::span will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::span (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include span/example_span_default_constructor.hpp
        ///
        constexpr span() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a span given a pointer to an array, and the
        ///     number of elements in the array. Note that the array must be
        ///     contiguous in memory and [ptr, ptr + count) must be a valid
        ///     range.
        ///   @include span/example_span_ptr_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param ptr a pointer to the array being spaned.
        ///   @param count the number of elements in the array being spaned.
        ///
        constexpr span(pointer const ptr, size_type const count) noexcept    // --
            : m_view{ptr, count}
        {}

        /// <!-- description -->
        ///   @brief Returns subspan(0, count). If count is 0, an invalid
        ///     span is returned.
        ///   @include span/example_span_first.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param count the number of elements of the new subspan
        ///   @return Returns subspan(0, count). If count is 0, an invalid
        ///     span is returned.
        ///
        [[nodiscard]] constexpr span
        first(size_type count = npos) const noexcept
        {
            return this->subspan(0, count);
        }

        /// <!-- description -->
        ///   @brief Returns subspan(this->size() - count, count). If count
        ///     is greater than the size of the current span, a copy of the
        ///     current span is returned. If the count is 0, an invalid span
        ///     is returned.
        ///   @include span/example_span_last.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param count the number of elements of the new subspan
        ///   @return Returns subspan(this->size() - count, count). If count
        ///     is greater than the size of the current span, a copy of the
        ///     current span is returned. If the count is 0, an invalid span
        ///     is returned.
        ///
        [[nodiscard]] constexpr span
        last(size_type count = npos) const noexcept
        {
            if (count >= this->size()) {
                return *this;
            }

            return this->subspan(this->size() - count, count);
        }

        /// <!-- description -->
        ///   @brief Returns span{at_if(pos), min(count, size() - pos)}. If
        ///     the provided "pos" is greater than or equal to the size of
        ///     the current span, an invalid span is returned.
        ///   @include span/example_span_subspan.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of the new span
        ///   @param count the number of elements of the new subspan
        ///   @return Returns span{at_if(pos), min(count, size() - pos)}. If
        ///     the provided "pos" is greater than or equal to the size of
        ///     the current span, an invalid span is returned.
        ///
        [[nodiscard]] constexpr span
        subspan(size_type pos, size_type count = npos) const noexcept
        {
            if (pos >= this->size()) {
                return {};
            }

            return span{this->at_if(pos), min(count, this->size() - pos)};
        }
    };
}

#endif
