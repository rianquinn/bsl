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

#ifndef BSL_BASIC_STRING_VIEW_HPP
#define BSL_BASIC_STRING_VIEW_HPP

#include "char_traits.hpp"
#include "contiguous_iterator.hpp"
#include "cstdint.hpp"
#include "min.hpp"
#include "npos.hpp"
#include "reverse_iterator.hpp"
#include "view.hpp"

// TODO:
// - Need to implement the find functions. These need the safe_int class as
//   there is a lot of math that could result in overflow that needs to be
//   accounted for.
//

namespace bsl
{
    /// @class bsl::basic_string_view
    ///
    /// <!-- description -->
    ///   @brief A bsl::basic_string_view is a non-owning, encapsulation of a
    ///     string, providing helper functions for working with strings.
    ///   @include example_basic_string_view_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///
    template<typename CharT, typename Traits = char_traits<CharT>>
    class basic_string_view final : public view<CharT const>
    {
    public:
        /// @brief alias for: CharT const
        using value_type = CharT const;
        /// @brief alias for: bsl::uintmax
        using size_type = bsl::uintmax;
        /// @brief alias for: bsl::uintmax
        using difference_type = bsl::uintmax;
        /// @brief alias for: CharT const &
        using reference = CharT const &;
        /// @brief alias for: CharT const &
        using const_reference = CharT const &;
        /// @brief alias for: CharT const *
        using pointer = CharT const *;
        /// @brief alias for: CharT const const *
        using const_pointer = CharT const *;
        /// @brief alias for: contiguous_iterator<CharT const>
        using iterator = contiguous_iterator<CharT const>;
        /// @brief alias for: contiguous_iterator<CharT const const>
        using const_iterator = contiguous_iterator<CharT const>;

        /// <!-- description -->
        ///   @brief Default constructor that creates a basic_string_view with
        ///     data() == nullptr and size() == 0. All accessors
        ///     will return a nullptr if used. Note that like other view types
        ///     in the BSL, the bsl::basic_string_view is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::basic_string_view, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::basic_string_view will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::basic_string_view (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include basic_string_view/example_basic_string_view_default_constructor.hpp
        ///
        constexpr basic_string_view() noexcept = default;

        /// <!-- description -->
        ///   @brief ptr/count constructor. Creates a bsl::basic_string_view
        ///     given a pointer to a string and the number of characters in
        ///     the string.
        ///   @include basic_string_view/example_basic_string_view_s_count_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///   @param count the number of characters in the string
        ///
        constexpr basic_string_view(pointer const s, size_type const count) noexcept
            : view<CharT const>{s, count}
        {}

        /// <!-- description -->
        ///   @brief ptr constructor. This creates a bsl::basic_string_view
        ///     given a pointer to a string. The number of characters in the
        ///     string is determined using Traits<CharT>::length,
        ///     which scans for '\0'.
        ///   @include basic_string_view/example_basic_string_view_s_constructor.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply (as pointers are not fundamental types).
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///
        constexpr basic_string_view(pointer const s) noexcept    // PRQA S 2180 // NOLINT
            : view<CharT const>{s, Traits::length(s)}
        {}

        /// <!-- description -->
        ///   @brief Returns the length of the string being viewed. This is
        ///     the same as bsl::basic_string_view::size(). Note that the
        ///     length refers to the total number of characters in the
        ///     string and not the number of bytes in the string. For the
        ///     total number of bytes, use bsl::basic_string_view::size_bytes().
        ///   @include basic_string_view/example_basic_string_view_length.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the length of the string being viewed.
        ///
        [[nodiscard]] constexpr size_type
        length() const noexcept
        {
            return this->size();
        }

        /// <!-- description -->
        ///   @brief Moves the start of the view forward by n characters. If
        ///     n >= size(), the bsl::basic_string_view is reset to a NULL
        ///     string, with data() returning a nullptr, and size() returning 0.
        ///   @include basic_string_view/example_basic_string_view_remove_prefix.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param n the number of character to remove from the start of
        ///     the string.
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr basic_string_view &
        remove_prefix(size_type const n) noexcept
        {
            if (n >= this->size()) {
                *this = basic_string_view{};
            }

            *this = basic_string_view{this->at_if(n), this->size() - n};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Moves the end of the view back by n characters. If
        ///     n >= size(), the bsl::basic_string_view is reset to a NULL
        ///     string, with data() returning a nullptr, and size() returning 0.
        ///   @include basic_string_view/example_basic_string_view_remove_suffix.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param n the number of character to remove from the end of
        ///     the string.
        ///   @return returns *this
        ///
        [[maybe_unused]] constexpr basic_string_view &
        remove_suffix(size_type const n) noexcept
        {
            if (n >= this->size()) {
                *this = basic_string_view{};
            }

            *this = basic_string_view{this->at_if(0U), this->size() - n};
            return *this;
        }

        /// <!-- description -->
        ///   @brief Returns a new bsl::basic_string_view that is a
        ///     substring view of the original. The substring starts at "pos"
        ///     and ends at "pos" + "count". Note that this does not copy
        ///     the string, it simply changes the internal pointer and size
        ///     of the same string that is currently being viewed (meaning
        ///     the lifetime of the new substring cannot outlive the lifetime
        ///     of the string being viewed by the original
        ///     bsl::basic_string_view). If the provided "pos" or "count"
        ///     are invalid, this function returns an empty string view.
        ///   @include basic_string_view/example_basic_string_view_substr.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of the new substring.
        ///   @param count the length of the new bsl::basic_string_view
        ///   @return Returns a new bsl::basic_string_view that is a
        ///     substring view of the original. The substring starts at "pos"
        ///     and ends at "pos" + "count".
        ///
        [[nodiscard]] constexpr basic_string_view
        substr(size_type const pos = 0U, size_type const count = npos) const noexcept
        {
            if (pos >= this->size()) {
                return basic_string_view{};
            }

            return basic_string_view{this->at_if(pos), min(count, this->size() - pos)};
        }

        /// <!-- description -->
        ///   @brief Compares two strings.
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(basic_string_view const &v) const noexcept
        {
            return Traits::compare(this->data(), v.data(), min(this->size(), v.size()));
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count).compare(v)
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                      // --
            size_type const pos,      // --
            size_type const count,    // --
            basic_string_view const &v) const noexcept
        {
            return this->substr(pos, count).compare(v);
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos1, count1).compare(v.substr(pos2, count2))
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos1 the starting position of "this" to compare from
        ///   @param count1 the number of characters of "this" to compare
        ///   @param v the bsl::basic_string_view to compare with
        ///   @param pos2 the starting position of "v" to compare from
        ///   @param count2 the number of characters of "v" to compare
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                           // --
            size_type pos1,                // --
            size_type count1,              // --
            basic_string_view const &v,    // --
            size_type pos2,                // --
            size_type count2) const noexcept
        {
            return this->substr(pos1, count1).compare(v.substr(pos2, count2));
        }

        /// <!-- description -->
        ///   @brief Same as compare(basic_string_view{s})
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to a string to compare with "this"
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(pointer const s) const noexcept
        {
            return this->compare(basic_string_view{s});
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count).compare(basic_string_view{s})
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count the number of characters of "this" to compare
        ///   @param s a pointer to a string to compare with "this"
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(size_type pos, size_type count, pointer const s) const noexcept
        {
            return this->substr(pos, count).compare(basic_string_view{s});
        }

        /// <!-- description -->
        ///   @brief Same as substr(pos, count1).compare(basic_string_view{s, count2})
        ///   @include basic_string_view/example_basic_string_view_compare.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param pos the starting position of "this" to compare from
        ///   @param count1 the number of characters of "this" to compare
        ///   @param s a pointer to a string to compare with "this"
        ///   @param count2 the number of characters of "s" to compare
        ///   @return Returns the same results as std::strncmp
        ///
        [[nodiscard]] constexpr bsl::int32
        compare(                 // --
            size_type pos,       // --
            size_type count1,    // --
            pointer const s,     // --
            size_type count2) const noexcept
        {
            return this->substr(pos, count1).compare(basic_string_view{s, count2});
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(basic_string_view const &v) const noexcept
        {
            if (this->size() < v.size()) {
                return false;
            }

            return this->substr(0U, v.size()) == v;
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the CharT to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(CharT const c) const noexcept
        {
            if (auto *const ptr = this->front_if()) {
                return *ptr == c;
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Checks if the string begins with the given prefix
        ///   @include basic_string_view/example_basic_string_view_starts_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s the string to compare with
        ///   @return Returns true if the string begins with the given prefix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        starts_with(pointer const s) const noexcept
        {
            return this->starts_with(basic_string_view{s});
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the bsl::basic_string_view to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(basic_string_view const &v) const noexcept
        {
            if (this->size() < v.size()) {
                return false;
            }

            return this->compare(this->size() - v.size(), npos, v) == 0;
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the CharT to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(CharT const c) const noexcept
        {
            if (auto *const ptr = this->back_if()) {
                return *ptr == c;
            }

            return false;
        }

        /// <!-- description -->
        ///   @brief Checks if the string ends with the given suffix
        ///   @include basic_string_view/example_basic_string_view_ends_with.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param s the string to compare with
        ///   @return Returns true if the string ends with the given suffix,
        ///     false otherwise.
        ///
        [[nodiscard]] constexpr bool
        ends_with(pointer const s) const noexcept
        {
            return this->ends_with(basic_string_view{s});
        }
    };

    /// <!-- description -->
    ///   @brief Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator==(
        bsl::basic_string_view<CharT, Traits> const &lhs,
        bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        if (lhs.size() != rhs.size()) {
            return false;
        }

        return lhs.compare(rhs) == 0;
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator==(bsl::basic_string_view<CharT, Traits> const &lhs, CharT const *const rhs) noexcept
    {
        return lhs == bsl::basic_string_view<CharT, Traits>{rhs};
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings have the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), and contain the same characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator==(CharT const *const lhs, bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        return bsl::basic_string_view<CharT, Traits>{lhs} == rhs;
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(
        bsl::basic_string_view<CharT, Traits> const &lhs,
        bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(bsl::basic_string_view<CharT, Traits> const &lhs, CharT const *const rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///   @include basic_string_view/example_basic_string_view_not_equals.hpp
    ///   @related bsl::basic_string_view
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam CharT the type of characters in the string
    ///   @tparam Traits the traits class used to work with the string
    ///   @param lhs the left hand side of the operation
    ///   @param rhs the right hand side of the operation
    ///   @return Returns true if two strings are not the same length (which is
    ///     different from compare() which uses the minimum size between the
    ///     two provided strings), or contain different characters. Returns
    ///     false otherwise.
    ///
    template<typename CharT, typename Traits>
    constexpr bool
    operator!=(CharT const *const lhs, bsl::basic_string_view<CharT, Traits> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }
}

#endif
