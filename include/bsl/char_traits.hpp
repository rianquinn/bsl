/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
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
/// @file char_traits.hpp
///

#ifndef BSL_CHAR_TRAITS_HPP
#define BSL_CHAR_TRAITS_HPP

#include "char_type.hpp"
#include "cstring.hpp"
#include "safe_integral.hpp"
#include "touch.hpp"

namespace bsl
{
    /// @cond doxygen off

    /// @class bsl::char_traits
    ///
    /// <!-- description -->
    ///   @brief Provides the generic implementation of char_traits, which
    ///     does not implement any of the char_triats, generating a compiler
    ///     error if you attempt to use it.
    ///
    /// <!-- template parameters -->
    ///   @tparam CHAR_T the character type that is not supported
    ///
    template<typename CHAR_T>
    class char_traits final
    {};

    /// @endcond doxygen on

    /// <!-- description -->
    ///   @brief Implements the char_traits for the type "char_type", which is
    ///     a type alias for "char". In general, you should not need to use
    ///     this class directly, and we only provide it for compatibility.
    ///     Note that there are some BSL specific changes to the library, which
    ///     should not change the "valid" behavior of this class, but will
    ///     change "invalid" behavior to comply better with AUTOSAR. Also,
    ///     we do not provide support for the type aliases (due to name
    ///     collisions), and there are some functions that we do not support
    ///     as they are not really AUTOSAR compliant (requiring the use of
    ///     C-style array types). Once again, do not use this directly.
    ///     Instead, find a BSL alternative to this functionality.
    ///   @include example_char_traits_overview.hpp
    ///
    template<>
    class char_traits<char_type> final
    {
    public:
        /// <!-- description -->
        ///   @brief Returns true if "a" == "b"
        ///   @include char_traits/example_char_traits_eq.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param a the left hand side of the query
        ///   @param b the right hand side of the query
        ///   @return Returns true if "a" == "b"
        ///
        [[nodiscard]] static constexpr auto
        eq(char_type const a, char_type const b) noexcept -> bool
        {
            return a == b;
        }

        /// <!-- description -->
        ///   @brief Returns true if "a" < "b"
        ///   @include char_traits/example_char_traits_lt.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param a the left hand side of the query
        ///   @param b the right hand side of the query
        ///   @return Returns true if "a" < "b"
        ///
        [[nodiscard]] static constexpr auto
        lt(char_type const a, char_type const b) noexcept -> bool
        {
            return a < b;
        }

        /// <!-- description -->
        ///   @brief Compares two strings. Returns negative value if s1 appears
        ///     before s2 in lexicographical order. Return 0 if s1 and s2
        ///     compare equal, if s1 or s2 are nullptr, or if count is zero.
        ///     Positive value if s1 appears after s2 in lexicographical order.
        ///   @include char_traits/example_char_traits_compare.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     return 0 if s1 or s2 are a nullptr (same as if num was set
        ///     to 0).
        ///
        /// <!-- inputs/outputs -->
        ///   @param s1 the left hand side of the query
        ///   @param s2 the right hand side of the query
        ///   @param count the number of characters to compare
        ///   @return Returns negative value if s1 appears before s2 in
        ///     lexicographical order. Return 0 if s1 and s2 compare equal,
        ///     if s1 or s2 are nullptr, or if count is zero. Positive value
        ///     if s1 appears after s2 in lexicographical order.
        ///
        [[nodiscard]] static constexpr auto
        compare(                          // --
            char_type const *const s1,    // --
            char_type const *const s2,    // --
            safe_uintmax const &count) noexcept -> safe_int32
        {
            return bsl::builtin_strncmp(s1, s2, count);
        }

        /// <!-- description -->
        ///   @brief Returns the length of the provided string.
        ///   @include char_traits/example_char_traits_length.hpp
        ///
        /// <!-- notes -->
        ///   @note The BSL adds a nullptr check to this call, and will
        ///     return 0 if s is a nullptr.
        ///
        /// <!-- inputs/outputs -->
        ///   @param s the string to get the length of
        ///   @return Returns the length of the provided string.
        ///
        [[nodiscard]] static constexpr auto
        length(char_type const *const s) noexcept -> safe_uintmax
        {
            return bsl::builtin_strlen(s);
        }

        /// <!-- description -->
        ///   @brief Converts a value of bsl::intmax to char_type. If there is
        ///     no equivalent value (such as when c is a copy of the eof value),
        ///     the results are unspecified.
        ///   @include char_traits/example_char_traits_to_char_type.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the character to convert
        ///   @return c
        ///
        [[nodiscard]] static constexpr auto
        to_char_type(bsl::intmax const c) noexcept -> char_type
        {
            return static_cast<char_type>(c);
        }

        /// <!-- description -->
        ///   @brief Converts a value of char_type to bsl::intmax.
        ///   @include char_traits/example_char_traits_to_int_type.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c the character to convert
        ///   @return c
        ///
        [[nodiscard]] static constexpr auto
        to_int_type(char_type const c) noexcept -> bsl::intmax
        {
            return static_cast<bsl::intmax>(c);
        }

        /// <!-- description -->
        ///   @brief Checks whether two values of type int_type are equal.
        ///   @include char_traits/example_char_traits_eq_int_type.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param c1 the left hand side of the query
        ///   @param c2 the right hand side of the query
        ///   @return Returns eq(c1, c2) if c1 and c2 are valid char types.
        ///     Returns true if c1 and c2 are both EOF. Returns false
        ///     otherwise.
        ///
        [[nodiscard]] static constexpr auto
        eq_int_type(bsl::intmax const c1, bsl::intmax const c2) noexcept -> bool
        {
            if (eof() == c1) {
                if (eof() == c2) {
                    return true;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            return eq(to_char_type(c1), to_char_type(c2));
        }

        /// <!-- description -->
        ///   @brief Returns the value of EOF
        ///   @include char_traits/example_char_traits_eof.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of EOF
        ///
        [[nodiscard]] static constexpr auto
        eof() noexcept -> bsl::intmax
        {
            constexpr bsl::intmax value_of_eof{static_cast<bsl::intmax>(-1)};
            return value_of_eof;
        }

        /// <!-- description -->
        ///   @brief Returns e if e is not EOF, otherwise returns 0.
        ///   @include char_traits/example_char_traits_not_eof.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param e the character to query
        ///   @return Returns e if e is not EOF, otherwise returns 0.
        ///
        [[nodiscard]] static constexpr auto
        not_eof(bsl::intmax const e) noexcept -> bsl::intmax
        {
            if (!eq_int_type(e, eof())) {
                return e;
            }

            return static_cast<bsl::intmax>(0);
        }
    };
}

#endif
