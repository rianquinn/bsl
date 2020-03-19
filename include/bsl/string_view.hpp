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

#ifndef BSL_STRING_VIEW_HPP
#define BSL_STRING_VIEW_HPP

#include "details/view.hpp"

#include "char_traits.hpp"
#include "cstdint.hpp"

// TODO:
// - We currently do not implement the iterator based initialization
//   constructor.
// - We currently do not provide any of the type aliases. We need to
//   implement Clang Tidy checks for type aliasing before we can do
//   that to overcome limitations with PRQA.
//

namespace bsl
{
    template<typename CharT, typename Traits = char_traits<CharT>>
    class string_view final : public details::view<CharT>
    {
    public:
        /// <!-- description -->
        ///   @brief Default constructor that creates a string_view with
        ///     data() == nullptr and size()/length() == 0. All accessors
        ///     will return a nullptr if used. Note that like other view types
        ///     in the BSL, the bsl::string_view is a POD type. This means that
        ///     when declaring a global, default constructed bsl::string_view,
        ///     DO NOT include the {} for initialization. Instead, remove the
        ///     {} and the global bsl::string_view will be included in the BSS
        ///     section of the executable, and initialized to 0 for you.
        ///     All other instantiations of a bsl::string_view (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is not allowed by AUTOSAR.
        ///   @include  string_view/example_string_view_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        constexpr string_view() noexcept = default;

        /// <!-- description -->
        ///   @brief ptr/count constructor. This creates a bsl::string_view
        ///     given a pointer to a string and the number of characters in
        ///     the string.
        ///   @include string_view/example_string_view_s_count_constructor.hpp
        ///   @related
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///   @param count the number of characters in the string
        ///
        constexpr string_view(CharT const *const s, bsl::uintmax const count) noexcept
            : details::view<CharT>{s, count}
        {}

        /// <!-- description -->
        ///   @brief ptr constructor. This creates a bsl::string_view
        ///     given a pointer to a string. The number of characters in the
        ///     string is determined using bsl::char_types<CharT>::length,
        ///     which scans for '\0'.
        ///   @include string_view/example_string_view_s_constructor.hpp
        ///   @related
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param s a pointer to the string
        ///
        constexpr string_view(CharT const *const s) noexcept    // NOLINT
            : details::view<CharT>{s, Traits::length(s)}
        {}
    };
}

#endif
