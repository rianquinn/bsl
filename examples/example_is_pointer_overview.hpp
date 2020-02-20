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

#ifndef EXAMPLE_IS_POINTER_OVERVIEW_HPP
#define EXAMPLE_IS_POINTER_OVERVIEW_HPP

#include <bsl/discard.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/arguments.hpp>

#include <bsl/is_same.hpp>
#include <bsl/is_pointer.hpp>
#include <bsl/add_pointer.hpp>
#include <bsl/remove_pointer.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments passed to the application
    ///   @return exit_success on success, exit_failure otherwise
    ///
    [[maybe_unused]] inline bsl::exit_code
    example_is_pointer_overview(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);

        static_assert(!bsl::is_pointer<bool>::value);
        static_assert(!bsl::is_pointer<bool &>::value);
        static_assert(!bsl::is_pointer<bool &&>::value);

        static_assert(bsl::is_pointer<bsl::add_pointer_t<bool>>::value);
        static_assert(bsl::is_pointer<bsl::add_pointer_t<bool &>>::value);
        static_assert(bsl::is_pointer<bsl::add_pointer_t<bool &&>>::value);
        static_assert(bsl::is_pointer<bsl::add_pointer_t<bool const>>::value);
        static_assert(bsl::is_pointer<bsl::add_pointer_t<bool const &>>::value);

        static_assert(bsl::is_same<bsl::add_pointer_t<bool>, bool *>::value);
        static_assert(bsl::is_same<bsl::add_pointer_t<bool &>, bool *>::value);
        static_assert(bsl::is_same<bsl::add_pointer_t<bool &&>, bool *>::value);
        static_assert(bsl::is_same<bsl::add_pointer_t<bool const>, bool const *>::value);
        static_assert(bsl::is_same<bsl::add_pointer_t<bool const &>, bool const *>::value);

        static_assert(!bsl::is_pointer<bsl::remove_pointer_t<bool *>>::value);
        static_assert(!bsl::is_pointer<bsl::remove_pointer_t<bool *const>>::value);
        static_assert(!bsl::is_pointer<bsl::remove_pointer_t<bool const *const>>::value);

        static_assert(bsl::is_same<bsl::remove_pointer_t<bool *>, bool>::value);
        static_assert(bsl::is_same<bsl::remove_pointer_t<bool const *>, bool const>::value);
        static_assert(bsl::is_same<bsl::remove_pointer_t<bool const *const>, bool const>::value);

        return bsl::exit_success;
    }
}

#endif
