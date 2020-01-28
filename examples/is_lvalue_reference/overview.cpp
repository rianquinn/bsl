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

#include <bsl/discard.hpp>
#include <bsl/main.hpp>

#include <bsl/is_reference.hpp>
#include <bsl/is_lvalue_reference.hpp>
#include <bsl/is_rvalue_reference.hpp>
#include <bsl/add_lvalue_reference.hpp>
#include <bsl/add_rvalue_reference.hpp>
#include <bsl/remove_reference.hpp>

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
    bsl::exit_code
    entry(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);

        static_assert(!bsl::is_reference<bool>::value);
        static_assert(!bsl::is_lvalue_reference<bool>::value);
        static_assert(!bsl::is_rvalue_reference<bool>::value);

        static_assert(bsl::is_reference<bsl::add_lvalue_reference_t<bool>>::value);
        static_assert(bsl::is_reference<bsl::add_lvalue_reference_t<bool &>>::value);
        static_assert(bsl::is_reference<bsl::add_lvalue_reference_t<bool &&>>::value);
        static_assert(bsl::is_lvalue_reference<bsl::add_lvalue_reference_t<bool>>::value);
        static_assert(bsl::is_lvalue_reference<bsl::add_lvalue_reference_t<bool &>>::value);
        static_assert(bsl::is_lvalue_reference<bsl::add_lvalue_reference_t<bool &&>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::add_lvalue_reference_t<bool>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::add_lvalue_reference_t<bool &>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::add_lvalue_reference_t<bool &&>>::value);

        static_assert(bsl::is_reference<bsl::add_rvalue_reference_t<bool>>::value);
        static_assert(bsl::is_reference<bsl::add_rvalue_reference_t<bool &>>::value);
        static_assert(bsl::is_reference<bsl::add_rvalue_reference_t<bool &&>>::value);
        static_assert(!bsl::is_lvalue_reference<bsl::add_rvalue_reference_t<bool>>::value);
        static_assert(bsl::is_lvalue_reference<bsl::add_rvalue_reference_t<bool &>>::value);
        static_assert(!bsl::is_lvalue_reference<bsl::add_rvalue_reference_t<bool &&>>::value);
        static_assert(bsl::is_rvalue_reference<bsl::add_rvalue_reference_t<bool>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::add_rvalue_reference_t<bool &>>::value);
        static_assert(bsl::is_rvalue_reference<bsl::add_rvalue_reference_t<bool &&>>::value);

        static_assert(!bsl::is_lvalue_reference<bsl::remove_reference_t<bool>>::value);
        static_assert(!bsl::is_lvalue_reference<bsl::remove_reference_t<bool &>>::value);
        static_assert(!bsl::is_lvalue_reference<bsl::remove_reference_t<bool &&>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::remove_reference_t<bool>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::remove_reference_t<bool &>>::value);
        static_assert(!bsl::is_rvalue_reference<bsl::remove_reference_t<bool &&>>::value);

        static_assert(!bsl::is_reference<bsl::add_lvalue_reference_t<void>>::value);
        static_assert(!bsl::is_reference<bsl::add_rvalue_reference_t<void>>::value);

        return bsl::exit_code::exit_success;
    }
}
