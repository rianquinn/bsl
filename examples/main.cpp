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

#include "example_add_const__overview.hpp"
#include "example_add_lvalue_reference__overview.hpp"
#include "example_add_pointer__overview.hpp"
#include "example_add_rvalue_reference__overview.hpp"
#include "example_aligned_storage__overview.hpp"
#include "example_bind_apis__overview.hpp"
#include "example_byte__overview.hpp"
#include "example_conditional__overview.hpp"
#include "example_construct_at__overview.hpp"
#include "example_decay__overview.hpp"
#include "example_destroy_at__overview.hpp"
#include "example_discard__overview.hpp"
#include "example_enable_if__overview.hpp"
#include "example_is_assignable__overview.hpp"
#include "example_is_base_of__overview.hpp"
#include "example_is_bool__overview.hpp"
#include "example_is_class__overview.hpp"
#include "example_is_compound__overview.hpp"
#include "example_is_const__overview.hpp"
#include "example_is_constructible__overview.hpp"
#include "example_is_copy_assignable__overview.hpp"
#include "example_is_copy_constructible__overview.hpp"
#include "example_is_default_constructible__overview.hpp"
#include "example_is_empty__overview.hpp"
#include "example_is_enum__overview.hpp"
#include "example_is_function__overview.hpp"
#include "example_is_fundamental__overview.hpp"
#include "example_is_integral__overview.hpp"
#include "example_is_lvalue_reference__overview.hpp"
#include "example_is_member_function_pointer__overview.hpp"
#include "example_is_member_object_pointer__overview.hpp"
#include "example_is_member_pointer__overview.hpp"
#include "example_is_move_assignable__overview.hpp"
#include "example_is_move_constructible__overview.hpp"
#include "example_is_nullptr__overview.hpp"
#include "example_is_object__overview.hpp"
#include "example_is_pod__overview.hpp"
#include "example_is_pointer__overview.hpp"
#include "example_is_reference__overview.hpp"
#include "example_is_rvalue_reference__overview.hpp"
#include "example_is_same__overview.hpp"
#include "example_is_scalar__overview.hpp"
#include "example_is_signed__overview.hpp"
#include "example_is_standard_layout__overview.hpp"
#include "example_is_trivial__overview.hpp"
#include "example_is_unsigned__overview.hpp"
#include "example_is_void__overview.hpp"
#include "example_make_signed__overview.hpp"
#include "example_make_unsigned__overview.hpp"
#include "example_move__overview.hpp"
#include "example_remove_const__overview.hpp"
#include "example_remove_pointer__overview.hpp"
#include "example_remove_reference__overview.hpp"
#include "example_swap__overview.hpp"
#include "example_type_identity__overview.hpp"
#include "example_underlying_type__overview.hpp"

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

        example_add_const__overview(args);
        example_add_lvalue_reference__overview(args);
        example_add_pointer__overview(args);
        example_add_rvalue_reference__overview(args);
        example_aligned_storage__overview(args);
        example_bind_apis__overview(args);
        example_byte__overview(args);
        example_conditional__overview(args);
        example_construct_at__overview(args);
        example_decay__overview(args);
        example_destroy_at__overview(args);
        example_discard__overview(args);
        example_enable_if__overview(args);
        example_is_assignable__overview(args);
        example_is_base_of__overview(args);
        example_is_bool__overview(args);
        example_is_class__overview(args);
        example_is_compound__overview(args);
        example_is_const__overview(args);
        example_is_constructible__overview(args);
        example_is_copy_assignable__overview(args);
        example_is_copy_constructible__overview(args);
        example_is_default_constructible__overview(args);
        example_is_empty__overview(args);
        example_is_enum__overview(args);
        example_is_function__overview(args);
        example_is_fundamental__overview(args);
        example_is_integral__overview(args);
        example_is_lvalue_reference__overview(args);
        example_is_member_function_pointer__overview(args);
        example_is_member_object_pointer__overview(args);
        example_is_member_pointer__overview(args);
        example_is_move_assignable__overview(args);
        example_is_move_constructible__overview(args);
        example_is_nullptr__overview(args);
        example_is_object__overview(args);
        example_is_pod__overview(args);
        example_is_pointer__overview(args);
        example_is_reference__overview(args);
        example_is_rvalue_reference__overview(args);
        example_is_same__overview(args);
        example_is_scalar__overview(args);
        example_is_signed__overview(args);
        example_is_standard_layout__overview(args);
        example_is_trivial__overview(args);
        example_is_unsigned__overview(args);
        example_is_void__overview(args);
        example_make_signed__overview(args);
        example_make_unsigned__overview(args);
        example_move__overview(args);
        example_remove_const__overview(args);
        example_remove_pointer__overview(args);
        example_remove_reference__overview(args);
        example_swap__overview(args);
        example_type_identity__overview(args);
        example_underlying_type__overview(args);

        return bsl::exit_code::exit_success;
    }
}
