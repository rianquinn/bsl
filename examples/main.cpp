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

#include <bsl/cstr_type.hpp>
#include <bsl/exit_code.hpp>

#include "example_add_const_overview.hpp"
#include "example_add_lvalue_reference_overview.hpp"
#include "example_add_pointer_overview.hpp"
#include "example_add_rvalue_reference_overview.hpp"
#include "example_aligned_storage_overview.hpp"
#include "example_alignment_of_overview.hpp"
#include "example_as_const_overview.hpp"
#include "example_bind_apis_overview.hpp"
#include "example_byte_overview.hpp"
#include "example_common_type_overview.hpp"
// #include "example_conditional_overview.hpp"
// #include "example_construct_at_overview.hpp"
// #include "example_decay_overview.hpp"
// #include "example_destroy_at_overview.hpp"
// #include "example_discard_overview.hpp"
// #include "example_enable_if_overview.hpp"
// #include "example_is_assignable_overview.hpp"
// #include "example_is_base_of_overview.hpp"
// #include "example_is_bool_overview.hpp"
// #include "example_is_class_overview.hpp"
// #include "example_is_compound_overview.hpp"
// #include "example_is_const_overview.hpp"
// #include "example_is_constructible_overview.hpp"
// #include "example_is_copy_assignable_overview.hpp"
// #include "example_is_copy_constructible_overview.hpp"
// #include "example_is_default_constructible_overview.hpp"
// #include "example_is_empty_overview.hpp"
// #include "example_is_enum_overview.hpp"
// #include "example_is_function_overview.hpp"
// #include "example_is_fundamental_overview.hpp"
// #include "example_is_integral_overview.hpp"
// #include "example_is_lvalue_reference_overview.hpp"
// #include "example_is_member_function_pointer_overview.hpp"
// #include "example_is_member_object_pointer_overview.hpp"
// #include "example_is_member_pointer_overview.hpp"
// #include "example_is_move_assignable_overview.hpp"
// #include "example_is_move_constructible_overview.hpp"
// #include "example_is_nullptr_overview.hpp"
// #include "example_is_object_overview.hpp"
// #include "example_is_pod_overview.hpp"
// #include "example_is_pointer_overview.hpp"
// #include "example_is_reference_overview.hpp"
// #include "example_is_rvalue_reference_overview.hpp"
// #include "example_is_same_overview.hpp"
// #include "example_is_scalar_overview.hpp"
// #include "example_is_signed_overview.hpp"
// #include "example_is_standard_layout_overview.hpp"
// #include "example_is_trivial_overview.hpp"
// #include "example_is_unsigned_overview.hpp"
// #include "example_is_void_overview.hpp"
// #include "example_make_signed_overview.hpp"
// #include "example_make_unsigned_overview.hpp"
// #include "example_move_overview.hpp"
// #include "example_remove_const_overview.hpp"
// #include "example_remove_pointer_overview.hpp"
// #include "example_remove_reference_overview.hpp"
// #include "example_swap_overview.hpp"
// #include "example_type_identity_overview.hpp"
// #include "example_underlying_type_overview.hpp"

/// <!-- description -->
///   @brief Provides the example's main function
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @param argc the total number of arguments passed to the application
///   @param argv the arguments passed to the application
///   @return 0 on success, non-0 on failure
///
bsl::exit_code
main(bsl::int32 const argc, bsl::cstr_type const *const argv) noexcept
{
    if ((0 == argc) || (nullptr == argv)) {
        return bsl::exit_failure;
    }

    bsl::example_add_const_overview();
    bsl::example_add_lvalue_reference_overview();
    bsl::example_add_pointer_overview();
    bsl::example_add_rvalue_reference_overview();
    bsl::example_aligned_storage_overview();
    bsl::example_alignment_of_overview();
    bsl::example_as_const_overview();
    bsl::example_bind_apis_overview();
    bsl::example_byte_overview();
    bsl::example_common_type_overview();
    // bsl::example_conditional_overview();
    // bsl::example_construct_at_overview();
    // bsl::example_decay_overview();
    // bsl::example_destroy_at_overview();
    // bsl::example_discard_overview();
    // bsl::example_enable_if_overview();
    // bsl::example_is_assignable_overview();
    // bsl::example_is_base_of_overview();
    // bsl::example_is_bool_overview();
    // bsl::example_is_class_overview();
    // bsl::example_is_compound_overview();
    // bsl::example_is_const_overview();
    // bsl::example_is_constructible_overview();
    // bsl::example_is_copy_assignable_overview();
    // bsl::example_is_copy_constructible_overview();
    // bsl::example_is_default_constructible_overview();
    // bsl::example_is_empty_overview();
    // bsl::example_is_enum_overview();
    // bsl::example_is_function_overview();
    // bsl::example_is_fundamental_overview();
    // bsl::example_is_integral_overview();
    // bsl::example_is_lvalue_reference_overview();
    // bsl::example_is_member_function_pointer_overview();
    // bsl::example_is_member_object_pointer_overview();
    // bsl::example_is_member_pointer_overview();
    // bsl::example_is_move_assignable_overview();
    // bsl::example_is_move_constructible_overview();
    // bsl::example_is_nullptr_overview();
    // bsl::example_is_object_overview();
    // bsl::example_is_pod_overview();
    // bsl::example_is_pointer_overview();
    // bsl::example_is_reference_overview();
    // bsl::example_is_rvalue_reference_overview();
    // bsl::example_is_same_overview();
    // bsl::example_is_scalar_overview();
    // bsl::example_is_signed_overview();
    // bsl::example_is_standard_layout_overview();
    // bsl::example_is_trivial_overview();
    // bsl::example_is_unsigned_overview();
    // bsl::example_is_void_overview();
    // bsl::example_make_signed_overview();
    // bsl::example_make_unsigned_overview();
    // bsl::example_move_overview();
    // bsl::example_remove_const_overview();
    // bsl::example_remove_pointer_overview();
    // bsl::example_remove_reference_overview();
    // bsl::example_swap_overview();
    // bsl::example_type_identity_overview();
    // bsl::example_underlying_type_overview();

    return bsl::exit_success;
}
