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

#ifndef EXAMPLE_BIND_APIS__OVERVIEW_HPP
#define EXAMPLE_BIND_APIS__OVERVIEW_HPP

#include <bsl/discard.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/arguments.hpp>

#include <bsl/print.hpp>
#include "example_interface.hpp"
#include "example_implementation.hpp"

namespace bsl
{
    using example_bind_apis_type = bind_apis<example_interface, example_implementation>;

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
    example_bind_apis__overview(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);

        constexpr bsl::int32 valid_answer{42};
        if (example_bind_apis_type::static_func_example(valid_answer)) {
            bsl::print("success\n");
        }

        constexpr bsl::int32 invalid_answer{23};
        if (!example_bind_apis_type::static_func_example(invalid_answer)) {
            bsl::print("success\n");
        }

        if (auto const impl = example_implementation::make(valid_answer).get_if()) {
            example_bind_apis_type enforced_impl{*impl};

            if (enforced_impl.member_func_example(valid_answer)) {
                bsl::print("success\n");
            }

            if (!enforced_impl.member_func_example(invalid_answer)) {
                bsl::print("success\n");
            }
        }
        else {
            bsl::print("failure\n");
        }

        if (auto const impl = example_implementation::make(invalid_answer).get_if()) {
            bsl::discard(impl);
            bsl::print("failure\n");
        }
        else {
            bsl::print("success\n");
        }

        return bsl::exit_code::exit_success;
    }
}

#endif
