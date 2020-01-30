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

#ifndef BSL_UT_HPP
#define BSL_UT_HPP

#include "details/scenario_impl.hpp"
#include "details/scenario_step_impl.hpp"

namespace bsl
{
    /// @brief defines a scenario
    using ut_scenario = details::scenario_impl;

    /// @brief defines a scenario
    using ut_given = details::scenario_step_impl;

    /// @brief defines a scenario
    using ut_when = details::scenario_step_impl;

    /// @brief defines a scenario
    using ut_then = details::scenario_step_impl;

    /// <!-- description -->
    ///   @brief Sets the unit test's reset handler. After each test has
    ///     executed, this register handler will be called.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param hdlr the handler to register as the reset handler
    ///
    template<typename T = void>
    void
    set_ut_reset_handler(details::ut_test_handler_type const hdlr) noexcept
    {
        details::ut_reset_handler() = hdlr;
    }

    /// <!-- description -->
    ///   @brief Outputs a message and returns bsl::exit_code::exit_success
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return returns bsl::exit_code::exit_success
    ///
    template<typename T = void>
    bsl::exit_code
    ut_success() noexcept
    {
        printf("%s%s%s\n", green, "All tests passed", reset_color);
        return bsl::exit_code::exit_success;
    }

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    template<typename T = void>
    [[maybe_unused]] bool
    ut_check(const bool test, sloc_type const &sloc = here()) noexcept
    {
        if (!test) {
            printf("%s%s%s ", red, "[CHECK FAILED]", reset_color);
            printf("in test case \"");
            printf("%s%s%s", magenta, details::ut_current_test_case(), reset_color);
            printf("\"\n");
            details::ut_output_here(sloc);

            std::exit(EXIT_FAILURE);    // PRQA S 5024
        }

        return test;
    }
}

#endif
