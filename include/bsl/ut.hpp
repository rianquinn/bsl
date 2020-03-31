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

#include <cstdlib>

#include "color.hpp"
#include "cstr_type.hpp"
#include "exit_code.hpp"
#include "forward.hpp"
#include "invoke.hpp"
#include "is_constant_evaluated.hpp"
#include "main.hpp"
#include "print.hpp"
#include "source_location.hpp"

#pragma clang diagnostic ignored "-Wunused-member-function"
#pragma clang diagnostic ignored "-Wunneeded-member-function"
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"

namespace bsl
{
    namespace details
    {
        /// @brief defines the reset handler function type
        using ut_reset_handler_type = void (*)();

        /// <!-- description -->
        ///   @brief Returns a reference to the name of the current test
        ///     case.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the name of the current test
        ///     case.
        ///
        inline cstr_type &
        ut_current_test_case_name() noexcept
        {
            static cstr_type s_ut_current_test_case_name{};
            return s_ut_current_test_case_name;
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the reset handler function
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to the reset handler function
        ///
        inline ut_reset_handler_type &
        ut_reset_handler() noexcept
        {
            static ut_reset_handler_type s_ut_reset_handler{};
            return s_ut_reset_handler;
        }

        /// <!-- description -->
        ///   @brief Prints the current source location to the console.
        ///
        /// <!-- inputs/outputs -->
        ///   @param sloc the current source location to print
        ///
        inline void
        ut_print_here(sloc_type const &sloc) noexcept
        {
            bsl::print("  --> ");
            bsl::print("%s%s%s", yellow, sloc.file_name(), reset_color);
            bsl::print(": ");
            bsl::print("%s%d%s", cyan, sloc.line(), reset_color);
            bsl::print("\n");
        }
    }

    /// @class bsl::ut_scenario
    ///
    /// <!-- description -->
    ///   @brief Defines a unit test scenario. A scenario defines a user
    ///     story, describing the "scenario" being tested. A scenario
    ///     should be paired with ut_given, ut_when and ut_then to define
    ///     the scenario in english.
    ///
    class ut_scenario final
    {
    public:
        /// <!-- description -->
        ///   @brief Constructs a scenario
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the scenario (i.e., test case)
        ///
        explicit constexpr ut_scenario(cstr_type const &name) noexcept    // --
            : m_name{name}
        {}

        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the scenario.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_scenario &
        operator=(FUNC &&func) noexcept
        {
            if (!is_constant_evaluated()) {
                details::ut_current_test_case_name() = m_name;
            }

            bsl::invoke(bsl::forward<FUNC>(func));
            if (!is_constant_evaluated()) {
                if (nullptr != details::ut_reset_handler()) {
                    details::ut_reset_handler()();
                }
            }

            if (!is_constant_evaluated()) {
                details::ut_current_test_case_name() = nullptr;
            }

            return *this;
        }

    private:
        /// @brief stores the name of the scenario
        cstr_type m_name;
    };

    /// @class bsl::ut_given
    ///
    /// <!-- description -->
    ///   @brief Defines the initial state of a unit test scenario including
    ///     the creation of any objects that might participate in the
    ///     unit test.
    ///
    class ut_given final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "given" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_given.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_given &
        operator=(FUNC &&func) noexcept
        {
            bsl::invoke(bsl::forward<FUNC>(func));
            return *this;
        }
    };

    /// @class bsl::ut_when
    ///
    /// <!-- description -->
    ///   @brief Defines the "action" of a unit test scenario
    ///
    class ut_when final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "when" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_when.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_when &
        operator=(FUNC &&func) noexcept
        {
            bsl::invoke(bsl::forward<FUNC>(func));
            return *this;
        }
    };

    /// @class bsl::ut_then
    ///
    /// <!-- description -->
    ///   @brief Defines the expected "result" of a unit test scenario.
    ///
    class ut_then final
    {
    public:
        /// <!-- description -->
        ///   @brief Executes a lambda function as the body of the
        ///     "then" portion of the scenario.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the type of lambda being executed
        ///   @param func the lambda being executed
        ///   @return Returns a reference to the ut_then.
        ///
        template<typename FUNC>
        [[maybe_unused]] constexpr ut_then &
        operator=(FUNC &&func) noexcept
        {
            bsl::invoke(bsl::forward<FUNC>(func));
            if (!is_constant_evaluated()) {
                if (nullptr != details::ut_reset_handler()) {
                    details::ut_reset_handler()();
                }
            }

            return *this;
        }
    };

    /// <!-- description -->
    ///   @brief Sets the unit test's reset handler. After each test has
    ///     executed, this register handler will be called. Note that the
    ///     reset handler is not supported for compile-time checks.
    ///
    /// <!-- inputs/outputs -->
    ///   @param hdlr the handler to register as the reset handler
    ///
    inline void
    set_ut_reset_handler(details::ut_reset_handler_type const hdlr) noexcept
    {
        details::ut_reset_handler() = hdlr;
    }

    /// <!-- description -->
    ///   @brief Outputs a message and returns bsl::exit_success
    ///
    /// <!-- inputs/outputs -->
    ///   @return returns bsl::exit_success
    ///
    constexpr bsl::exit_code
    ut_success() noexcept
    {
        if (!is_constant_evaluated()) {
            bsl::print("%s%s%s\n", green, "All tests passed", reset_color);
        }

        return bsl::exit_success;
    }

    /// <!-- description -->
    ///   @brief This is a non-constexpr function that can be used to detect
    ///     when a unit test check fails. If this function is called at
    ///     compile-time, it will not compile, resulting in a human readable
    ///     error message.
    ///
    inline void
    ut_check_failed() noexcept
    {}

    /// <!-- description -->
    ///   @brief Checks to see if "test" is true. If test is false, this
    ///     function will exit fast with a failure code.
    ///
    /// <!-- inputs/outputs -->
    ///   @param test if test is true, this function returns true. If test is
    ///     false, this function will exit fast with a failure code.
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///   @return returns test
    ///
    [[maybe_unused]] constexpr bool
    ut_check(bool const test, sloc_type const &sloc = here()) noexcept
    {
        if (!test) {
            ut_check_failed();
            bsl::print("%s%s%s ", red, "[CHECK FAILED]", reset_color);
            bsl::print("in test case \"");
            bsl::print("%s%s%s", magenta, details::ut_current_test_case_name(), reset_color);
            bsl::print("\"\n");
            details::ut_print_here(sloc);

            exit(EXIT_FAILURE);
        }

        return test;
    }
}

#endif
