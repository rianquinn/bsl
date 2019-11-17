//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BSL_UT_H
#define BSL_UT_H

// -----------------------------------------------------------------------------
// Features
// -----------------------------------------------------------------------------
//
// - This is a macro-free unit test library that leverages source_location
//   to get file/line information. This not only dramatically improves the
//   compile times, it also provides full support for C++ without any weird
//   hacks. This means things like {} initializers work fine.
//
// - Header-Only. We do depend on some of our own headers, as well as the
//   {fmt} library, but at least it is header-only. Maybe someday we will
//   remove the need for the rest of this.
//
// - Easy to use. We support most of the same features as more complete
//   unit test libraries like Catch2 and Doctest. We worked hard to emulate
//   the Catch2 interfaces (at least the sane ones), including some of its
//   output (with some of our own improvements).
//
// - Well tested. All of the same tests that we apply to the BSL, we apply to
//   the unit test library, including ensuring that we have 100% code coverage
//   on the library.
//
// - Super fast compilation times. Compared to macro based libraries like
//   Catch2 and Doctest, this library compiles and runs really fast.
//
// - Death tests. We provide support for death tests so that you can test
//   for when std::terminate and friends execute. This is important as
//   the C++ language is moving more towards using std::terminate() in place
//   of throwing logic errors. If you are working towards AUTOSAR compliance,
//   this likely will not be a feature you need as those functions are not
//   allowed.
//
// - Behavior Driven Development support with given, when and then. This is
//   possible because we fully support the ability to nest test cases,
//   similar to a SECTION in Catch2. If copy/mutable lambdas are used,
//   each test case becomes independent.

// -----------------------------------------------------------------------------
// Notes
// -----------------------------------------------------------------------------
//
// - We do not attempt to be AUTOSAR compliant with any of our unit tests as
//   this would needlessly limit the use of C++ to make the tests easier to
//   read and maintain. With that said, we do try to stick to the spec as
//   much as we can and where it makes sense.
//
// - We do not support any of the _AS, _WITH and _THAT exception checks that
//   Catch2 provides as these overspecify your unit tests. With that said, we
//   do provide versions for checking AUTOSAR checked vs. unchecked exception
//   types as this is important to ensure that what we document in each
//   function holds true.
//
// - We do not support logging. This is one feature that we do not like about
//   most unit test libraries as CMake already hides the output of a test.
//   When we run the unit test, we want to see the output, and therefore,
//   there is no need for logging. Just use std::cout.
//
// - We do not support parameterized tests. If you need to loop through tests,
//   loop through them yourself. We don't want to overcomplicate this
//   library. This includes most of the generator logic in Catch2. If you
//   need generators that bad, use C++20 Coroutines.
//
// - We do not support test suites. Once again, if you really need a test
//   suite, just define your own added functions. Adding in test suites
//   would just add another header and more code to this library, making it
//   more complicated for a feature that is simple to add yourself.
//

#include "discard.hpp"
#include "finally.hpp"
#include "source_location.hpp"

#include <string>

#include <fmt/core.h>
#include <fmt/color.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

// -----------------------------------------------------------------------------
// Global Resources
// -----------------------------------------------------------------------------

namespace bsl
{
    class test_case;

    namespace details::ut
    {
        using name_type = const char *;       ///< Used to store names/labels
        using info_type = source_location;    ///< Used to store location info

        inline std::uint64_t total_test_cases{};      ///< Total # of tests
        inline std::uint64_t total_assertions{};      ///< Total # of assertions
        inline std::uint64_t failed_test_cases{};     ///< Failed tests
        inline std::uint64_t failed_assertions{};     ///< Failed assertions
        inline std::uint64_t skipped_test_cases{};    ///< Total # of skipped

        constexpr auto red = fmt::fg(fmt::terminal_color::bright_red);
        constexpr auto green = fmt::fg(fmt::terminal_color::bright_green);
        constexpr auto yellow = fmt::fg(fmt::terminal_color::bright_yellow);
        constexpr auto magenta = fmt::fg(fmt::terminal_color::bright_magenta);
        constexpr auto cyan = fmt::fg(fmt::terminal_color::bright_cyan);

        inline std::string *failures{};    ///< Stores each assertion's failures

        /// Assertion Failure
        ///
        /// This function is used to log an assertion failure. Each test case
        /// has its own assertion log, and will check the log to see if
        /// anything was added to determine if the test case passed or not.
        /// To handle the fact that test cases can be nested, each time a
        /// test case is executed, it updates the global "failures" string
        /// with a pointer to the test case's log. This allows the test cases
        /// to handle nested test cases safely.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param name the name of the assertion that failed
        /// @param info the source location information for the assertion
        /// @param what (optional), the what() string is exceptions were used.
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        inline auto
        assertion_failure(
            const name_type name, const info_type &info, const name_type what)
            -> void
        {
            if (nullptr == failures) {
                throw std::domain_error("check/require outside of test case\n");
            }

            *failures += fmt::format("  | [");
            *failures += fmt::format(magenta, "{}", name);

            if (nullptr != info.file_name()) {
                *failures += fmt::format("] failed on line: ");
                *failures += fmt::format(yellow, "{}\n", info.line());
            }
            else {
                *failures += fmt::format("]\n");
            }

            if (nullptr != what) {
                *failures += fmt::format("  |   - ");
                *failures += fmt::format(cyan, "what");
                *failures += fmt::format(": {}\n", what);
            }
        }
    }    // namespace details::ut
}    // namespace bsl

// -----------------------------------------------------------------------------
// Test Cases
// -----------------------------------------------------------------------------

namespace bsl
{
    /// Check Results
    ///
    /// This function is executed at the end of all of the unit tests to
    /// check the results of the unit test itself and report success or
    /// failure.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @return EXIT_SUCCESS when the unit test passes, EXIT_FAILURE otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[nodiscard]] inline auto
    check_results() noexcept -> std::int32_t
    {
        using details::ut::green;
        using details::ut::yellow;
        using details::ut::red;

        const auto total_test_cases = details::ut::total_test_cases;
        const auto total_assertions = details::ut::total_assertions;
        const auto failed_test_cases = details::ut::failed_test_cases;
        const auto failed_assertions = details::ut::failed_assertions;
        const auto skipped_test_cases = details::ut::skipped_test_cases;

        details::ut::total_test_cases = {};
        details::ut::total_assertions = {};
        details::ut::failed_test_cases = {};
        details::ut::failed_assertions = {};
        details::ut::skipped_test_cases = {};

        const char *as = total_assertions != 1 ? "s" : "";
        const char *ts = total_test_cases != 1 ? "s" : "";
        const char *ss = skipped_test_cases != 1 ? "s" : "";

        try {
            if (0 == total_test_cases) {
                fmt::print(yellow, "{:=^80}\n", "=");
                fmt::print(yellow, "No tests ran\n");

                return EXIT_FAILURE;
            }

            if ((total_test_cases > 0) && (failed_test_cases > 0)) {
                fmt::print(red, "{:=^80}\n", "=");
                fmt::print("test cases: {:>3}", total_test_cases);
                fmt::print(" | ");
                fmt::print(red, "{:>3} ", failed_test_cases);
                fmt::print(red, "failed");

                if (skipped_test_cases > 0) {
                    fmt::print(" | ");
                    fmt::print(yellow, "{:>3} ", skipped_test_cases);
                    fmt::print(yellow, "skipped");
                }

                fmt::print("\n");
                fmt::print("assertions: {:>3}", total_assertions);
                fmt::print(" | ");
                fmt::print(red, "{:>3} ", failed_assertions);
                fmt::print(red, "failed");
                fmt::print("\n");

                return EXIT_FAILURE;
            }

            fmt::print(green, "{:=^80}\n", "=");
            fmt::print(green, "All tests passed ");
            fmt::print("(");
            fmt::print("{} assertion{}", total_assertions, as);
            fmt::print(" in ");
            fmt::print("{} test case{}", total_test_cases, ts);

            if (skipped_test_cases > 0) {
                fmt::print(yellow, " [");
                fmt::print(yellow, "{} case{}", skipped_test_cases, ss);
                fmt::print(yellow, " skipped]");
            }

            fmt::print(")\n");
        }
        catch (...) {    //NOSONAR
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }

    /// Test Case
    ///
    /// This is the main object that does all of the work in this library.
    /// Each assertion must be wrapped in a test case. The test case object
    /// ensures that assertions have a log and that this log is checked as
    /// needed. It also gathers source location information and unique name
    /// information to help identify the test case itself.
    ///
    /// Test cases can be nested, so this class must ensure that the logs
    /// are handled properly and failed assertions are properly attributed
    /// to the correct test case.
    ///
    class test_case
    {
        /// Execute Test
        ///
        /// Executes a test function. This function ensures that the test
        /// function has a failures log, and catches all possible exceptions
        /// so that they can be handled properly. If a required failure
        /// occurs, this function will return EXIT_FAILURE so that the unit
        /// test can be halted.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param func the test function to execute
        /// @return EXIT_FAILURE if a required check fails, EXIT_SUCCESS
        ///     otherwise.
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        template<typename F>
        auto
        execute_test(F &&func, std::string *failures) -> std::int32_t
        {
            auto tmp = details::ut::failures;
            details::ut::failures = failures;

            auto restore_failures = bsl::finally([&] {
                details::ut::failures = tmp;
            });

            try {
                func();
            }
            catch (const std::exception &e) {
                if (std::string("x|required failed|x") == e.what()) {
                    return EXIT_FAILURE;
                }

                details::ut::assertion_failure(
                    "unexpected exception", {}, e.what());
            }
            catch (...) {
                details::ut::assertion_failure(
                    "unexpected exception", {}, "unknown");
            }

            return EXIT_SUCCESS;
        }

    public:
        /// Test Case Constructor
        ///
        /// Creates a test case with a given name and location.
        ///
        /// expects:
        /// ensures:
        ///
        /// @param name the name of the test case
        /// @param info information about the test case
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr test_case(
            details::ut::name_type name = "",
            details::ut::info_type info = source_location::current()) noexcept :
            m_name{name}, m_info{info}
        {
            details::ut::total_test_cases++;
        }

        /// Execute Test Case
        ///
        /// This is the public function used to execute a test case. Once a
        /// test case lambda is set, it is executed. It should be noted that
        /// this function will catch all exceptions to ensure the rest of the
        /// unit test is not alterred by other test cases.
        ///
        /// expects:
        /// ensures:
        ///
        /// @param func the test to run
        /// @return *this
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        template<typename F>
        [[maybe_unused]] auto
        operator=(F &&func) noexcept -> test_case &
        {
            std::int32_t exit_code = EXIT_SUCCESS;

            try {
                std::string failures{};
                exit_code = execute_test(std::forward<F>(func), &failures);

                if (!failures.empty()) {
                    fmt::print(details::ut::red, "{:-^80}\n", "-");
                    fmt::print(details::ut::red, "failed: ");
                    fmt::print(details::ut::yellow, "{}\n", m_name);
                    fmt::print(details::ut::red, "{:-^80}\n", "-");
                    fmt::print("  | ");
                    fmt::print(details::ut::cyan, "{} ", m_info.file_name());
                    fmt::print("[");
                    fmt::print(details::ut::yellow, "{}", m_info.line());
                    fmt::print("]\n");
                    fmt::print("  |\n{}", failures);

                    if (exit_code != EXIT_SUCCESS) {
                        fmt::print(details::ut::red, "  |    ^^^ \n");
                        fmt::print(
                            details::ut::red,
                            "  |     |  REQUIRED FAILED... EXITING !!! \n");
                        fmt::print(details::ut::red, "  |\n");
                    }

                    fmt::print("  |\n");
                    fmt::print("\n");

                    details::ut::failed_test_cases++;
                }

                if (exit_code != EXIT_SUCCESS) {
                    throw std::runtime_error("required failed");
                }
            }
            catch (...) {
                std::exit(exit_code);
            }

            return *this;
        }

    private:
        details::ut::name_type m_name{};
        details::ut::info_type m_info{};
    };

    /// Skip Test Case
    ///
    /// This class can be used to skip a test case. This works by taking
    /// in a test case using a | and returning another skip_test_case
    /// object. The resulting = operator that should have been given to the
    /// test case is now given to a skip_test_case which does nothing.
    ///
    class skip_test_case
    {
    public:
        /// Pipe
        ///
        /// This function absorbs a test case by returning another
        /// skip_test_case when given a regular test case.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param test the test case to absorb
        /// @return *this
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[maybe_unused]] constexpr auto
        operator|(const test_case &test) noexcept -> skip_test_case &
        {
            bsl::discard(test);
            return *this;
        }

        /// Assignment Operator
        ///
        /// If a test case has been absorbed, it is likely that the test
        /// case will have a lambda assigned to it that this class will have
        /// to handle, which it does by ignoring it, which ultimately is what
        /// causes the test case to be skipped.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param func the lambda function to skip
        /// @return *this
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename F>
        [[maybe_unused]] constexpr auto
        operator=(F &&func) noexcept -> skip_test_case &
        {
            bsl::discard(func);

            details::ut::skipped_test_cases++;
            return *this;
        }
    };

    /// Skip
    ///
    /// This is the actual object that is used to skip a test case. Use this
    /// with the | operator to skip a test.
    ///
    inline skip_test_case skip;

    /// Given
    ///
    /// This is a rename of the test_case() for use with BDD. The test_case()
    /// class already provides the support that is needed to make this work,
    /// but the rename provides better self-documentation.
    ///
    using given = test_case;

    /// When
    ///
    /// This is a rename of the test_case() for use with BDD. The test_case()
    /// class already provides the support that is needed to make this work,
    /// but the rename provides better self-documentation.
    ///
    using when = test_case;

    /// Then
    ///
    /// This is a rename of the test_case() for use with BDD. The test_case()
    /// class already provides the support that is needed to make this work,
    /// but the rename provides better self-documentation.
    ///
    using then = test_case;

    /// Section
    ///
    /// This is a rename of the test_case() to mimic a SECTION from Catch2. The
    /// test_case() class already provides the support that is needed to make
    /// this work, but the rename provides better self-documentation.
    ///
    using section = test_case;

    /// Scenario
    ///
    /// This is a rename of the test_case() to mimic a SCENARIO from Catch2. The
    /// test_case() class already provides the support that is needed to make
    /// this work, but the rename provides better self-documentation.
    ///
    using scenario = test_case;

}    // namespace bsl

// -----------------------------------------------------------------------------
// Assertions
// -----------------------------------------------------------------------------

namespace bsl
{
    /// Check
    ///
    /// Checks whether a condition is true. If the assertion is false,
    /// the failure is recorded and eventually reported to the user.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param test the boolean test that is checked.
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[maybe_unused]] inline auto
    check(
        bool test,
        details::ut::name_type name = "check",
        details::ut::info_type info = source_location::current()) -> bool
    {
        details::ut::total_assertions++;

        if (!test) {
            details::ut::assertion_failure(name, info, {});
            details::ut::failed_assertions++;

            return false;
        }

        return true;
    }

    /// Require
    ///
    /// Checks whether a condition is true. If the assertion is false,
    /// the failure is recorded and eventually reported to the user.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param test the boolean test that is checked.
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[maybe_unused]] inline auto
    require(
        bool test,
        details::ut::name_type name = "require",
        details::ut::info_type info = source_location::current()) -> bool
    {
        if (!check(test, name, info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

    /// Check (False)
    ///
    /// Checks whether a condition is false. If the assertion is true,
    /// the failure is recorded and eventually reported to the user.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param test the boolean test that is checked.
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[maybe_unused]] inline auto
    check_false(
        bool test, details::ut::info_type info = source_location::current())
        -> bool
    {
        return check(!test, "check_false", info);
    }

    /// Require (False)
    ///
    /// Checks whether a condition is false. If the assertion is true,
    /// the failure is recorded and eventually reported to the user.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param test the boolean test that is checked.
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[maybe_unused]] inline auto
    require_false(
        bool test, details::ut::info_type info = source_location::current())
        -> bool
    {
        return require(!test, "require_false", info);
    }

    /// Check Throws
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    check_throws(
        F &&func,
        details::ut::name_type name = "check_throws",
        details::ut::info_type info = source_location::current()) -> bool
    {
        bool caught = false;
        details::ut::total_assertions++;

        try {
            func();
        }
        catch (...) {
            caught = true;
        }

        if (!caught) {
            details::ut::assertion_failure(name, info, {});
            details::ut::failed_assertions++;

            return false;
        }

        return true;
    }

    /// Require Throws
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    require_throws(
        F &&func, details::ut::info_type info = source_location::current())
        -> bool
    {
        if (!check_throws(std::forward<F>(func), "require_throws", info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

    /// Check Throws (std::runtime_error)
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user. This specific version checks that the exception thrown
    /// inherits from std::runtime_error.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    check_throws_checked(
        F &&func,
        details::ut::name_type name = "check_throws_checked",
        details::ut::info_type info = source_location::current()) -> bool
    {
        bool caught = false;
        details::ut::total_assertions++;

        try {
            func();
        }
        catch (const std::runtime_error &e) {
            bsl::discard(e);
            caught = true;
        }
        catch (...) {
            caught = false;
        }

        if (!caught) {
            details::ut::assertion_failure(name, info, {});
            details::ut::failed_assertions++;

            return false;
        }

        return true;
    }

    /// Require Throws (std::runtime_error)
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user. This specific version checks that the exception thrown
    /// inherits from std::runtime_error.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    require_throws_checked(
        F &&func, details::ut::info_type info = source_location::current())
        -> bool
    {
        if (!check_throws_checked(
                std::forward<F>(func), "require_throws_checked", info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

    /// Check Throws (!std::runtime_error)
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user. This specific version checks that the exception thrown
    /// _does not_ inherit from std::runtime_error.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    check_throws_unchecked(
        F &&func,
        details::ut::name_type name = "check_throws_unchecked",
        details::ut::info_type info = source_location::current()) -> bool
    {
        bool caught = false;
        details::ut::total_assertions++;

        try {
            func();
        }
        catch (const std::runtime_error &e) {
            bsl::discard(e);
            caught = false;
        }
        catch (...) {
            caught = true;
        }

        if (!caught) {
            details::ut::assertion_failure(name, info, {});
            details::ut::failed_assertions++;

            return false;
        }

        return true;
    }

    /// Require Throws (!std::runtime_error)
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user. This specific version checks that the exception thrown
    /// _does not_ inherit from std::runtime_error.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    require_throws_unchecked(
        F &&func, details::ut::info_type info = source_location::current())
        -> bool
    {
        if (!check_throws_unchecked(
                std::forward<F>(func), "require_throws_unchecked", info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

    /// Check Does Not Throw
    ///
    /// Checks whether a function throws an exception. If the function
    /// throws an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    check_nothrow(
        F &&func,
        details::ut::name_type name = "check_nothrow",
        details::ut::info_type info = source_location::current()) -> bool
    {
        details::ut::total_assertions++;

        try {
            func();
        }
        catch (const std::exception &e) {
            details::ut::assertion_failure(name, info, e.what());
            details::ut::failed_assertions++;

            return false;
        }
        catch (...) {
            details::ut::assertion_failure(name, info, "unknown");
            details::ut::failed_assertions++;

            return false;
        }

        return true;
    }

    /// Require Does Not Throw
    ///
    /// Checks whether a function throws an exception. If the function
    /// throws an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if an exception throws
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    require_nothrow(
        F &&func, details::ut::info_type info = source_location::current())
        -> bool
    {
        if (!check_nothrow(std::forward<F>(func), "require_nothrow", info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

#ifdef __linux__

    /// Check Death
    ///
    /// Checks whether a function calls std::terminate and friends (anything
    /// that would result in the application exiting). If the application
    /// does not exit, the check fails and the results is eventually given
    /// to the user.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if it exits
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    check_death(
        F &&func,
        details::ut::name_type name = "check_death",
        details::ut::info_type info = source_location::current()) -> bool
    {
        constexpr std::int32_t exit_code = 191;

        fflush(stdout);
        details::ut::total_assertions++;

        if (fork() == 0) {
            std::string().swap(*details::ut::failures);
            func();
            std::exit(exit_code);
        }
        else {
            std::int32_t exit_status;
            wait(&exit_status);

            if (WEXITSTATUS(exit_status) == exit_code) {    // NOLINT
                details::ut::assertion_failure(name, info, {});
                details::ut::failed_assertions++;

                return false;
            }

            return true;
        }
    }

    /// Require Death
    ///
    /// Checks whether a function calls std::terminate and friends (anything
    /// that would result in the application exiting). If the application
    /// does not exit, the check fails and the results is eventually given
    /// to the user.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if it exits
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    require_death(
        F &&func, details::ut::info_type info = source_location::current())
        -> bool
    {
        if (!check_death(std::forward<F>(func), "require_death", info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

    /// Check Death
    ///
    /// Checks whether a function calls std::terminate and friends (anything
    /// that would result in the application exiting). If the application
    /// exits, the check fails and the results is eventually given
    /// to the user.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if it exits
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    check_nodeath(
        F &&func,
        details::ut::name_type name = "check_nodeath",
        details::ut::info_type info = source_location::current()) -> bool
    {
        constexpr std::int32_t exit_code = 191;

        fflush(stdout);
        details::ut::total_assertions++;

        if (fork() == 0) {
            std::string().swap(*details::ut::failures);
            func();
            std::exit(exit_code);
        }
        else {
            std::int32_t exit_status;
            wait(&exit_status);

            if (WEXITSTATUS(exit_status) != exit_code) {    // NOLINT
                details::ut::assertion_failure(name, info, {});
                details::ut::failed_assertions++;

                return false;
            }

            return true;
        }
    }

    /// Require Death
    ///
    /// Checks whether a function calls std::terminate and friends (anything
    /// that would result in the application exiting). If the application
    /// exits, the check fails and the results is eventually given
    /// to the user.
    ///
    /// Unlike the check version, if the test fails, this unit test will
    /// exit immediately.
    ///
    /// Notes:
    /// - The default arguments should not be used manually. These are
    ///   automatically set as needed by the library.
    /// - The assertion can only be executed from the context of a test_case.
    ///   Attempting to execute an assertion outside of a test_case is
    ///   undefined.
    ///
    /// expects: executed from a test_case()
    /// ensures: none
    ///
    /// @param func the function to run to see if it exits
    /// @return true if the check passed, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename F>
    [[maybe_unused]] auto
    require_nodeath(
        F &&func, details::ut::info_type info = source_location::current())
        -> bool
    {
        if (!check_nodeath(std::forward<F>(func), "require_nodeath", info)) {
            throw std::runtime_error("x|required failed|x");
        }

        return true;
    }

#endif

}    // namespace bsl

#endif
