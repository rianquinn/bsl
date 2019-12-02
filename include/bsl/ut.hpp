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

#ifndef BSL_UT_HPP
#define BSL_UT_HPP

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

#include "debug.hpp"

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
    namespace details::ut
    {
        struct invalid_check : bsl::checked_error
        {};
        struct ut_failed : bsl::checked_error
        {};
        struct required_failed : bsl::checked_error
        {};

        using name_type = const char *const;
        using info_type = source_location;

        inline std::uint64_t total_test_cases{};
        inline std::uint64_t total_assertions{};
        inline std::uint64_t failed_test_cases{};
        inline std::uint64_t failed_assertions{};
        inline std::uint64_t skipped_test_cases{};

        inline std::string *failures{};

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
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        assertion_failure(const name_type &name, const info_type &info) noexcept
            -> void
        {
            bsl::catch_all([&name, &info] {
                if (nullptr == failures) {
                    fmt::print(red, "FATAL ERROR: ");
                    fmt::print(" check ignored [");
                    fmt::print(cyan, "{}", info.line());
                    fmt::print("]: ");
                    fmt::print(yellow, "{}", info.file_name());

                    throw invalid_check{};
                }

                *failures += fmt::format("  | [");
                *failures += fmt::format(blue, "{}", name);

                if (nullptr != info.file_name()) {
                    *failures += fmt::format("] failed on line: ");
                    *failures += fmt::format(yellow, "{}\n", info.line());
                }
                else {
                    *failures += fmt::format("]\n");
                }
            });
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
        auto success = bsl::catch_all([] {
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

            const auto *const as = total_assertions != 1 ? "s" : "";
            const auto *const ts = total_test_cases != 1 ? "s" : "";
            const auto *const ss = skipped_test_cases != 1 ? "s" : "";

            if (0 == total_test_cases) {
                fmt::print(yellow, "{:=^80}\n", "=");
                fmt::print(yellow, "No tests ran\n");

                throw details::ut::ut_failed{};
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

                throw details::ut::ut_failed{};
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
        });

        if (success) {
            return EXIT_SUCCESS;
        }

        return EXIT_FAILURE;
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
        /// @return false if a required check fails, true otherwise.
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        template<typename F>
        auto
        execute_test(F &&func, std::string *const failures) -> bool
        {
            bool no_reason_to_exit = true;

            auto *const tmp = details::ut::failures;
            details::ut::failures = failures;

            auto caught = !bsl::catch_all([&func, &no_reason_to_exit] {
                try {
                    func();
                }
                catch (const details::ut::required_failed &e) {
                    bsl::discard(e);
                    no_reason_to_exit = false;
                }
            });

            if (caught) {
                details::ut::assertion_failure("unexpected exception", {});
            }

            details::ut::failures = tmp;
            return no_reason_to_exit;
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
            const details::ut::name_type name = "",
            const details::ut::info_type info = here()) noexcept :
            m_name{name}, m_info{info}
        {
            ++details::ut::total_test_cases;
        }

        /// Execute Test Case
        ///
        /// This is the public function used to execute a test case. Once a
        /// test case lambda is set, it is executed. It should be noted that
        /// this function will catch all exceptions to ensure the rest of the
        /// unit test is not alterred by other test cases.
        ///
        /// NOSONAR:
        /// - We call std::exit() in this function to handle required() checks.
        ///   This is fine since we are just unit testing.
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
            bsl::catch_all([&func, this] {
                std::string failures{};
                auto status = execute_test(std::forward<F>(func), &failures);

                if (!failures.empty()) {
                    fmt::print(red, "{:-^80}\n", "-");
                    fmt::print(red, "failed: ");
                    fmt::print(yellow, "{}\n", m_name);
                    fmt::print(red, "{:-^80}\n", "-");
                    fmt::print("  | --> ");
                    fmt::print(cyan, "{}", m_info.file_name());
                    fmt::print(": ");
                    fmt::print(yellow, "{}", m_info.line());
                    fmt::print("\n");
                    fmt::print("  |\n{}", failures);

                    if (!status) {
                        fmt::print(red, "  |   ^^^ \n");
                        fmt::print(
                            red, "  |    |  REQUIRED FAILED... EXITING !!! \n");
                        fmt::print(red, "  |\n");
                    }

                    fmt::print("  |\n");
                    fmt::print("\n");

                    ++details::ut::failed_test_cases;
                }

                if (!status) {
                    std::exit(EXIT_FAILURE);    //NOSONAR
                }
            });

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

            ++details::ut::skipped_test_cases;
            return *this;
        }
    };
}    // namespace bsl

/// Pipe
///
/// This function absorbs a test case by returning another
/// skip_test_case when given a regular test case.
///
/// expects: none
/// ensures: none
///
/// @param s "skip" is the only argument for this
/// @param t the test case to absorb
/// @return *this
/// @throw [checked]: none
/// @throw [unchecked]: none
///
[[maybe_unused]] constexpr auto
operator|(const bsl::skip_test_case &s, const bsl::test_case &t) noexcept
    -> bsl::skip_test_case
{
    bsl::discard(s);
    bsl::discard(t);

    return {};
}

namespace bsl
{
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
        const bool test,
        const details::ut::name_type &name = "check",
        const details::ut::info_type &info = here()) noexcept -> bool
    {
        ++details::ut::total_assertions;

        if (!test) {
            details::ut::assertion_failure(name, info);
            ++details::ut::failed_assertions;

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
        const bool test,
        const details::ut::name_type &name = "require",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check(test, name, info)) {
            throw details::ut::required_failed{};
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
        const bool test,
        const details::ut::name_type &name = "check_false",
        const details::ut::info_type &info = here()) noexcept -> bool
    {
        return check(!test, name, info);
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
        const bool test,
        const details::ut::name_type &name = "require_false",
        const details::ut::info_type &info = here()) -> bool
    {
        return require(!test, name, info);
    }

    /// Check Throws
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// NOSONAR:
    /// - This specific check needs to detect if any exception is thrown, which
    ///   can only be done if we catch all exceptions.
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
        const details::ut::name_type &name = "check_throws",
        const details::ut::info_type &info = here()) noexcept -> bool
    {
        ++details::ut::total_assertions;

        auto caught = !bsl::catch_all([&func] {
            func();
        });

        if (!caught) {
            details::ut::assertion_failure(name, info);
            ++details::ut::failed_assertions;

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
        F &&func,
        const details::ut::name_type &name = "require_throws",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check_throws(std::forward<F>(func), name, info)) {
            throw details::ut::required_failed{};
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
    /// NOSONAR:
    /// - This specific check needs to detect if a std::runtime_error is
    ///   thrown, which can only be done if we catch this type of exception
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
        const details::ut::name_type &name = "check_throws_checked",
        const details::ut::info_type &info = here()) noexcept -> bool
    {
        bool caught = false;
        ++details::ut::total_assertions;

        bsl::catch_all([&func, &caught] {
            try {
                func();
            }
            catch (const std::runtime_error &e) {    //NOSONAR
                bsl::discard(e);
                caught = true;
            }
        });

        if (!caught) {
            details::ut::assertion_failure(name, info);
            ++details::ut::failed_assertions;

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
        F &&func,
        const details::ut::name_type &name = "require_throws_checked",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check_throws_checked(std::forward<F>(func), name, info)) {
            throw details::ut::required_failed{};
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
    /// NOSONAR:
    /// - This specific check needs to detect if anything other than a
    ///   std::runtime_error is thrown, which can only be done if we catch
    ///   a std::runtime_error as well as all exceptions, both of which
    ///   SonarCloud gets mad about.
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
        const details::ut::name_type &name = "check_throws_unchecked",
        const details::ut::info_type &info = here()) noexcept -> bool
    {
        ++details::ut::total_assertions;

        auto caught = !bsl::catch_all([&func] {
            try {
                func();
            }
            catch (const std::runtime_error &e) {    //NOSONAR
                bsl::discard(e);
            }
        });

        if (!caught) {
            details::ut::assertion_failure(name, info);
            ++details::ut::failed_assertions;

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
        F &&func,
        const details::ut::name_type &name = "require_throws_unchecked",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check_throws_unchecked(std::forward<F>(func), name, info)) {
            throw details::ut::required_failed{};
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
        const details::ut::name_type &name = "check_nothrow",
        const details::ut::info_type &info = here()) noexcept -> bool
    {
        ++details::ut::total_assertions;

        auto caught = !bsl::catch_all([&func] {
            func();
        });

        if (caught) {
            details::ut::assertion_failure(name, info);
            ++details::ut::failed_assertions;

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
        F &&func,
        const details::ut::name_type &name = "require_nothrow",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check_nothrow(std::forward<F>(func), name, info)) {
            throw details::ut::required_failed{};
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
    /// NOSONAR:
    /// - To check for a death, we need to fork a process, and that process
    ///   must exit without continuing as that would cause a bunch of
    ///   unit test logic to execute without in our child process, which is
    ///   why we must call std::exit.
    ///
    /// NOLINT:
    /// - We have no choice but to use UNIX APIs here as we must fork a
    ///   process. These APIs trigger clang-tidy, which we silence. C++ really
    ///   needs process management APIs to resolve this problem.
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
        const details::ut::name_type &name = "check_death",
        const details::ut::info_type &info = here()) -> bool
    {
        constexpr std::int32_t exit_code = 191;

        fflush(stdout);
        ++details::ut::total_assertions;

        if (0 == fork()) {
            std::string().swap(*details::ut::failures);
            func();
            std::exit(exit_code);    //NOSONAR
        }
        else {
            std::int32_t exit_status;
            wait(&exit_status);

            if (WEXITSTATUS(exit_status) == exit_code) {    // NOLINT
                details::ut::assertion_failure(name, info);
                ++details::ut::failed_assertions;

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
        F &&func,
        const details::ut::name_type &name = "require_death",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check_death(std::forward<F>(func), name, info)) {
            throw details::ut::required_failed{};
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
    /// NOSONAR:
    /// - To check for a death, we need to fork a process, and that process
    ///   must exit without continuing as that would cause a bunch of
    ///   unit test logic to execute without in our child process, which is
    ///   why we must call std::exit.
    ///
    /// NOLINT:
    /// - We have no choice but to use UNIX APIs here as we must fork a
    ///   process. These APIs trigger clang-tidy, which we silence. C++ really
    ///   needs process management APIs to resolve this problem.
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
        const details::ut::name_type &name = "check_nodeath",
        const details::ut::info_type &info = here()) -> bool
    {
        constexpr std::int32_t exit_code = 191;

        fflush(stdout);
        ++details::ut::total_assertions;

        if (0 == fork()) {
            std::string().swap(*details::ut::failures);
            func();
            std::exit(exit_code);    //NOSONAR
        }
        else {
            std::int32_t exit_status;
            wait(&exit_status);

            if (WEXITSTATUS(exit_status) != exit_code) {    // NOLINT
                details::ut::assertion_failure(name, info);
                ++details::ut::failed_assertions;

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
        F &&func,
        const details::ut::name_type &name = "require_nodeath",
        const details::ut::info_type &info = here()) -> bool
    {
        if (!check_nodeath(std::forward<F>(func), name, info)) {
            throw details::ut::required_failed{};
        }

        return true;
    }

#endif

}    // namespace bsl

#endif
