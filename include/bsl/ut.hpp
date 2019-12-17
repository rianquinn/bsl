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
//   much as we can and where it makes sense. A couple notable exceptions are:
//   - We are ok using the []{} syntax for lambas, and nested lambdas are also
//     ok.
//   - The implementation of this UT library uses make_noexcept in situations
//     where exceptions could fire, which would result in std::terminate()
//     being caught. In such cases, the UT would fail, which is the desired
//     behavior. Since this code is not used in production, that is fine.
//
// - We do not support the _WITH and _THAT exception checks that Catch2
//   provides as these overspecify your unit tests.
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
//   suite, just define your own added functions.
//

#include "int.hpp"
#include "debug.hpp"

#include <deque>

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
        using name_type = cstr_t;
        using what_type = std::string;
        using sloc_type = source_location;

        inline ::bsl::uintmax_t total_test_cases{};
        inline ::bsl::uintmax_t total_assertions{};
        inline ::bsl::uintmax_t failed_test_cases{};
        inline ::bsl::uintmax_t failed_assertions{};
        inline ::bsl::uintmax_t skipped_test_cases{};

        /// Test Case Status
        ///
        /// Each time a test case is created with =, a test case status is
        /// created which is where all of the results of each check is stored.
        /// We do not store this information in the test case itself because
        /// if a required check failed, we would end up with a memory leak.
        ///
        class test_case_status
        {
        public:
            /// Test Case Status Constructor
            ///
            /// Creates a test case status that is used to track the status
            /// of a test case.
            ///
            /// expects: none
            /// ensures: none
            ///
            /// @param name the name of the test case
            /// @param sloc the location of the test case
            /// @throw [checked]: none
            /// @throw [unchecked]: none
            ///
            test_case_status(
                const details::ut::name_type &name,
                const details::ut::sloc_type &sloc) noexcept :
                m_name{name}, m_sloc{sloc}
            {}

            /// Append
            ///
            /// Adds failure text to the test case status. Once this occurs,
            /// the test case has officially failed, so we add a header when
            /// this occurs as well (on teh first append).
            ///
            /// AUTOSAR:
            /// - A15-3-4: the catch all is used for isolation.
            ///
            /// expects: none
            /// ensures: none
            ///
            /// @param str the failure string to add to the test case status.
            /// @throw [checked]: none
            /// @throw [unchecked]: none
            ///
            inline auto
            append(const std::string &str) noexcept -> void
            {
                using fmt::format;

                try {
                    if (m_failures.empty()) {
                        m_failures += format(red, "{:-^80}\n", "-");
                        m_failures += format(red, "failed: ");
                        m_failures += format(yellow, "{}\n", m_name);
                        m_failures += format(red, "{:-^80}\n", "-");
                        m_failures += format("  | --> ");
                        m_failures += format(cyan, "{}", m_sloc.file_name());
                        m_failures += format(": ");
                        m_failures += format(yellow, "{}", m_sloc.line());
                        m_failures += format("\n");
                        m_failures += format("  |\n");
                    }

                    m_failures += str;
                }
                catch(...) {
                    ::bsl::unexpected_exception(::bsl::here());
                    ::bsl::fail_fast();
                }
            }

            /// Passed
            ///
            /// Returns true if the test case passed, false otherwise
            ///
            /// expects: none
            /// ensures: none
            ///
            /// @return returns true if the test case passed, false otherwise
            /// @throw [checked]: none
            /// @throw [unchecked]: none
            ///
            [[nodiscard]] inline auto
            passed() const noexcept -> bool
            {
                return m_failures.empty();
            }

            /// Failures
            ///
            /// Returns all of the failures that were appended to the test
            /// case as well as a header.
            ///
            /// expects: none
            /// ensures: none
            ///
            /// @return the failures that were appended to the test case
            /// @throw [checked]: none
            /// @throw [unchecked]: none
            ///
            [[nodiscard]] inline auto
            failures() noexcept -> std::string &
            {
                return m_failures;
            }

        private:
            std::string m_failures{};
            details::ut::name_type m_name{};
            details::ut::sloc_type m_sloc{};
        };

        /// Test Cases
        ///
        /// This contains all of the test case statuses that are created. Each
        /// time the user creates a test case, a test case status is pushed
        /// to this stack, and all failures are appended. Once the test case
        /// is done, the test case status is popped from the stack, and
        /// checked to see if any failures were registered. If they were, they
        /// are outputted to the console. The reason we use a stack is the
        /// test cases can be nested.
        ///
        /// AUTOSAR:
        /// - A15-3-4: the catch all is used for isolation.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return a reference to the test cases stack
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        /// Test Case Stack
        ///
        [[nodiscard]] inline auto
        test_cases() noexcept -> std::deque<test_case_status> &
        {
            static std::deque<test_case_status> s_test_cases;
            return s_test_cases;
        }

        /// Push Test Case
        ///
        /// This function is what actually creates a test case. It does this
        /// by pushing a test case status to the test case stack. Each check
        /// in the test case appends text to the test case status when a check
        /// fails.
        ///
        /// AUTOSAR:
        /// - A15-3-4: the catch all is used for isolation.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param tcs the test case status to add to the stack
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        push_test_case(const test_case_status &tcs) noexcept -> void
        {
            try {
                test_cases().push_back(tcs);
                ++details::ut::total_test_cases;
            }
            catch (...) {
                ::bsl::unexpected_exception(::bsl::here());
                ::bsl::fail_fast();
            }
        }

        /// Pop Test Case
        ///
        /// Pops a test case status from the test case stack. If the test
        /// case didn't pass, we output the failures to the console.
        ///
        /// AUTOSAR:
        /// - A15-3-4: the catch all is used for isolation.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        pop_test_case() noexcept -> void
        {
            if (test_cases().empty()) {
                ::bsl::error("invalid call to pop_test_case\n");
                return;
            }

            try {
                if (!test_cases().back().passed()) {
                    ::bsl::print(test_cases().back().failures());
                    ::bsl::print("  |\n");
                    ::bsl::print("\n");

                    ++details::ut::failed_test_cases;
                }

                details::ut::test_cases().pop_back();
            }
            catch (...) {
                ::bsl::unexpected_exception(::bsl::here());
                ::bsl::fail_fast();
            }
        }

        /// Required Failed
        ///
        /// This function is executed whenever a required() check is run and
        /// fails. When this happens, we need to output all of the logged
        /// failures before cleaning up and exiting as we cannot execute any
        /// additional checks or test cases safely.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[noreturn]] inline auto
        required_failed() noexcept -> void
        {
            const cstr_t msg = "REQUIRED FAILED... EXITING !!!";

            if (test_cases().empty()) {
                ::bsl::alert("orphaned require() failed!!!\n");
            }
            else {
                ::bsl::print(test_cases().back().failures());
                ::bsl::print(red, "  |   ^^^ \n");
                ::bsl::print(red, "  |    | {}  \n", msg);
                ::bsl::print(red, "  |\n");
                ::bsl::print("  |\n");
                ::bsl::print("\n");
            }

            ::bsl::fail_fast();
        }

        /// Log Assertion Failure
        ///
        /// This function is used to log an assertion failure.
        ///
        /// AUTOSAR:
        /// - A15-3-4: the catch all is used for isolation.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param name the name of the assertion that failed
        /// @param sloc the source location information for the assertion
        /// @param what (optional) what() from an exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        log_assertion_failure(
            const name_type &name,
            const sloc_type &sloc,
            const what_type &what) noexcept -> void
        {
            if (test_cases().empty()) {
                ::bsl::alert("check ignored\n{}\n", sloc);
                return;
            }

            try {
                auto &tcs = test_cases().back();

                tcs.append(fmt::format("  | ["));
                tcs.append(fmt::format(blue, "{}", name));

                if (nullptr != sloc.file_name()) {
                    tcs.append(fmt::format("] failed on line: "));
                    tcs.append(fmt::format(yellow, "{}\n", sloc.line()));

                    ++details::ut::failed_assertions;
                }
                else {
                    tcs.append(fmt::format("]\n"));
                }

                if (!what.empty()) {
                    tcs.append(fmt::format("  | - what: "));
                    tcs.append(fmt::format(cyan, "{}\n", what));
                }
            }
            catch (...) {
                ::bsl::unexpected_exception(::bsl::here());
                ::bsl::fail_fast();
            }
        }

        /// Test Assertion
        ///
        /// This function is used to test to see if an assertion has passed.
        /// If it is has not, it will log the assertion.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param test the boolean test that is checked.
        /// @param name the name of the test that is checked.
        /// @param sloc the location of the test that is checked.
        /// @param what (optional) the what() information for an exception
        /// @return none
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        test_assertion(
            const bool test,
            const details::ut::name_type &name,
            const details::ut::sloc_type &sloc,
            const details::ut::what_type &what) noexcept -> bool
        {
            try {
                ++details::ut::total_assertions;

                if (!test) {
                    details::ut::log_assertion_failure(name, sloc, what);
                    return false;
                }

                return true;
            }
            catch (...) {
                ::bsl::unexpected_exception(::bsl::here());
                ::bsl::fail_fast();
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
    check_results() noexcept -> bsl::int32_t
    {
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

        const cstr_t as = total_assertions != 1 ? "s" : "";
        const cstr_t ts = total_test_cases != 1 ? "s" : "";
        const cstr_t ss = skipped_test_cases != 1 ? "s" : "";

        if (0 == total_test_cases) {
            bsl::print(yellow, "{:=^80}\n", "=");
            bsl::print(yellow, "No tests ran\n");

            return bsl::exit_failure;
        }

        if ((total_test_cases > 0) && (failed_test_cases > 0)) {
            bsl::print(red, "{:=^80}\n", "=");
            bsl::print("test cases: {:>3}", total_test_cases.to_string());
            bsl::print(" | ");
            bsl::print(red, "{:>3} ", failed_test_cases.to_string());
            bsl::print(red, "failed");

            if (skipped_test_cases > 0) {
                bsl::print(" | ");
                bsl::print(yellow, "{:>3} ", skipped_test_cases.to_string());
                bsl::print(yellow, "skipped");
            }

            bsl::print("\n");
            bsl::print("assertions: {:>3}", total_assertions.to_string());
            bsl::print(" | ");
            bsl::print(red, "{:>3} ", failed_assertions.to_string());
            bsl::print(red, "failed");
            bsl::print("\n");

            return bsl::exit_failure;
        }

        bsl::print(green, "{:=^80}\n", "=");
        bsl::print(green, "All tests passed ");
        bsl::print("(");
        bsl::print("{} assertion{}", total_assertions, as);
        bsl::print(" in ");
        bsl::print("{} test case{}", total_test_cases, ts);

        if (skipped_test_cases > 0) {
            bsl::print(yellow, " [");
            bsl::print(yellow, "{} case{}", skipped_test_cases, ss);
            bsl::print(yellow, " skipped]");
        }

        bsl::print(")\n");
        return bsl::exit_success;
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
    /// to the correct test case. To do this, we use a test case status stack
    /// that is pushed/popped as each nested test case is created.
    ///
    class test_case
    {
    public:
        /// Test Case Constructor
        ///
        /// Creates a test case with a given name and location.
        ///
        /// expects:
        /// ensures:
        ///
        /// @param name the name of the test case
        /// @param sloc the location of the test case
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr test_case(
            const details::ut::name_type &name = "",
            const details::ut::sloc_type &sloc = here()) noexcept :
            m_name{name}, m_sloc{sloc}
        {}

        /// Execute Test Case
        ///
        /// This is the public function used to execute a test case. Once a
        /// test case lambda is set, it is executed. It should be noted that
        /// this function will catch all exceptions to ensure the rest of the
        /// unit test is not alterred by other test cases.
        ///
        /// AUTOSAR:
        /// - A15-3-4: the catch all and catch std::exception are used for
        ///   isolation.
        ///
        /// expects:
        /// ensures:
        ///
        /// @param func the test to run
        /// @return *this
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        template<
            typename FUNC,
            std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr>
        [[maybe_unused]] auto
        operator=(FUNC &&func) noexcept -> test_case &
        {
            try {
                details::ut::push_test_case({m_name, m_sloc});
                std::forward<FUNC>(func)();
            }
            catch(const std::exception &e) {
                details::ut::log_assertion_failure(
                    "unexpected exception", {}, e.what());
            }
            catch(...) {
                details::ut::log_assertion_failure(
                    "unexpected exception", {}, "...");
            }

            details::ut::pop_test_case();
            return *this;
        }

    private:
        details::ut::name_type m_name{};
        details::ut::sloc_type m_sloc{};
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
        /// AUTOSAR:
        /// - A15-3-4: the catch all is used for isolation.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param func the lambda function to skip
        /// @return *this
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<
            typename FUNC,
            std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr>
        [[maybe_unused]] auto
        operator=(FUNC &&func) noexcept -> skip_test_case &
        {
            bsl::discard(func);

            try {
                ++details::ut::total_test_cases;
                ++details::ut::skipped_test_cases;
            }
            catch (...) {
                ::bsl::unexpected_exception(::bsl::here());
                ::bsl::fail_fast();
            }

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
    /// @throw [unchecked]: none
    ///
    [[maybe_unused]] inline auto
    check(
        const bool test,
        const details::ut::name_type &name = "check",
        const details::ut::sloc_type &sloc = here()) noexcept -> bool
    {
        return details::ut::test_assertion(test, name, sloc, {});
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
    /// @throw [unchecked]: none
    ///
    [[maybe_unused]] inline auto
    require(
        const bool test,
        const details::ut::name_type &name = "require",
        const details::ut::sloc_type &sloc = here()) noexcept -> bool
    {
        if (!check(test, name, sloc)) {
            details::ut::required_failed();
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
    /// @throw [unchecked]: none
    ///
    [[maybe_unused]] inline auto
    check_false(
        const bool test,
        const details::ut::name_type &name = "check_false",
        const details::ut::sloc_type &sloc = here()) noexcept -> bool
    {
        return check(!test, name, sloc);
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
    /// @throw [unchecked]: none
    ///
    [[maybe_unused]] inline auto
    require_false(
        const bool test,
        const details::ut::name_type &name = "require_false",
        const details::ut::sloc_type &sloc = here()) noexcept -> bool
    {
        return require(!test, name, sloc);
    }

    /// Check Throws
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// AUTOSAR:
    /// - A15-3-4: the catch all and catch std::exception are used for
    ///   isolation.
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    check_throws(
        FUNC &&func,
        const details::ut::name_type &name = "check_throws",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        bool caught{};
        std::string caught_what{};

        try {
            std::forward<FUNC>(func)();
        }
        catch(const std::exception &e) {
            caught = true;
            caught_what = e.what();
        }
        catch(...) {
            caught = true;
            caught_what = "...";
        }

        return details::ut::test_assertion(caught, name, sloc, caught_what);
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    require_throws(
        FUNC &&func,
        const details::ut::name_type &name = "require_throws",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        if (!check_throws(std::forward<FUNC>(func), name, sloc)) {
            details::ut::required_failed();
        }

        return true;
    }

    /// Check Throws As
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user. This specific version checks that the exception thrown
    /// has a type of E
    ///
    /// AUTOSAR:
    /// - A15-3-4: the catch all and catch std::exception are used for
    ///   isolation.
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
    /// @throw [unchecked]: none
    ///
    template<typename E, typename FUNC>
    [[maybe_unused]] auto
    check_throws_as(
        FUNC &&func,
        const details::ut::name_type &name = "check_throws",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        bool caught{};
        std::string caught_what{};

        try {
            std::forward<FUNC>(func)();
        }
        catch(const E &e) {
            caught = true;
            caught_what = e.what();
        }
        catch(const std::exception &e) {
            caught = false;
            caught_what = e.what();
        }
        catch(...) {
            caught = false;
            caught_what = "...";
        }

        return details::ut::test_assertion(caught, name, sloc, caught_what);
    }

    /// Check Throws As
    ///
    /// Checks whether a function throws an exception. If the function does not
    /// throw an exception, the check will fail and eventually be reported
    /// to the user. This specific version checks that the exception thrown
    /// has a type of E
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
    /// @throw [unchecked]: none
    ///
    template<typename E, typename FUNC>
    [[maybe_unused]] auto
    require_throws_as(
        FUNC &&func,
        const details::ut::name_type &name = "require_throws_checked",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        if (!check_throws_as<E>(std::forward<FUNC>(func), name, sloc)) {
            details::ut::required_failed();
        }

        return true;
    }

    /// Check Does Not Throw
    ///
    /// Checks whether a function throws an exception. If the function
    /// throws an exception, the check will fail and eventually be reported
    /// to the user.
    ///
    /// AUTOSAR:
    /// - A15-3-4: the catch all and catch std::exception are used for
    ///   isolation.
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    check_nothrow(
        FUNC &&func,
        const details::ut::name_type &name = "check_nothrow",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        bool caught{};
        std::string caught_what{};

        try {
            std::forward<FUNC>(func)();
        }
        catch(const std::exception &e) {
            caught = true;
            caught_what = e.what();
        }
        catch(...) {
            caught = true;
            caught_what = "...";
        }

        return details::ut::test_assertion(!caught, name, sloc, caught_what);
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    require_nothrow(
        FUNC &&func,
        const details::ut::name_type &name = "require_nothrow",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        if (!check_nothrow(std::forward<FUNC>(func), name, sloc)) {
            details::ut::required_failed();
        }

        return true;
    }

#ifdef __linux__

    namespace details::ut
    {
        /// Wait
        ///
        /// Waits for a process to finish. This is used by the death tests
        /// to wait for a forked process to complete
        ///
        /// NOLINT:
        /// - We have no choice but to use UNIX APIs here as we must fork a
        ///   process. These APIs trigger clang-tidy, which we silence.
        ///   C++ really needs process management APIs to resolve this problem.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return the exit code from the process
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        wait() noexcept -> bsl::int32_t
        {
            bsl::int32_t exit_status;

            ::wait(&exit_status.get());
            return bsl::int32_t{WEXITSTATUS(exit_status.get())};    // NOLINT
        }
    }    // namespace details::ut

    /// Check Death
    ///
    /// Checks whether a function calls std::terminate and friends (anything
    /// that would result in the application exiting). If the application
    /// does not exit, the check fails and the results is eventually given
    /// to the user.
    ///
    /// AUTOSAR:
    /// - A15-3-4: the catch all and catch std::exception are used for
    ///   isolation.
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    check_death(
        FUNC &&func,
        const details::ut::name_type &name = "check_death",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        constexpr bsl::int32_t exit_code{191};
        fflush(stdout);

        if (0 == fork()) {
            try {
                std::forward<FUNC>(func)();
            }
            catch(...) {
            }

            bsl::fail_fast(exit_code.get());
        }
        else {
            return details::ut::test_assertion(
                details::ut::wait() != exit_code, name, sloc, {});
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    require_death(
        FUNC &&func,
        const details::ut::name_type &name = "require_death",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        if (!check_death(std::forward<FUNC>(func), name, sloc)) {
            details::ut::required_failed();
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
    /// AUTOSAR:
    /// - A15-3-4: the catch all and catch std::exception are used for
    ///   isolation.
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    check_nodeath(
        FUNC &&func,
        const details::ut::name_type &name = "check_nodeath",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        constexpr bsl::int32_t exit_code{191};
        fflush(stdout);

        if (0 == fork()) {
            try {
                std::forward<FUNC>(func)();
            }
            catch(...) {
            }

            bsl::fail_fast(exit_code.get());
        }
        else {
            return details::ut::test_assertion(
                details::ut::wait() == exit_code, name, sloc, {});
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
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    require_nodeath(
        FUNC &&func,
        const details::ut::name_type &name = "require_nodeath",
        const details::ut::sloc_type &sloc = here()) noexcept
        -> std::enable_if_t<std::is_invocable_v<FUNC>, bool>
    {
        if (!check_nodeath(std::forward<FUNC>(func), name, sloc)) {
            details::ut::required_failed();
        }

        return true;
    }

#endif

}    // namespace bsl

#endif
