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

#include <stdlib.h>    // NOLINT

#include "color.hpp"
#include "cstr_type.hpp"
#include "discard.hpp"
#include "exit_code.hpp"
#include "forward.hpp"
#include "move.hpp"
#include "new.hpp"
#include "print.hpp"
#include "source_location.hpp"

namespace bsl
{
    namespace details
    {
        using ut_test_handler_type = void (*)();

        template<typename T = void>
        cstr_type &
        ut_current_test_case() noexcept
        {
            static cstr_type s_ut_current_test_case{};
            return s_ut_current_test_case;
        }

        template<typename T = void>
        ut_test_handler_type &
        ut_reset_handler() noexcept
        {
            static ut_test_handler_type s_ut_reset_handler{};
            return s_ut_reset_handler;
        }

        template<typename T = void>
        void
        ut_output_here(sloc_type const &sloc) noexcept
        {
            bsl::print("  --> ");
            bsl::print("%s%s%s", yellow, sloc.file_name(), reset_color);
            bsl::print(": ");
            bsl::print("%s%d%s", cyan, sloc.line(), reset_color);
            bsl::print("\n");
        }
    }

    class ut_scenario final
    {
    public:
        explicit constexpr ut_scenario(cstr_type const &name) noexcept    // --
            : m_name{name}
        {}

        template<typename FUNC>
        [[maybe_unused]] constexpr ut_scenario &
        operator=(FUNC &&func) noexcept
        {
            details::ut_current_test_case() = m_name;

            bsl::forward<FUNC>(func)();
            if (nullptr != details::ut_reset_handler()) {
                details::ut_reset_handler()();
            }

            details::ut_current_test_case() = nullptr;
            return *this;
        }

        constexpr ut_scenario(ut_scenario const &o) noexcept = delete;
        constexpr ut_scenario(ut_scenario &&o) noexcept = delete;

        [[maybe_unused]] constexpr ut_scenario &operator=(ut_scenario const &o) &noexcept = delete;
        [[maybe_unused]] constexpr ut_scenario &operator=(ut_scenario &&o) &noexcept = delete;

        ~ut_scenario() noexcept = default;

    private:
        cstr_type m_name;
    };

    class ut_given final
    {
    public:
        constexpr ut_given() noexcept = default;

        template<typename FUNC>
        [[maybe_unused]] constexpr ut_given &
        operator=(FUNC &&func) noexcept
        {
            bsl::forward<FUNC>(func)();
            return *this;    // PRQA S 2880
        }

        constexpr ut_given(ut_given const &o) noexcept = delete;
        constexpr ut_given(ut_given &&o) noexcept = delete;

        [[maybe_unused]] constexpr ut_given &operator=(ut_given const &o) &noexcept = delete;
        [[maybe_unused]] constexpr ut_given &operator=(ut_given &&o) &noexcept = delete;

        ~ut_given() noexcept = default;
    };

    class ut_when final
    {
    public:
        constexpr ut_when() noexcept = default;

        template<typename FUNC>
        [[maybe_unused]] constexpr ut_when &
        operator=(FUNC &&func) noexcept
        {
            bsl::forward<FUNC>(func)();
            return *this;    // PRQA S 2880
        }

        constexpr ut_when(ut_when const &o) noexcept = delete;
        constexpr ut_when(ut_when &&o) noexcept = delete;

        [[maybe_unused]] constexpr ut_when &operator=(ut_when const &o) &noexcept = delete;
        [[maybe_unused]] constexpr ut_when &operator=(ut_when &&o) &noexcept = delete;

        ~ut_when() noexcept = default;
    };

    class ut_then final
    {
    public:
        constexpr ut_then() noexcept = default;

        template<typename FUNC>
        [[maybe_unused]] constexpr ut_then &
        operator=(FUNC &&func) noexcept
        {
            bsl::forward<FUNC>(func)();
            if (nullptr != details::ut_reset_handler()) {
                details::ut_reset_handler()();
            }

            return *this;    // PRQA S 2880
        }

        constexpr ut_then(ut_then const &o) noexcept = delete;
        constexpr ut_then(ut_then &&o) noexcept = delete;

        [[maybe_unused]] constexpr ut_then &operator=(ut_then const &o) &noexcept = delete;
        [[maybe_unused]] constexpr ut_then &operator=(ut_then &&o) &noexcept = delete;

        ~ut_then() noexcept = default;
    };

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
    ///   @brief Outputs a message and returns bsl::exit_success
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return returns bsl::exit_success
    ///
    template<typename T = void>
    bsl::exit_code
    ut_success() noexcept
    {
        bsl::print("%s%s%s\n", green, "All tests passed", reset_color);
        return bsl::exit_success;
    }

    /// <!-- description -->
    ///   @brief Outputs a message and returns bsl::exit_success
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param sloc used to identify the location in the unit test that a
    ///     check failed.
    ///
    template<typename T = void>
    void
    ut_failure(sloc_type const &sloc = here()) noexcept
    {
        bsl::print("%s%s%s ", red, "[UNIT TEST FAILED]", reset_color);
        bsl::print("in test case \"");
        bsl::print("%s%s%s", magenta, details::ut_current_test_case(), reset_color);
        bsl::print("\"\n");
        details::ut_output_here(sloc);

        exit(EXIT_FAILURE);    // PRQA S 5024
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
            bsl::print("%s%s%s ", red, "[CHECK FAILED]", reset_color);
            bsl::print("in test case \"");
            bsl::print("%s%s%s", magenta, details::ut_current_test_case(), reset_color);
            bsl::print("\"\n");
            details::ut_output_here(sloc);

            exit(EXIT_FAILURE);    // PRQA S 5024
        }

        return test;
    }
}

#endif
