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
///
/// @file failure.hpp
///

#ifndef BSL_FAILURE_HPP
#define BSL_FAILURE_HPP

#include "fatal_error.hpp"

namespace bsl
{
    /// @brief denotes a successful exit
    constexpr std::int32_t exit_success{EXIT_SUCCESS};
    /// @brief denotes a failed exit
    constexpr std::int32_t exit_failure{EXIT_FAILURE};

    /// <!-- description -->
    ///   @brief The following is used to fail fast. This is needed when there
    ///     is no other option, and we must exit. When possible, you should
    ///     call bsl::fatal() instead of this function as it will call
    ///     call bsl::fail() which will throw an exception when AUTOSAR is
    ///     enabled instead of failing fast. Another option would be to throw
    ///     a bsl::checked_error() exception, or use a contract like
    ///     bsl::expects(). This function should only be used when you know
    ///     that there are absolutely no other options but to exit the program.
    ///     When AUTOSAR is enabled, this will call std::exit(), otherwise
    ///     this will call std::abort().
    ///   @include failure/fail_fast.cpp
    ///
    ///   SUPPRESSION: PRQA 4649 - false positive
    ///   - We suppress this because PRQA is stating that this function does
    ///     not have an external side effect. This function calls std::exit(),
    ///     which calls the atexit() handles, which is an external side effect,
    ///     and thus, this is a false positive.
    ///
    ///   SUPPRESSION: PRQA 5024 - mutually exclusive rules
    ///   - We suppress this because M18-0-3 is mutually exclusive with
    ///     A15-5-2. M18-0-3 states that std::exit() may not be called, while
    ///     A15-5-2 provides an exception to this rule specifically for
    ///     std::exit() as it calls the atexit() registered functions. When
    ///     an error occurs that cannot be recovered from (meaning an exception
    ///     is not possible), this is the AUTOSAR compliant solution. Note that
    ///     exceptions should be thrown when possible, and this should only
    ///     be used as a last resort.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param exit_code the exit code to pass to std::exit() if needed
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    [[noreturn]] inline void
    fail_fast(std::int32_t const exit_code = exit_failure) noexcept    // PRQA S 4649
    {
        static_cast<void>(exit_code);
        BSL_EXIT_FUNCTION;    // PRQA S 5024
    }

    /// <!-- description -->
    ///   @brief Used to issue a run-time failure. Note that this function
    ///     should be called using bsl::fatal() instead of directly calling
    ///     it. If AUTOSAR is enabled, this function will throw. Otherwise,
    ///     this function will call std::exit() with the provided exit code.
    ///   @include failure/fail.cpp
    ///
    ///   SUPPRESSION: PRQA 2880 - false positive
    ///   - We suppress this because M0-1-1 states that the program shall not
    ///     contain unreachable code, which refers to unreachable code at
    ///     runtime, not code that is compiled out due to a configuration
    ///     change. For example, code after a return statement, and code in
    ///     a switch statement with no associated case. In this specific case,
    ///     a constexpr-if statement is used which PRQA should be able to
    ///     detect but doesn't. Also note that Clang-Tidy has this same check
    ///     and the code below compiles without issue.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param sloc the location of the call to fail()
    ///   @param exit_code the exit code to pass to std::exit() if needed
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] possible
    ///
    [[noreturn]] inline void
    fail(sloc_type const &sloc = bsl::here(), std::int32_t const exit_code = exit_failure)
    {
        if constexpr (BSL_AUTOSAR_COMPLIANT) {
            throw fatal_error{sloc};
        }

        ::bsl::fail_fast(exit_code);    // PRQA S 2880
    }
}    // namespace bsl

#endif
