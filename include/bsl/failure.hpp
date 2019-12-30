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

#ifndef BSL_FAILURE_HPP
#define BSL_FAILURE_HPP

#include "fatal_error.hpp"
#include <cstdlib>

namespace bsl
{
    /// @brief denotes a successful exit
    constexpr std::int32_t exit_success{0};
    /// @brief denotes a failed exit
    constexpr std::int32_t exit_failure{1};

    /// Fail Fast
    ///
    /// The following is used to fail fast. This is needed when there is
    /// no other option, and we must exit. When possible, you should
    /// call bsl::fail() instead of this function as it will throw an exception
    /// when AUTOSAR is enabled instead of failing fast. Another option would
    /// be to throw an exception. This function should only be used when you
    /// know that there are absolutely no other options but to exit the
    /// program. When AUTOSAR is enabled, this will call std::exit(), otherwise
    /// this will call std::abort().
    ///
    /// SUPPRESSION: PRQA 4649 - false positive
    /// - This function calls std::exit(), which calls the atexit() handles,
    ///   which is an external side effect.
    ///
    /// SUPPRESSION: PRQA 5024 - mutually exclusive rules
    /// - We suppress this because M18-0-3 is mutually exclusive with
    ///   A15-5-2. M18-0-3 states that std::exit() may not be called, while
    ///   A15-5-2 provides an exception to this rule specifically for
    ///   std::exit() as it calls the atexit() registered functions. When
    ///   an error occurs that cannot be recovered from (meaning an exception
    ///   is not possible), this is the AUTOSAR compliant solution.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param exit_code the exit code to pass to std::exit
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    [[noreturn]] inline void
    fail_fast(std::int32_t const exit_code = exit_failure) noexcept    // PRQA S 4649
    {
        static_cast<void>(exit_code);
        BSL_EXIT_FUNCTION;    // PRQA S 5024
    }

    /// Fail
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param sloc the source location of the failure
    /// @param exit_code the exit code to pass to fast_fail
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    [[noreturn]] inline void
    fail(sloc_type const &sloc = bsl::here(), std::int32_t const exit_code = exit_failure)
    {
        if constexpr (BSL_AUTOSAR_COMPLIANT) {
            throw fatal_error{sloc};
        }

        ::bsl::fail_fast(exit_code);
    }
}    // namespace bsl

#endif
