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

#ifndef BSL_CONTRACTS_H
#define BSL_CONTRACTS_H

#include "console_colors.h"
#include "source_location.h"
#include "utility.h"

#include <string>
#include <iostream>

// The following implementation is inspired from the following:
//
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0380r1.pdf
//
// There are some differences:
// - We cannot use the attribute syntax, so this is implemented using regular
//   C++ functions
// - There is no support for the declaration based syntax.
// - Axioms are supported but do nothing other than comment.
//

#define BSL_BUILD_LEVEL_OFF 0        ///< Turns off contract checks
#define BSL_BUILD_LEVEL_DEFAULT 1    ///< Turns on default contract checks
#define BSL_BUILD_LEVEL_AUDIT 2      ///< Turns on all contract checks

#ifndef BSL_BUILD_LEVEL
#define BSL_BUILD_LEVEL BSL_BUILD_LEVEL_DEFAULT
#endif

#ifndef BSL_CONTINUE_ON_CONTRACT_VIOLATION
#define BSL_CONTINUE_ON_CONTRACT_VIOLATION false
#endif

#if BSL_BUILD_LEVEL < 0 || BSL_BUILD_LEVEL > 2
#error "invalid BSL_BUILD_LEVEL: expecting 0, 1, or 2"
#endif

#if BSL_CONTINUE_ON_CONTRACT_VIOLATION != 0 &&                                 \
    BSL_CONTINUE_ON_CONTRACT_VIOLATION != 1
#error "invalid BSL_BUILD_LEVEL: expecting 0, 1, or 2"
#endif

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bsl
{
    /// Violation Information
    ///
    /// Provides information about a contract violation that can be used in a
    /// custom violation handler.
    ///
    /// @var violation_info::location
    ///     the location of the violation.
    /// @var violation_info::comment
    ///     a comment about the violation (our version of contracts does not
    ///     include a stringified version of the contract itself as that
    ///     could require macros, which we do not want to support).
    ///
    struct violation_info
    {
        source_location location;
        const char *comment;
    };

    /// Private Details
    ///
    namespace details::contracts
    {
        [[noreturn]] inline auto
        default_handler(const violation_info &info) noexcept -> void
        {
            if constexpr (BSL_BUILD_LEVEL > BSL_BUILD_LEVEL_OFF) {
                std::string msg;
                msg += console_color::light_red;
                msg += "FATAL ERROR:";
                msg += console_color::end;
                msg += " ";
                msg += console_color::light_magenta;
                msg += info.comment;
                msg += console_color::end;
                msg += " [";
                msg += console_color::light_cyan;
                msg += info.location.line();
                msg += console_color::end;
                msg += "]: ";
                msg += console_color::light_yellow;
                msg += info.location.file();
                msg += console_color::end;

                std::cerr << msg << '\n';
            }
            else {
                bsl::discard(info);
            }

            std::abort();
        }

        void (*handler)(const violation_info &) = default_handler;
    }    // namespace details::contracts

    /// Set Violation Handler
    ///
    /// Sets the global violation handler that is called when a contract
    /// violation occurs.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts none
    ///
    /// @param handler the handler to call when a contract violation occurs
    /// @return none
    ///
    constexpr auto
    set_violation_handler(void (*handler)(const violation_info &)) noexcept
        -> void
    {
        if constexpr (BSL_BUILD_LEVEL > BSL_BUILD_LEVEL_OFF) {
            details::contracts::handler = handler;
        }
        else {
            bsl::discard(handler);
        }
    }

    /// Expects
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts depends on the violation handler. the default violation
    ///     handler is marked as noexcept and called std::abort().
    ///
    /// @param test the precondition to check
    /// @return none
    ///
    constexpr auto
    expects(bool test, source_location loc = source_location::current()) -> void
    {
        if constexpr (BSL_BUILD_LEVEL >= BSL_BUILD_LEVEL_DEFAULT) {
            if (!test) {
                details::contracts::handler({loc, "precondition violation"});

                if constexpr (!BSL_CONTINUE_ON_CONTRACT_VIOLATION) {
                    std::get_terminate()();
                }
            }
        }
        else {
            bsl::discard(test);
            bsl::discard(loc);
        }
    }

    /// Ensures
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts depends on the violation handler. the default violation
    ///     handler is marked as noexcept and called std::abort().
    ///
    /// @param test the postcondition to check
    /// @return none
    ///
    constexpr auto
    ensures(bool test, source_location loc = source_location::current()) -> void
    {
        if constexpr (BSL_BUILD_LEVEL >= BSL_BUILD_LEVEL_DEFAULT) {
            if (!test) {
                details::contracts::handler({loc, "postcondition violation"});

                if constexpr (!BSL_CONTINUE_ON_CONTRACT_VIOLATION) {
                    std::get_terminate()();
                }
            }
        }
        else {
            bsl::discard(test);
            bsl::discard(loc);
        }
    }

    /// Assert
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts depends on the violation handler. the default violation
    ///     handler is marked as noexcept and called std::abort().
    ///
    /// @param test the assertion to check
    /// @return none
    ///
    constexpr auto
    assert(bool test, source_location loc = source_location::current()) -> void
    {
        if constexpr (BSL_BUILD_LEVEL >= BSL_BUILD_LEVEL_DEFAULT) {
            if (!test) {
                details::contracts::handler({loc, "assertion violation"});

                if constexpr (!BSL_CONTINUE_ON_CONTRACT_VIOLATION) {
                    std::get_terminate()();
                }
            }
        }
        else {
            bsl::discard(test);
            bsl::discard(loc);
        }
    }

    /// Expects (Audit)
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts depends on the violation handler. the default violation
    ///     handler is marked as noexcept and called std::abort().
    ///
    /// @param test the precondition to check
    /// @return none
    ///
    constexpr auto
    expects_audit(bool test, source_location loc = source_location::current())
        -> void
    {
        if constexpr (BSL_BUILD_LEVEL >= BSL_BUILD_LEVEL_DEFAULT) {
            if (!test) {
                details::contracts::handler({loc, "precondition violation"});

                if constexpr (!BSL_CONTINUE_ON_CONTRACT_VIOLATION) {
                    std::get_terminate()();
                }
            }
        }
        else {
            bsl::discard(test);
            bsl::discard(loc);
        }
    }

    /// Ensures (Audit)
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts depends on the violation handler. the default violation
    ///     handler is marked as noexcept and called std::abort().
    ///
    /// @param test the postcondition to check
    /// @return none
    ///
    constexpr auto
    ensures_audit(bool test, source_location loc = source_location::current())
        -> void
    {
        if constexpr (BSL_BUILD_LEVEL >= BSL_BUILD_LEVEL_DEFAULT) {
            if (!test) {
                details::contracts::handler({loc, "postcondition violation"});

                if constexpr (!BSL_CONTINUE_ON_CONTRACT_VIOLATION) {
                    std::get_terminate()();
                }
            }
        }
        else {
            bsl::discard(test);
            bsl::discard(loc);
        }
    }

    /// Assert (Audit)
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts depends on the violation handler. the default violation
    ///     handler is marked as noexcept and called std::abort().
    ///
    /// @param test the assertion to check
    /// @return none
    ///
    constexpr auto
    assert_audit(bool test, source_location loc = source_location::current())
        -> void
    {
        if constexpr (BSL_BUILD_LEVEL >= BSL_BUILD_LEVEL_DEFAULT) {
            if (!test) {
                details::contracts::handler({loc, "assertion violation"});

                if constexpr (!BSL_CONTINUE_ON_CONTRACT_VIOLATION) {
                    std::get_terminate()();
                }
            }
        }
        else {
            bsl::discard(test);
            bsl::discard(loc);
        }
    }

    /// Expects (Axiom)
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation is ignored. This is for documentation purposes only.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts none
    ///
    /// @param test the precondition to check
    /// @return none
    ///
    constexpr auto
    expects_axiom(bool test) -> void
    {
        bsl::discard(test);
    }

    /// Ensures (Axiom)
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation is ignored. This is for documentation purposes only.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts none
    ///
    /// @param test the postcondition to check
    /// @return none
    ///
    constexpr auto
    ensures_axiom(bool test) -> void
    {
        bsl::discard(test);
    }

    /// Assert (Axiom)
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation is ignored. This is for documentation purposes only.
    ///
    /// @expects none
    /// @ensures none
    /// @excepts none
    ///
    /// @param test the assertion to check
    /// @return none
    ///
    constexpr auto
    assert_axiom(bool test) -> void
    {
        bsl::discard(test);
    }
}    // namespace bsl

#endif
