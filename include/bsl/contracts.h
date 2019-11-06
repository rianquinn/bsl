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

// -----------------------------------------------------------------------------
// !!! AUTOSAR EXCEPTIONS !!!
// -----------------------------------------------------------------------------
//
// - Rule M0-1-11: There shall be no unused parameters (named or unnamed)
//   in non-virtualfunctions.
//
//   We use bsl::discard() to hide unused parameters from the compiler and
//   static analysis tools specifically so that the compiler will optimize away
//   contracts when they are disabled. As a result, there are two options:
//
//   - BSL_BUILD_LEVEL == 2: This will enable all contract checks, and as a
//     result will ensure that all parameters are used. This will include
//     audit tests. Not advisable in release builds.
//
//   - BSL_BUILD_LEVEL <= 1: This will either disable audit checks, or will
//     disable all checks. In both cases, an exception to AUTOSAR would be
//     required to stay compliant. This is advised in release builds.
//

#include "console_colors.h"
#include "source_location.h"
#include "discard.h"
#include "autosar.h"

#include <string>
#include <iostream>

#ifndef BSL_BUILD_LEVEL
#define BSL_BUILD_LEVEL 1
#endif

#ifndef BSL_CONTINUE_OPTION
#define BSL_CONTINUE_OPTION 0
#endif

static_assert(BSL_BUILD_LEVEL >= 0 and BSL_BUILD_LEVEL <= 2);
static_assert(BSL_CONTINUE_OPTION >= 0 and BSL_CONTINUE_OPTION <= 1);

namespace bsl::details::contracts
{
    constexpr bool check_default = (BSL_BUILD_LEVEL >= 1);
    constexpr bool check_audit = (BSL_BUILD_LEVEL == 2);
    constexpr bool continue_on_violation = (BSL_CONTINUE_OPTION == 1);
};    // namespace bsl::details::contracts

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

    namespace details::contracts
    {
        /// Default Violation Handler
        ///
        /// This function implements the default violation handler that is
        /// executed when a contract violation occurs. You can override this
        /// handler by calling set_violation_handler(). By default, this
        /// handler will output a message and call std::abort() as defined in
        /// the contracts spec. The use of std::abort() is not allowed with
        /// AUTOSAR, so if you enable AUTOSAR compliance, this function will
        /// throw instead.
        ///
        /// @expects
        /// @ensures
        ///
        /// @param info the violation information
        /// @return none
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[noreturn]] inline auto
        default_handler(const violation_info &info) -> void
        {
            std::string msg;
            msg += console_color::light_red;
            msg += "FATAL ERROR:";
            msg += console_color::end;
            msg += " ";
            msg += console_color::light_magenta;
            msg += info.comment;
            msg += console_color::end;
            msg += " violation [";
            msg += console_color::light_cyan;
            msg += std::to_string(info.location.line());
            msg += console_color::end;
            msg += "]: ";
            msg += console_color::light_yellow;
            msg += info.location.file_name();
            msg += console_color::end;

            if constexpr (autosar_compliant) {
                throw std::logic_error(msg);
            }
            else {
                std::cerr << msg << '\n';
                std::abort();
            }
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
    ///
    /// @param handler the handler to call when a contract violation occurs
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    set_violation_handler(void (*handler)(const violation_info &)) noexcept
        -> void
    {
        details::contracts::handler = handler;
    }

    /// Expects
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param test the precondition to check
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    expects(bool test, source_location loc = source_location::current()) -> void
    {
        using details::contracts::check_default;
        using details::contracts::continue_on_violation;
        using details::contracts::handler;
        using details::contracts::default_handler;

        if constexpr (check_default) {
            if (!test) {
                handler({loc, "default precondition"});
                if constexpr (!continue_on_violation) {
                    default_handler({loc, "[unhandled] default precondition"});
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
    ///
    /// @param test the precondition to check
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    ensures(bool test, source_location loc = source_location::current()) -> void
    {
        using details::contracts::check_default;
        using details::contracts::continue_on_violation;
        using details::contracts::handler;
        using details::contracts::default_handler;

        if constexpr (check_default) {
            if (!test) {
                handler({loc, "default postcondition"});
                if constexpr (!continue_on_violation) {
                    default_handler({loc, "[unhandled] default postcondition"});
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
    ///
    /// @param test the precondition to check
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    assert(bool test, source_location loc = source_location::current()) -> void
    {
        using details::contracts::check_default;
        using details::contracts::continue_on_violation;
        using details::contracts::handler;
        using details::contracts::default_handler;

        if constexpr (check_default) {
            if (!test) {
                handler({loc, "default assertion"});
                if constexpr (!continue_on_violation) {
                    default_handler({loc, "[unhandled] default assertion"});
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
    ///
    /// @param test the precondition to check
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    expects_audit(bool test, source_location loc = source_location::current())
        -> void
    {
        using details::contracts::check_audit;
        using details::contracts::continue_on_violation;
        using details::contracts::handler;
        using details::contracts::default_handler;

        if constexpr (check_audit) {
            if (!test) {
                handler({loc, "audit precondition"});
                if constexpr (!continue_on_violation) {
                    default_handler({loc, "[unhandled] audit precondition"});
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
    ///
    /// @param test the precondition to check
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    ensures_audit(bool test, source_location loc = source_location::current())
        -> void
    {
        using details::contracts::check_audit;
        using details::contracts::continue_on_violation;
        using details::contracts::handler;
        using details::contracts::default_handler;

        if constexpr (check_audit) {
            if (!test) {
                handler({loc, "audit postcondition"});
                if constexpr (!continue_on_violation) {
                    default_handler({loc, "[unhandled] audit postcondition"});
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
    ///
    /// @param test the precondition to check
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    assert_audit(bool test, source_location loc = source_location::current())
        -> void
    {
        using details::contracts::check_audit;
        using details::contracts::continue_on_violation;
        using details::contracts::handler;
        using details::contracts::default_handler;

        if constexpr (check_audit) {
            if (!test) {
                handler({loc, "audit assertion"});
                if constexpr (!continue_on_violation) {
                    default_handler({loc, "[unhandled] audit assertion"});
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
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param test ignored
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    expects_axiom(bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Ensures (Axiom)
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param test ignored
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    ensures_axiom(bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Assert (Axiom)
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param test ignored
    /// @return none
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    assert_axiom(bool test) noexcept -> void
    {
        bsl::discard(test);
    }
}    // namespace bsl

#endif
