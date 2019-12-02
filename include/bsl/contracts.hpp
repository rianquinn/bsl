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

#ifndef BSL_CONTRACTS_HPP
#define BSL_CONTRACTS_HPP

#include "debug.hpp"

namespace bsl::details::contracts
{
#if !defined(BSL_BUILD_LEVEL)
    constexpr bool check_default = true;
    constexpr bool check_audit = false;
#elif BSL_BUILD_LEVEL == 1
    constexpr bool check_default = true;
    constexpr bool check_audit = false;
#elif BSL_BUILD_LEVEL == 2
    constexpr bool check_default = true;
    constexpr bool check_audit = true;
#else
    constexpr bool check_default = false;
    constexpr bool check_audit = false;
#endif

#ifdef BSL_CONTINUE_OPTION
    constexpr bool continue_on_violation = true;
#else
    constexpr bool continue_on_violation = false;
#endif
}    // namespace bsl::details::contracts

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bsl
{
    struct contract_violation_error : bsl::unchecked_error
    {};

    /// Violation Information
    ///
    /// Provides information about a contract violation that can be used in a
    /// custom violation handler.
    ///
    /// NOSONAR
    /// - This structure is defined by the spec for contracts, which dictates
    ///   the use of a struct with publically accessible data members with
    ///   these specific names. SonarCloud is mad about the fact that the
    ///   member names do not begin with m_, which is fine since we did not
    ///   write the spec, and someday, C++ will have native support for
    ///   contracts.
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
        source_location location{};    //NOSONAR
        const char *comment{};         //NOSONAR
    };

    namespace details::contracts
    {
        /// Private Handler Signature
        ///
        using handler_t = void (*)(const violation_info &);

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
        /// expects: none
        /// ensures: none
        ///
        /// @param info the violation information
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[noreturn]] inline auto
        default_handler(const violation_info &info) -> void
        {
            bsl::fatal<contract_violation_error>(
                "{} violation\n{}", info.comment, info.location);
        }

        /// NOSONAR:
        /// - We cannot use a std::function here as this requires a global
        ///   constructor/destructor.
        ///
        inline handler_t handler = default_handler;    //NOSONAR
    }    // namespace details::contracts

    /// Set Violation Handler
    ///
    /// Sets the global violation handler that is called when a contract
    /// violation occurs.
    ///
    /// NOSONAR:
    /// - We cannot store a std::function globally, so therefore we cannot
    ///   accept a std::function here.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param handler the handler to call when a contract violation occurs
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    set_violation_handler(
        const details::contracts::handler_t handler)    //NOSONAR
        noexcept -> void
    {
        details::contracts::handler = handler;
    }

    /// Expects
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    expects(const bool test, const source_location loc = here()) -> void
    {
        bsl::discard(test);
        bsl::discard(loc);

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
    }

    /// Expects False
    ///
    /// A precondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    expects_false(const bool test, const source_location loc = here()) -> void
    {
        expects(!test, loc);
    }

    /// Ensures
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    ensures(const bool test, const source_location loc = here()) -> void
    {
        bsl::discard(test);
        bsl::discard(loc);

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
    }

    /// Ensures False
    ///
    /// A postcondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    ensures_false(const bool test, const source_location loc = here()) -> void
    {
        ensures(!test, loc);
    }

    /// Confirm (Assert)
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// NOTE: We use confirm instead of assert as assert is a reserved
    ///     symbol that we cannot use.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    confirm(const bool test, const source_location loc = here()) -> void
    {
        bsl::discard(test);
        bsl::discard(loc);

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
    }

    /// Confirm False (Assert)
    ///
    /// An assertion to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// NOTE: We use confirm instead of assert as assert is a reserved
    ///     symbol that we cannot use.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    confirm_false(const bool test, const source_location loc = here()) -> void
    {
        confirm(!test, loc);
    }

    /// Expects (Audit)
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    expects_audit(const bool test, const source_location loc = here()) -> void
    {
        bsl::discard(test);
        bsl::discard(loc);

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
    }

    /// Expects False (Audit)
    ///
    /// A precondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    expects_audit_false(const bool test, const source_location loc = here())
        -> void
    {
        expects_audit(!test, loc);
    }

    /// Ensures (Audit)
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    ensures_audit(const bool test, const source_location loc = here()) -> void
    {
        bsl::discard(test);
        bsl::discard(loc);

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
    }

    /// Ensures False (Audit)
    ///
    /// A postcondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    ensures_audit_false(const bool test, const source_location loc = here())
        -> void
    {
        ensures_audit(!test, loc);
    }

    /// Confirm (Assert Audit)
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// NOTE: We use confirm instead of assert as assert is a reserved
    ///     symbol that we cannot use.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    confirm_audit(const bool test, const source_location loc = here()) -> void
    {
        bsl::discard(test);
        bsl::discard(loc);

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
    }

    /// Confirm False (Assert Audit)
    ///
    /// An assertion to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// NOTE: We use confirm instead of assert as assert is a reserved
    ///     symbol that we cannot use.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr auto
    confirm_audit_false(const bool test, const source_location loc = here())
        -> void
    {
        confirm_audit(!test, loc);
    }

    /// Expects (Axiom)
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test ignored
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    expects_axiom(const bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Expects False (Axiom)
    ///
    /// A precondition to check. If this check evaluates to true, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test ignored
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    expects_axiom_false(const bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Ensures (Axiom)
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test ignored
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    ensures_axiom(const bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Ensures False (Axiom)
    ///
    /// A postcondition to check. If this check evaluates to true, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test ignored
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    ensures_axiom_false(const bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Confirm (Assert Axiom)
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// NOTE: We use confirm instead of assert as assert is a reserved
    ///     symbol that we cannot use.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test ignored
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    confirm_axiom(const bool test) noexcept -> void
    {
        bsl::discard(test);
    }

    /// Confirm False (Assert Axiom)
    ///
    /// An assertion to check. If this check evaluates to true, the
    /// violation will be ignored. This exists for documentation only. Note
    /// that this is not compatible with AUTOSAR.
    ///
    /// NOTE: We use confirm instead of assert as assert is a reserved
    ///     symbol that we cannot use.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test ignored
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    confirm_axiom_false(const bool test) noexcept -> void
    {
        bsl::discard(test);
    }
}    // namespace bsl

#endif
