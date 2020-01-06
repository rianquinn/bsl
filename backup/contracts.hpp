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
/// @file contracts.hpp
///

#ifndef BSL_CONTRACTS_HPP
#define BSL_CONTRACTS_HPP

#include "violation_info.hpp"
#include "debug.hpp"

namespace bsl
{
    namespace details
    {
        /// @brief the type used to define a violation handler
        using violation_handler_t = void (*)(violation_info const &);

        /// @brief default_handler
        ///
        /// This function implements the default violation handler that is
        /// executed when a contract violation occurs. You can override this
        /// handler by calling set_violation_handler(). By default, this
        /// handler will output a message and call std::exit(). If AUTOSAR
        /// compliance is enabled, it will throw a contract_violation_error.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param info the violation information
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[noreturn]] constexpr void
        default_handler(violation_info const &info)
        {
            bsl::fatal(info.location(), "{} violation", info.comment());
        }

        /// @brief handler
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns a reference to the global violation handler
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename T = void>
        [[nodiscard]] violation_handler_t &
        handler() noexcept
        {
            static violation_handler_t s_handler{&default_handler};
            return s_handler;
        }

        /// @brief compile_time_contract_violation_occurred
        ///
        /// If you see this function show up in a compilation error, it
        /// means that a compile-time contract violation has occurred during
        /// the compilation of a constexpr. This function is not marked as a
        /// constexpr and is called from the contract functions. If the
        /// contract functions are used at compile-time, the compiler will
        /// error out when it attempts to compile this function, resulting
        /// in an error. This function only serves to provide a human readable
        /// error message. Without it, you would see an error about not being
        /// able to compile the handler as it is not marked as a constexpr.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return always returns false to silence side effect warnings.
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename T = void>
        [[maybe_unused]] bool
        compile_time_contract_violation_occurred() noexcept
        {
            return false;
        }
    }    // namespace details

    /// @brief set_violation_handler
    ///
    /// Sets the global violation handler that is called when a contract
    /// violation occurs.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param hdlr the handler to call when a contract violation occurs
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename T = void>
    void
    set_violation_handler(details::violation_handler_t const &hdlr) noexcept
    {
        details::handler() = hdlr;
    }

    /// @brief expects
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    expects(bool const test, sloc_type const &sloc = here())
    {
        static_cast<void>(test);
        static_cast<void>(sloc);

        if constexpr (BSL_CONTRACTS_CHECK_DEFAULT) {
            if (!test) {
                details::compile_time_contract_violation_occurred();
                details::handler()({sloc, "default precondition"});
                if constexpr (!BSL_CONTINUE_ON_VIOLATION) {
                    bsl::fail(sloc);
                }
            }
        }
    }

    /// @brief expects_false
    ///
    /// A precondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    expects_false(bool const test, sloc_type const &sloc = here())
    {
        expects(!test, sloc);
    }

    /// @brief ensures
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    ensures(bool const test, sloc_type const &sloc = here())
    {
        static_cast<void>(test);
        static_cast<void>(sloc);

        if constexpr (BSL_CONTRACTS_CHECK_DEFAULT) {
            if (!test) {
                details::compile_time_contract_violation_occurred();
                details::handler()({sloc, "default postcondition"});
                if constexpr (!BSL_CONTINUE_ON_VIOLATION) {
                    bsl::fail(sloc);
                }
            }
        }
    }

    /// @brief ensures_false
    ///
    /// A postcondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    ensures_false(bool const test, sloc_type const &sloc = here())
    {
        ensures(!test, sloc);
    }

    /// @brief confirm
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    confirm(bool const test, sloc_type const &sloc = here())
    {
        static_cast<void>(test);
        static_cast<void>(sloc);

        if constexpr (BSL_CONTRACTS_CHECK_DEFAULT) {
            if (!test) {
                details::compile_time_contract_violation_occurred();
                details::handler()({sloc, "default assertion"});
                if constexpr (!BSL_CONTINUE_ON_VIOLATION) {
                    bsl::fail(sloc);
                }
            }
        }
    }

    /// @brief confirm_false
    ///
    /// An assertion to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    confirm_false(bool const test, sloc_type const &sloc = here())
    {
        confirm(!test, sloc);
    }

    /// @brief expects_audit
    ///
    /// A precondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    expects_audit(bool const test, sloc_type const &sloc = here())
    {
        static_cast<void>(test);
        static_cast<void>(sloc);

        if constexpr (BSL_CONTRACTS_CHECK_AUDIT) {
            if (!test) {
                details::compile_time_contract_violation_occurred();
                details::handler()({sloc, "audit precondition"});
                if constexpr (!BSL_CONTINUE_ON_VIOLATION) {
                    bsl::fail(sloc);
                }
            }
        }
    }

    /// @brief expects_audit_false
    ///
    /// A precondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    expects_audit_false(bool const test, sloc_type const &sloc = here())
    {
        expects_audit(!test, sloc);
    }

    /// @brief ensures_audit
    ///
    /// A postcondition to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    ensures_audit(bool const test, sloc_type const &sloc = here())
    {
        static_cast<void>(test);
        static_cast<void>(sloc);

        if constexpr (BSL_CONTRACTS_CHECK_AUDIT) {
            if (!test) {
                details::compile_time_contract_violation_occurred();
                details::handler()({sloc, "audit postcondition"});
                if constexpr (!BSL_CONTINUE_ON_VIOLATION) {
                    bsl::fail(sloc);
                }
            }
        }
    }

    /// @brief ensures_audit_false
    ///
    /// A postcondition to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    ensures_audit_false(bool const test, sloc_type const &sloc = here())
    {
        ensures_audit(!test, sloc);
    }

    /// @brief confirm_audit
    ///
    /// An assertion to check. If this check evaluates to false, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    confirm_audit(bool const test, sloc_type const &sloc = here())
    {
        static_cast<void>(test);
        static_cast<void>(sloc);

        if constexpr (BSL_CONTRACTS_CHECK_AUDIT) {
            if (!test) {
                details::compile_time_contract_violation_occurred();
                details::handler()({sloc, "audit assertion"});
                if constexpr (!BSL_CONTINUE_ON_VIOLATION) {
                    bsl::fail(sloc);
                }
            }
        }
    }

    /// @brief confirm_audit_false
    ///
    /// An assertion to check. If this check evaluates to true, the
    /// violation handler is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param test the precondition to check
    /// @param sloc the location of the contract being checked
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    constexpr void
    confirm_audit_false(bool const test, sloc_type const &sloc = here())
    {
        confirm_audit(!test, sloc);
    }

    /// @brief expects_axiom
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
    template<typename T = void>
    constexpr void
    expects_axiom(bool const test) noexcept
    {
        static_cast<void>(test);
        static_assert(std::is_same<T, void>::value && !BSL_AUTOSAR_COMPLIANT);
    }

    /// @brief expects_axiom_false
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
    template<typename T = void>
    constexpr void
    expects_axiom_false(bool const test) noexcept
    {
        static_cast<void>(test);
        static_assert(std::is_same<T, void>::value && !BSL_AUTOSAR_COMPLIANT);
    }

    /// @brief ensures_axiom
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
    template<typename T = void>
    constexpr void
    ensures_axiom(bool const test) noexcept
    {
        static_cast<void>(test);
        static_assert(std::is_same<T, void>::value && !BSL_AUTOSAR_COMPLIANT);
    }

    /// @brief ensures_axiom_false
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
    template<typename T = void>
    constexpr void
    ensures_axiom_false(bool const test) noexcept
    {
        static_cast<void>(test);
        static_assert(std::is_same<T, void>::value && !BSL_AUTOSAR_COMPLIANT);
    }

    /// @brief confirm_axiom
    ///
    /// An assertion to check. If this check evaluates to false, the
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
    template<typename T = void>
    constexpr void
    confirm_axiom(bool const test) noexcept
    {
        static_cast<void>(test);
        static_assert(std::is_same<T, void>::value && !BSL_AUTOSAR_COMPLIANT);
    }

    /// @brief confirm_axiom_false
    ///
    /// An assertion to check. If this check evaluates to true, the
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
    template<typename T = void>
    constexpr void
    confirm_axiom_false(bool const test) noexcept
    {
        static_cast<void>(test);
        static_assert(std::is_same<T, void>::value && !BSL_AUTOSAR_COMPLIANT);
    }
}    // namespace bsl

#endif
