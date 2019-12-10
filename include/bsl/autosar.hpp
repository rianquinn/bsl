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

#ifndef BSL_AUTOSAR_HPP
#define BSL_AUTOSAR_HPP

#include <new>
#include <stdexcept>

#include <functional>
#include <memory>
#include <variant>

namespace bsl
{
    using cstr_t = const char *;

    namespace details::autosar
    {
#ifndef BSL_EXIT_INSTEAD_OF_ABORT
        constexpr const bool exit_instead_of_abort = false;
#else
        constexpr const bool exit_instead_of_abort = true;
#endif
    }    // namespace details::autosar

#ifndef BSL_AUTOSAR_COMPLIANT
    constexpr bool autosar_compliant = false;
#else
    constexpr bool autosar_compliant = true;
#endif

    /// Checked Error
    ///
    /// Defines a checked error (exception). These are exceptions that
    /// should be checked. They are errors can could happen, that can be dealt
    /// with, but should not happen as normal execution.
    ///
    /// NOTE:
    /// - We do not inherit from std::runtime_error or std::logic_error
    ///   as these exception types of exceptions add additional memory
    ///   allocations to the exception type which increase the chances
    ///   of a bad_alloc.
    ///
    class checked_error : public std::exception
    {
        const char *const m_what;

    public:
        /// Default Constructor
        ///
        /// Creates a default checked error.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        checked_error() noexcept : m_what{"checked_error"}
        {}

        /// Constructor (const char *)
        ///
        /// Creates a checked error given a specific error message.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param msg the checked error msg to use.
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit checked_error(const char *const msg) noexcept : m_what{msg}
        {}

        /// What
        ///
        /// Returns the message that was provided when the exception was
        /// constructed.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the message provided during construction
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] auto
        what() const noexcept -> const char * override
        {
            return m_what;
        }
    };

    /// Unchecked Error
    ///
    /// Defines a unchecked error (exception). These are exceptions that
    /// should be unchecked. They are errors that should not happen as normal
    /// execution.
    ///
    /// NOTE:
    /// - We do not inherit from std::runtime_error or std::logic_error
    ///   as these exception types of exceptions add additional memory
    ///   allocations to the exception type which increase the chances
    ///   of a bad_alloc.
    /// - Technically the AUTOSAR specification states that an unchecked
    ///   error must come from a specific subset of exception types. This
    ///   subset does not include inheriting from std::exception directly.
    ///   Our implementation does not adhere to this specific rule, due to
    ///   the above note, but we do adhere to the spirit of the rule.
    ///   This gives us the ability to define our own logic errors, without
    ///   introducing issues with bad_alloc, which was likely an oversight
    ///   in the spec.
    ///
    class unchecked_error : public std::exception
    {
        const char *const m_what;

    public:
        /// Default Constructor
        ///
        /// Creates a default unchecked error.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        unchecked_error() noexcept : m_what{"unchecked_error"}
        {}

        /// Constructor (const char *)
        ///
        /// Creates an unchecked error given a specific error message.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param msg the checked error msg to use.
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit unchecked_error(const char *const msg) noexcept : m_what{msg}
        {}

        /// What
        ///
        /// Returns the message that was provided when the exception was
        /// constructed.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the message provided during construction
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] auto
        what() const noexcept -> const char * override
        {
            return m_what;
        }
    };

    /// Unchecked Fatal
    ///
    /// Defines a unchecked fatal (exception). These are exceptions that
    /// should be unchecked. They are errors that should not happen as normal
    /// execution. Unlike an unchecked error, when this exception type is
    /// created we "fail fast" by calling std::abort(). If AUTOSAR is enabled
    /// this exception will be thrown instead. The provides a single mechanism
    /// for handling errors (just throw this exception type, or a subclass
    /// of it), and the AUTOSAR policy will kick in if needed. Otherwise,
    /// your application will fail fast.
    ///
    /// Note, we also provide the ability to run std::exit() instead of
    /// std::abort(). This is useful when unit testing as std::abort does not
    /// run the cleanup functions list atexit() registered destructors, and
    /// it also generates a core dump which is slow.
    ///
    class unchecked_fatal : public unchecked_error
    {
        const char *const m_what;

        /// Fail Fast
        ///
        /// There are two different ways that you can exit a program in C++
        /// when something bad happens: throw an exception, or fail fast.
        /// When you fail fast, you exit immediately, which provides an
        /// opportunity to debug the application. If you throw, you will have
        /// the opportunity, instead, to cleanup, ensuing all destructors and
        /// resources are handled properly. If AUTOSAR is disabled, this
        /// function will cause a fail fast to occur instead of throwing an
        /// exception.
        ///
        /// NOSONAR:
        /// - We call std::abort() as this is what the spec states for
        ///   contracts. If AUTOSAR is enabled, we throw an unchecked
        ///   exception instead.
        /// - During unit testings, std::exit can be called instead which will
        ///   ensure memory is properly deleted, and prevents a core dump from
        ///   occuring which is really slow. THis is fine for AUTOSAR as this
        ///   only occurs if AUTOSAR compliance is disabled.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        static auto
        fail_fast() noexcept -> void
        {
            if constexpr (!autosar_compliant) {
                if constexpr (details::autosar::exit_instead_of_abort) {
                    std::exit(1);    //NOSONAR
                }

                std::abort();    //NOSONAR
            }
        }

    public:
        /// Default Constructor
        ///
        /// Creates a default unchecked error.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        unchecked_fatal() noexcept : m_what{"unchecked_fatal"}
        {
            fail_fast();
        }

        /// Constructor (const char *)
        ///
        /// Creates an unchecked error given a specific error message.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param msg the checked error msg to use.
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit unchecked_fatal(const char *const msg) noexcept : m_what{msg}
        {
            fail_fast();
        }

        /// What
        ///
        /// Returns the message that was provided when the exception was
        /// constructed.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the message provided during construction
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] auto
        what() const noexcept -> const char * override
        {
            return m_what;
        }
    };

    /// Discard
    ///
    /// The following will silence the compiler as well as static analysis
    /// checks complaining about unused parameters. This is the only compliant
    /// way to silence unused variable warnings.
    ///
    /// expects:
    /// ensures:
    ///
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename T>
    constexpr auto
    discard(T &&t) noexcept -> void
    {
        static_cast<void>(t);
    }

    /// Catch Checked Exceptions
    ///
    /// The following function will catch checked exception types, and let
    /// unchecked exception types pass through. A checked exception type
    /// is desfiend as follows:
    ///
    /// Used to represent errors that are expected and reasonable
    /// to recover from, so they are supposed to be declared by functions and
    /// caught and handled. These are all standard and user-defined exceptions
    /// that are not classified as “unchecked”, i.e. they are instances or
    /// subclasses of one of the following standard exception type:
    /// - std::exception
    /// - std::runtime_error
    /// - bsl::checked_error (BSL custom checked exception type)
    ///
    /// NOTE:
    /// - AUTOSAR (as seen from the description above) states that any
    ///   exception that inherits from std::exception is a checked exception
    ///   type. The problem is, all of the unchecked exception types also
    ///   inherit std::exception, so we DO NOT catch these. To solve this,
    ///   we provide a custom checked_error exception that can be used
    ///   instead of std::exception.
    ///
    /// NOSONAR:
    /// - SonarCloud gets mad about catching a std::runtime_error which is
    ///   required by AUTOSAR. In general, we do not turn this check off as
    ///   we don't want this being used.
    ///
    /// expects:
    /// ensures:
    ///
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename FUNC,
        typename HDLR,
        std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr,
        std::enable_if_t<std::is_nothrow_invocable_v<HDLR, const cstr_t>> * =
            nullptr>
    auto
    catch_checked(FUNC &&func, HDLR &&handler) -> void
    {
        try {
            func();
        }
        catch (const checked_error &e) {
            handler(e.what());
        }
        catch (const std::runtime_error &e) {    //NOSONAR
            handler(e.what());
        }
    }

    /// Catch Unchecked Exceptions
    ///
    /// The following function will catch unchecked exception types, and lets
    /// checked exception types pass through. An unchecked exception type
    /// is desfiend as follows:
    ///
    /// Used to represent errors that a program can not recover from, so they
    /// are not supposed to be declared by functions nor caught by caller
    /// functions. These are all exceptions (either built-in or user-defined)
    /// that are instances or subclasses of one of the following standard
    /// exception type:
    /// - std::logic_error
    /// – std::bad_typeid
    /// – std::bad_cast
    /// – std::bad_weak_ptr
    /// – std::bad_function_call
    /// – std::bad_alloc
    /// – std::bad_exception
    /// - std::bad_variant_access (missing in current spec)
    /// - bsl::unchecked_error (BSL custom unchecked exception type)
    ///
    /// NOTE:
    /// - AUTOSAR (as seen from the description above) states that any
    ///   exception that inherits from std::exception is a checked exception
    ///   type. The problem is, all of the unchecked exception types also
    ///   inherit std::exception, so we DO NOT catch these. To solve this,
    ///   we provide a custom checked_error exception that can be used
    ///   instead of std::exception.
    ///
    /// NOSONAR:
    /// - SonarCloud gets mad about catching a std::logic_error which is
    ///   required by AUTOSAR. In general, we do not turn this check off as
    ///   we don't want this being used.
    ///
    /// expects:
    /// ensures:
    ///
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename FUNC,
        typename HDLR,
        std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr,
        std::enable_if_t<std::is_nothrow_invocable_v<HDLR, const cstr_t>> * =
            nullptr>
    auto
    catch_unchecked(FUNC &&func, HDLR &&handler) -> void
    {
        try {
            func();
        }
        catch (const unchecked_error &e) {
            handler(e.what());
        }
        catch (const std::logic_error &e) {    //NOSONAR
            handler(e.what());
        }
        catch (const std::bad_typeid &e) {
            handler(e.what());
        }
        catch (const std::bad_cast &e) {
            handler(e.what());
        }
        catch (const std::bad_weak_ptr &e) {
            handler(e.what());
        }
        catch (const std::bad_function_call &e) {
            handler(e.what());
        }
        catch (const std::bad_alloc &e) {
            handler(e.what());
        }
        catch (const std::bad_exception &e) {
            handler(e.what());
        }
        catch (const std::bad_variant_access &e) {
            handler(e.what());
        }
    }

    /// Catch All Exceptions
    ///
    /// The following function will catch unchecked exception types, and lets
    /// checked exception types pass through. An unchecked exception type
    /// is desfiend as follows:
    ///
    /// Used to represent errors that a program can not recover from, so they
    /// are not supposed to be declared by functions nor caught by caller
    /// functions. These are all exceptions (either built-in or user-defined)
    /// that are instances or subclasses of one of the following standard
    /// exception type:
    /// - std::logic_error
    /// – std::bad_typeid
    /// – std::bad_cast
    /// – std::bad_weak_ptr
    /// – std::bad_function_call
    /// – std::bad_alloc
    /// – std::bad_exception
    /// - std::bad_variant_access (missing in current spec)
    /// - bsl::unchecked_error (BSL custom unchecked exception type)
    ///
    /// NOTE:
    /// - AUTOSAR (as seen from the description above) states that any
    ///   exception that inherits from std::exception is a checked exception
    ///   type. The problem is, all of the unchecked exception types also
    ///   inherit std::exception, so we DO NOT catch these. To solve this,
    ///   we provide a custom checked_error exception that can be used
    ///   instead of std::exception.
    ///
    /// NOSONAR:
    /// - SonarCloud gets mad about catching a std::logic_error,
    ///   std::runtime_error and ... which are required by AUTOSAR. In
    ///   general, we do not turn this check off as we don't want these
    ///   being used.
    ///
    /// expects:
    /// ensures:
    ///
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename FUNC,
        typename HDLR1,
        typename HDLR2,
        std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr,
        std::enable_if_t<std::is_nothrow_invocable_v<HDLR1, const cstr_t>> * =
            nullptr,
        std::enable_if_t<std::is_nothrow_invocable_v<HDLR2, const cstr_t>> * =
            nullptr>
    auto
    catch_all(
        FUNC &&func,
        HDLR1 &&checked_handler,
        HDLR2 &&unchecked_handler) noexcept -> void
    {
        try {
            func();
        }
        catch (const checked_error &e) {
            checked_handler(e.what());
        }
        catch (const std::runtime_error &e) {    //NOSONAR
            checked_handler(e.what());
        }
        catch (const unchecked_error &e) {
            unchecked_handler(e.what());
        }
        catch (const std::logic_error &e) {    //NOSONAR
            unchecked_handler(e.what());
        }
        catch (const std::bad_typeid &e) {
            unchecked_handler(e.what());
        }
        catch (const std::bad_cast &e) {
            unchecked_handler(e.what());
        }
        catch (const std::bad_weak_ptr &e) {
            unchecked_handler(e.what());
        }
        catch (const std::bad_function_call &e) {
            unchecked_handler(e.what());
        }
        catch (const std::bad_alloc &e) {
            unchecked_handler(e.what());
        }
        catch (const std::bad_exception &e) {
            unchecked_handler(e.what());
        }
        catch (const std::bad_variant_access &e) {
            unchecked_handler(e.what());
        }
        catch (const std::exception &e) {    //NOSONAR
            checked_handler(e.what());
        }
        catch (...) {    //NOSONAR
            checked_handler("...");
        }
    }

    /// Catch All Exceptions (No Handlers)
    ///
    /// Same as:
    ///     catch_all(
    ///         std::forward<FUNC>(func),
    ///         do_nothing,
    ///         do_nothing);
    ///
    template<
        typename FUNC,
        std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr>
    auto
    catch_all(FUNC &&func) noexcept -> void
    {
        try {
            func();
        }
        catch (...) {    //NOSONAR
        }
    }

    /// Catch All Exceptions (One Handler)
    ///
    /// Same as:
    ///     catch_all(
    ///         std::forward<FUNC>(func),
    ///         std::forward<FUNC>(handler),
    ///         std::forward<FUNC>(handler));
    ///
    template<
        typename FUNC,
        typename HDLR,
        std::enable_if_t<std::is_invocable_v<FUNC>> * = nullptr,
        std::enable_if_t<std::is_invocable_v<HDLR, const cstr_t>> * = nullptr>
    auto
    catch_all(FUNC &&func, HDLR &&handler) noexcept -> void
    {
        try {
            func();
        }
        catch (const std::exception &e) {    //NOSONAR
            handler(e.what());
        }
        catch (...) {    //NOSONAR
            handler("...");
        }
    }
}    // namespace bsl

#endif
