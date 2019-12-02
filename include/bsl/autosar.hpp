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

#include <cstdlib>
#include <stdexcept>

namespace bsl
{
    namespace details::autosar
    {
#ifndef BSL_AUTOSAR_COMPLIANT
        constexpr bool autosar_compliant = false;
#else
        constexpr bool autosar_compliant = true;
#endif

#ifndef BSL_EXIT_INSTEAD_OF_ABORT
        constexpr const bool exit_instead_of_abort = false;
#else
        constexpr const bool exit_instead_of_abort = true;
#endif
    }    // namespace details::autosar

    /// Checked Error
    ///
    /// Defines a checked error (exception). These are exceptions that
    /// should be checked. They are errors can could happen, that can be dealt
    /// with, but should not happen as normal execution. For example, not being
    /// able to open a file is not a good example of a checked error. That type
    /// of error can be dealt with, but could happen as normal execution, and
    /// so this type of error should be checked using an error code, and not
    /// an exception. A good example of a checked exception would be an error
    /// with a public API like a vmcall. Normal operation should never throw,
    /// but if something goes bad, this type of exception can be detected and
    /// handled (by returning from the API an error).
    ///
    class checked_error : public std::runtime_error
    {
    public:
        /// Default Constructor
        ///
        /// Creates a default checked error type based on the string the
        /// checked error was created from.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        checked_error() : std::runtime_error("checked_error")
        {}

        /// Constructor (const char *)
        ///
        /// Creates a default checked error type based on the string the
        /// checked error was created from.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param msg the checked error msg to use.
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit checked_error(const char *const msg) : std::runtime_error(msg)
        {}
    };

    /// Unchecked Error
    ///
    /// Defines an unchecked error (exception). These are exceptions that
    /// should not be checked. These types of errors should bubble up to the
    /// main() function (or any other entry point), and then an exit should
    /// occur. These should not generate a called to std::terminate(), so
    /// noexcept is not allowed if an unchecked could throw, but you should
    /// not attempt to catch these until you hit the entry point, which is the
    /// only place a catch(...) is allowed.
    ///
    class unchecked_error : public std::logic_error
    {
    public:
        /// Default Constructor
        ///
        /// Creates a default unchecked error type based on the string the
        /// unchecked error was created from.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        unchecked_error() : std::logic_error("unchecked_error")
        {}

        /// Constructor (const char *)
        ///
        /// Creates a default unchecked error type based on the string the
        /// unchecked error was created from.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param msg the unchecked error msg to use.
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit unchecked_error(const char *const msg) : std::logic_error(msg)
        {}
    };

    /// Abort
    ///
    /// Executes an abort(). Unlike the standard library version, the BSL
    /// version will throw instead of aborting if AUTOSAR compliance is
    /// enabled. In addition, this function can be configured to exit with an
    /// error code instead of aborting, which will ensure atexit() is called
    /// properly, which is useful when unit testing (no memory leaks).
    ///
    /// NOSONAR:
    /// - We call std::abort() as this is what the spec states for contracts.
    ///   If AUTOSAR is enabled, we throw an unchecked exception instead.
    /// - During unit testings, std::exit can be called instead which will
    ///   ensure memory is properly deleted, and prevents a core dump from
    ///   occuring which is really slow. THis is fine for AUTOSAR as this only
    ///   occurs if AUTOSAR compliance is disabled.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param exit_code the exit code to pass to std::exit()
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename ERROR = unchecked_error>
    [[noreturn]] auto
    abort(int exit_code = EXIT_FAILURE) -> void
    {
        if constexpr (details::autosar::autosar_compliant) {
            throw ERROR{};
        }

        if constexpr (details::autosar::exit_instead_of_abort) {
            std::exit(exit_code);    //NOSONAR
        }

        std::abort();    //NOSONAR
    }

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

    /// Catch All
    ///
    /// Catch All statements are only allowed from entry points. The AUTOSAR
    /// spec states this as the main() function. The intent of this rule is
    /// all checked exceptions are checked using a specific catch handler,
    /// and all other exceptions (i.e., unchecked) as checked at the entry
    /// point, using a catch all. This ensures that an error properly unrolls
    /// the stack and all objects that were created, without propagating
    /// beyond the entry point (usually the main function). There are other
    /// entry points however. For example, unit testing, IOCTL handlers,
    /// VMCall handlers, etc... This function provides a generic catch all
    /// that should only be used with entry points, and this should not be
    /// used to catch checked exceptions as those should be caught using
    /// a specific catch handler.
    ///
    /// NOSONAR:
    /// - SonarCloud gets mad about the catch(...), which is required by
    ///   AUTOSAR for entry points, so we need to disable this here.
    ///
    /// expects:
    /// ensures:
    ///
    /// @return true if no exceptions where thrown, false otherwise.
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename FUNC>
    [[maybe_unused]] auto
    catch_all(FUNC &&func) noexcept -> bool
    {
        try {
            func();
        }
        catch (...) {    //NOSONAR
            return false;
        }

        return true;
    }
}    // namespace bsl

#endif
