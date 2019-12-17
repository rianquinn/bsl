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

#include <stdexcept>

namespace bsl
{
    /// C-Style String Type
    ///
    /// The following defines a C style string type.
    ///
    using cstr_t = const char *;

    /// AUTOSAR Compliant
    ///
    /// If this is set, the BSL is configured to be compliant with AUTOSAR
    /// which changes certain behaviors including things like contracts
    /// throwing instead of calling std::abort().
    ///
    constexpr bool autosar_compliant = BSL_AUTOSAR_COMPLIANT;

    /// Checked Error
    ///
    /// Defines a checked error (exception). These are exceptions that
    /// should be checked. They are errors can could happen, that can be dealt
    /// with, but should not happen as normal execution.
    ///
    class checked_error : public std::runtime_error
    {
    public:
        /// Default Constructor
        ///
        /// Creates a default checked error.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        checked_error() : std::runtime_error("checked_error")
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
        /// @throw [unchecked]: possible
        ///
        explicit checked_error(cstr_t msg) : std::runtime_error(msg)
        {}
    };

    /// Unchecked Error
    ///
    /// Defines a unchecked error (exception). These are exceptions that
    /// should be unchecked. They are errors that should not happen as normal
    /// execution.
    ///
    class unchecked_error : public std::logic_error
    {
    public:
        /// Default Constructor
        ///
        /// Creates a default checked error.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        unchecked_error() : std::logic_error("unchecked_error")
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
        /// @throw [unchecked]: possible
        ///
        explicit unchecked_error(cstr_t msg) : std::logic_error(msg)
        {}
    };

    /// Fail Fast
    ///
    /// The following is used to fail fast. This is needed when there is
    /// no other option, and we must exit. When possible, you should
    /// propogate a bsl::unchecked_error instead of calling this function,
    /// but if you are isolating exceptions, this might be needed when you
    /// cannot handle all possible exception types.
    ///
    /// NOSONAR: AUTOSAR:
    /// - A15-5-2: We call std::exit(EXIT_FAILURE), instead of std::abort,
    ///   or std::terminate() as directed.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    [[noreturn]] inline auto
    fail_fast(int exit_code = EXIT_FAILURE) noexcept -> void
    {
        std::exit(exit_code); //NOSONAR
    }

    namespace details::autosar
    {
        /// Failure
        ///
        /// The following handles fatal errors. This function is used by the
        /// debug logic to implement a bsl::fatal. It lives here because how
        /// this code functions is dictated by the AUTOSAR policy. If
        /// AUTOSAR is required, we throw, otherwise we exit.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        template<typename ERROR = bsl::unchecked_error()>
        [[noreturn]] constexpr auto
        failure() -> void
        {
            if constexpr (autosar_compliant) {
                throw ERROR{};
            }

            ::bsl::fail_fast();
        }
    }    // namespace details::autosar

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
}    // namespace bsl

#endif
