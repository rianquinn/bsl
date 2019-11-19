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

#ifndef BSL_EXCEPTION_H
#define BSL_EXCEPTION_H

#include <stdexcept>

namespace bsl
{
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
    template<const char *L>
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
        checked_error() :
            std::runtime_error(L)
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
        explicit checked_error(const char *msg) :
            std::runtime_error(msg)
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
    template<const char *L>
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
        unchecked_error() :
            std::runtime_error(L)
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
        explicit unchecked_error(const char *msg) :
            std::runtime_error(msg)
        {}
    };
}    // namespace bsl

#endif
