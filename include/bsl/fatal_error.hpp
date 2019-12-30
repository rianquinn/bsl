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

#ifndef BSL_FATAL_ERROR_HPP
#define BSL_FATAL_ERROR_HPP

#include "unchecked_error.hpp"

namespace bsl
{
    /// @class fatal_error
    ///
    /// This class provides the base type for all unchecked exception types
    /// used by Bareflank.
    ///
    class fatal_error final : public unchecked_error
    {
    public:
        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param sloc the source location of the exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit fatal_error(sloc_type const &sloc = bsl::here()) noexcept
            : unchecked_error{"fatal_error", nullptr, sloc}
        {}

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param comm a comment to add to the exception
        /// @param sloc the source location of the exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit fatal_error(cstr_type const &comm, sloc_type const &sloc = bsl::here()) noexcept
            : unchecked_error{"fatal_error", comm, sloc}
        {}

        /// @brief destructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~fatal_error() noexcept final = default;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        fatal_error(fatal_error const &o) noexcept = default;

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return a reference to the newly copied object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        fatal_error &operator=(fatal_error const &o) &noexcept = default;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        fatal_error(fatal_error &&o) noexcept = default;

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return a reference to the newly moved object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        fatal_error &operator=(fatal_error &&o) &noexcept = default;
    };
}    // namespace bsl

#endif
