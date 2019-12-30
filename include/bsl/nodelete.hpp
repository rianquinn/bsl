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

#ifndef BSL_NODELETE_HPP
#define BSL_NODELETE_HPP

namespace bsl
{
    /// @class nodelete
    ///
    /// Does nothing. As a result, the bsl::unique_owner and friends should
    /// optimize away and behave like a gsl::owner. In addition, the owner
    /// can be used as a constexpr.
    ///
    template<typename T>
    class nodelete
    {
        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr nodelete() noexcept = default;

    protected:
        /// @brief destructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~nodelete() noexcept = default;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr nodelete(nodelete const &o) noexcept = default;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be moved
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr nodelete(nodelete &&o) noexcept = default;

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @return a reference to the newly copied object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr nodelete &operator=(nodelete const &o) &noexcept = default;

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be moved
        /// @return a reference to the newly moved object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr nodelete &operator=(nodelete &&o) &noexcept = default;
    };
}    // namespace bsl

#endif
