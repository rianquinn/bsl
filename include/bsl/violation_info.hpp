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

#ifndef BSL_VIOLATION_INFO_HPP
#define BSL_VIOLATION_INFO_HPP

#include "types.hpp"
#include "source_location.hpp"

namespace bsl
{
    /// @class violation_info
    ///
    /// Provides information about a contract violation that can be used in a
    /// custom violation handler.
    ///
    class violation_info final
    {
    public:
        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param sloc the source location of the contract violation
        /// @param comm the comment associated with the contract violation
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr violation_info(sloc_type const &sloc, cstr_type const &comm) noexcept
            : m_sloc{sloc}, m_comm{comm}
        {}

        /// @brief location
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the source location of the contract violation
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr sloc_type const &
        location() const noexcept
        {
            return m_sloc;
        }

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the comment associated with the contract violation
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr cstr_type const &
        comment() const noexcept
        {
            return m_comm;
        }

    private:
        /// @brief stores the source location of the contract violation
        sloc_type m_sloc;
        /// @brief stores the comment associated with the contract violation
        cstr_type m_comm;
    };
}    // namespace bsl

#endif
