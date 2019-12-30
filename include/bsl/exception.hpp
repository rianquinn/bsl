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

#ifndef BSL_EXCEPTION_HPP
#define BSL_EXCEPTION_HPP

#include "source_location.hpp"

namespace bsl
{
    /// @class exception
    ///
    /// This class provides the base type for all exception types
    /// used by Bareflank.
    ///
    /// SUPPRESSION: PRQA 2659 - false positive
    /// - We suppress this because A12-8-6 is mutually exclusive with
    ///   A15-1-1. A12-8-6 states that you must only inherit from classes with
    ///   protected copy/move assignment operators, which std::exception
    ///   is not defined as, while A15-1-1 requires that all exceptions are
    ///   subclasses of std::exception. To address this, we inherit using
    ///   protected inheritance instead of public inheritance, which should
    ///   resolve the problem, but PRQA doesn't seem to detect this.
    ///
    class exception : protected std::exception    // PRQA S 2659
    {
    public:
        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param desc a description of the exception type
        /// @param comm a comment to add to the exception
        /// @param sloc the source location of the exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        exception(cstr_type const &desc, cstr_type const &comm, sloc_type const &sloc) noexcept
            : std::exception{}, m_desc{desc}, m_comm{comm}, m_sloc{sloc}
        {}

        /// @brief description
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return the description of the exception type
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] cstr_type const &
        description() const noexcept
        {
            return m_desc;
        }

        /// @brief comment
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return the comment added to the exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] cstr_type const &
        comment() const noexcept
        {
            return m_comm;
        }

        /// @brief location
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return the source location of the exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] sloc_type const &
        location() const noexcept
        {
            return m_sloc;
        }

        /// @brief what overload
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return the comment added to the exception
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] cstr_type
        what() const noexcept override
        {
            return m_comm;
        }

        /// @brief destructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~exception() noexcept override = default;

    protected:
        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        exception(exception const &o) noexcept = default;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be moved
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        exception(exception &&o) noexcept = default;

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
        [[maybe_unused]] exception &operator=(exception const &o) &noexcept = default;

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
        [[maybe_unused]] exception &operator=(exception &&o) &noexcept = default;

    private:
        /// @brief stores the name of the exception
        cstr_type m_desc;
        /// @brief stores the comment associated with this exception
        cstr_type m_comm;
        /// @brief store the source location associated with this exception
        sloc_type m_sloc;
    };

    /// @brief operator <<
    ///
    /// Provides support for outputing a bsl::source_location.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param os the stream to output the source location to
    /// @param e the exception to output
    /// @return a reference to the output stream provided
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    inline std::ostream &
    operator<<(std::ostream &os, exception const &e)
    {
        os << fmt::format("{}EXCEPTION THROWN{} ", bold_red, reset_color);
        if (nullptr != e.description()) {
            os << fmt::format("[{}{}{}]", white, e.description(), reset_color);
        }
        if (nullptr != e.comment()) {
            os << fmt::format(": {}", e.comment());
        }
        os << fmt::format("\n{}", e.location());

        return os;
    }
}    // namespace bsl

#endif
