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
/// @file exception.hpp
///

#ifndef BSL_EXCEPTION_HPP
#define BSL_EXCEPTION_HPP

#include "source_location.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This class provides the base type for all exceptions
    ///     types used by Bareflank
    ///   @include checked_error/overview.cpp
    ///
    ///   SUPPRESSION: PRQA 2659 - false positive
    ///   - We suppress this because A12-8-6 is mutually exclusive with
    ///     A15-1-1. A12-8-6 states that you must inherit from classes with
    ///     protected copy/move assignment operators, which std::exception
    ///     is not defined as, while A15-1-1 requires that all exceptions are
    ///     subclasses of std::exception. To address this, we inherit using
    ///     protected inheritance instead of public inheritance, which should
    ///     resolve the problem, but PRQA doesn't seem to detect this.
    ///
    class exception : protected std::exception    // PRQA S 2659
    {
    public:
        /// <!-- description -->
        ///   @brief Constructs a bsl::exception
        ///   @include exception/constructor_desc_comm_sloc.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param desc a description of the exception type
        ///   @param comm a comment to add to the exception
        ///   @param sloc the source location of the exception
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        exception(
            cstr_type const &desc,
            cstr_type const &comm,
            sloc_type const &sloc = bsl::here()) noexcept
            : std::exception{}, m_desc{desc}, m_comm{comm}, m_sloc{sloc}
        {}

        /// <!-- description -->
        ///   @brief Returns the description of the exception
        ///   @include exception/description.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns a description of the exception
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] cstr_type const &
        description() const noexcept
        {
            return m_desc;
        }

        /// <!-- description -->
        ///   @brief Returns the comment associated with the exception. Note
        ///     that this is the same as what()
        ///   @include exception/comment.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the comment associated with the exception
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] cstr_type const &
        comment() const noexcept
        {
            return m_comm;
        }

        /// <!-- description -->
        ///   @brief Returns the location associated with the exception
        ///   @include exception/location.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the location associated with the exception
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] sloc_type const &
        location() const noexcept
        {
            return m_sloc;
        }

        /// <!-- description -->
        ///   @brief Returns the comment associated with the exception. Note
        ///     that this is the same as comment()
        ///   @include exception/what.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the comment associated with the exception
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] cstr_type
        what() const noexcept override
        {
            return m_comm;
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::exception
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        ~exception() noexcept override = default;

    protected:
        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        exception(exception const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        exception(exception &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[maybe_unused]] exception &operator=(exception const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[maybe_unused]] exception &operator=(exception &&o) &noexcept = default;

    private:
        /// @brief stores the name of the exception
        cstr_type m_desc;
        /// @brief stores the comment associated with the exception
        cstr_type m_comm;
        /// @brief stores the location associated with the exception
        sloc_type m_sloc;
    };

    /// <!-- description -->
    ///   @brief Inserts the value of the exception e into the output stream os
    ///   @include exception/operator_left_shift.cpp
    ///   @related bsl::exception
    ///
    /// <!-- notes -->
    ///   @note This function not only provides support for std::cout, it
    ///     also provides support for fmt::print and BSL debug statements
    ///     which are the preferred output mechanisms.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param os the output stream to insert e into
    ///   @param e the exception to insert into the output stream os
    ///   @return a reference to the output stream os
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] possible
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
