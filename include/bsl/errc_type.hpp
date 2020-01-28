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
/// @file errc_type.hpp
///

#ifndef BSL_ERRC_TYPE_HPP
#define BSL_ERRC_TYPE_HPP

#include "cstdint.hpp"
#include "cstr_type.hpp"
#include "discard.hpp"
#include "move.hpp"

namespace bsl
{
    /// @class
    ///
    /// <!-- description -->
    ///   @brief Defines an error code. We do not use the same pattern as the
    ///     standard library. The goal is to ensure an error code can consume
    ///     a single register to ensure maximum compatibility with different
    ///     CPU archiectures that only have a 32bit return register. We also do
    ///     not use an enum to ensure custom error codes can be created. This
    ///     also means there are not error code categories. Instead, an error
    ///     code is checked if it is negative, and unchecked if it is positive
    ///     to align with AUTOSAR. Finally, we provide the ability to change
    ///     the type that an error code uses under the hood which allows you
    ///     to use a "long" type, or some other integer type depending on your
    ///     requirements.
    ///   @include error_type/overview.cpp
    ///
    template<typename T = bsl::int32, T SUCCESS = 0>
    class errc_type final
    {
    public:
        /// <!-- description -->
        ///   @brief Value initialization constructor
        ///   @include errc_type/value_constructor.cpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param errc the error code to store
        ///
        explicit constexpr errc_type(T const &errc = SUCCESS) noexcept    // --
            : m_errc{errc}
        {}

        /// <!-- description -->
        ///   @brief Returns the integer value that represents the error code.
        ///     Normally, this function should not be used, and instead, you
        ///     should use the other functions like ==, !=, operator bool(),
        ///     is_checked() and is_unchecked().
        ///   @include errc_type/get.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the integer value that represents the error code.
        ///
        [[nodiscard]] constexpr T const &
        get() const noexcept
        {
            return m_errc;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code contains SUCCESS,
        ///     otherwise, if the error code contains an error code,
        ///     returns false.
        ///   @include errc_type/success.cpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code contains SUCCESS,
        ///     otherwise, if the error code contains an error code,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        success() const noexcept
        {
            return m_errc == SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code contains an error code,
        ///     otherwise, if the error code contains SUCCESS,
        ///     returns false.
        ///   @include errc_type/failure.cpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code contains an error code,
        ///     otherwise, if the error code contains SUCCESS,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        failure() const noexcept
        {
            return m_errc != SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code is a checked error (i.e.,
        ///     that is the error code is negative), false otherwise. If this
        ///     error code is bsl::errc_success, returns false.
        ///   @include errc_type/is_checked.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code is a checked error (i.e.,
        ///     that is the error code is negative), false otherwise. If this
        ///     error code is bsl::errc_success, returns false.
        ///
        [[nodiscard]] constexpr bool
        is_checked() const noexcept
        {
            return m_errc < 0;
        }

        /// <!-- description -->
        ///   @brief Returns true if the error code is an unchecked error
        ///     (i.e., that is the error code is positive), false otherwise.
        ///     If this error code is bsl::errc_success, returns false.
        ///   @include errc_type/is_unchecked.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the error code is an unchecked error
        ///     (i.e., that is the error code is positive), false otherwise.
        ///     If this error code is bsl::errc_success, returns false.
        ///
        [[nodiscard]] constexpr bool
        is_unchecked() const noexcept
        {
            return m_errc > 0;
        }

        /// <!-- description -->
        ///   @brief Returns a human readable version of the error code. If
        ///     the error code is a custom, user defined error code, returns
        ///     a nullptr.
        ///   @include errc_type/message.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a human readable version of the error code. If
        ///     the error code is a custom, user defined error code, returns
        ///     a nullptr.
        ///
        [[nodiscard]] constexpr cstr_type message() const noexcept;

    private:
        /// @brief stores the error code
        T m_errc;
    };

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include errc_type/operator_equal.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T1, T1 SUCCESS1, typename T2, T2 SUCCESS2>
    constexpr bool
    operator==(errc_type<T1, SUCCESS1> const &lhs, errc_type<T2, SUCCESS2> const &rhs) noexcept
    {
        return lhs.get() == rhs.get();
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include errc_type/operator_equal.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T1, T1 SUCCESS1, typename T2, T2 SUCCESS2>
    constexpr bool
    operator!=(errc_type<T1, SUCCESS1> const &lhs, errc_type<T2, SUCCESS2> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include errc_type/operator_equal.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T1, T1 SUCCESS1, typename T2>
    constexpr bool
    operator==(errc_type<T1, SUCCESS1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs.get() == rhs;
    }

    /// <!-- description -->
    ///   @brief Returns true if the lhs is equal to the rhs, false otherwise
    ///   @include errc_type/operator_equal.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns true if the lhs is equal to the rhs, false otherwise
    ///
    template<typename T1, typename T2, T2 SUCCESS2>
    constexpr bool
    operator==(T1 const &lhs, errc_type<T2, SUCCESS2> const &rhs) noexcept
    {
        return lhs == rhs.get();
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include errc_type/operator_equal.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T1, T1 SUCCESS1, typename T2>
    constexpr bool
    operator!=(errc_type<T1, SUCCESS1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs.get() != rhs;
    }

    /// <!-- description -->
    ///   @brief Returns false if the lhs is equal to the rhs, true otherwise
    ///   @include errc_type/operator_equal.cpp
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the operator
    ///   @param rhs the right hand side of the operator
    ///   @return Returns false if the lhs is equal to the rhs, true otherwise
    ///
    template<typename T1, typename T2, T2 SUCCESS2>
    constexpr bool
    operator!=(T1 const &lhs, errc_type<T2, SUCCESS2> const &rhs) noexcept
    {
        return lhs != rhs.get();
    }
}

// -----------------------------------------------------------------------------
// Pre-defined Error Codes
// -----------------------------------------------------------------------------

namespace bsl
{
    /// @brief Defines the "no error" case
    constexpr errc_type<> errc_success{};
    /// @brief Defines the general unchecked error case
    constexpr errc_type<> errc_failure{1};
    /// @brief Defines the general precondition error case
    constexpr errc_type<> errc_precondition{2};
    /// @brief Defines the general postcondition error case
    constexpr errc_type<> errc_postcondition{3};
    /// @brief Defines the general assertion error case
    constexpr errc_type<> errc_assetion{4};

    /// @brief Defines an invalid argument error code
    constexpr errc_type<> errc_invalid_argument{10};
    /// @brief Defines an out of bounds error code
    constexpr errc_type<> errc_index_out_of_bounds{11};

    /// @brief Defines an overflow, underflow or unsigned wrap error
    constexpr errc_type<> errc_unsigned_wrap{30};
    /// @brief Defines an overflow, underflow or unsigned wrap error
    constexpr errc_type<> errc_narrow_overflow{31};
    /// @brief Defines an overflow, underflow or unsigned wrap error
    constexpr errc_type<> errc_signed_overflow{32};
    /// @brief Defines a divide by zero error
    constexpr errc_type<> errc_divide_by_zero{33};
    /// @brief Defines an out of bounds error code
    constexpr errc_type<> errc_nullptr_dereference{34};
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bsl
{
    template<typename T, T SUCCESS>
    [[nodiscard]] constexpr cstr_type
    errc_type<T, SUCCESS>::message() const noexcept
    {
        cstr_type msg{};

        switch (m_errc) {
            case errc_success.get(): {
                msg = "success";
                break;
            }

            case errc_failure.get(): {
                msg = "general failure";
                break;
            }

            case errc_precondition.get(): {
                msg = "general precondition failure";
                break;
            }

            case errc_postcondition.get(): {
                msg = "general postcondition failure";
                break;
            }

            case errc_assetion.get(): {
                msg = "general assertion failure";
                break;
            }

            case errc_invalid_argument.get(): {
                msg = "invalid argument (precondition) failure";
                break;
            }

            case errc_index_out_of_bounds.get(): {
                msg = "index out of bounds (precondition) failure";
                break;
            }

            case errc_unsigned_wrap.get(): {
                msg = "unsigned wrap (assertion) failure";
                break;
            }

            case errc_narrow_overflow.get(): {
                msg = "narrow overflow (assertion) failure";
                break;
            }

            case errc_signed_overflow.get(): {
                msg = "signed overflow (assertion) failure";
                break;
            }

            case errc_divide_by_zero.get(): {
                msg = "divide by zero (assertion) failure";
                break;
            }

            case errc_nullptr_dereference.get(): {
                msg = "null dereference (assertion) failure";
                break;
            }

            default: {
                break;
            }
        }

        return msg;
    }
}

#endif
