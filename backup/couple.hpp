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
/// @file couple.hpp
///

#ifndef BSL_COUPLE_HPP
#define BSL_COUPLE_HPP

#include "types.hpp"

namespace bsl
{
    /// @class bsl::couple
    ///
    /// <!-- description -->
    ///   @brief This is similar to std::pair, with the main difference being
    ///     that the bsl::couple is a trivial object. This means that some of
    ///     the functionality is different, but not much. The biggest
    ///     differences are no constructors, assignment operators or
    ///     make_pair() functions. Instead, treat this a as simple struct.
    ///   @include couple/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T0 defines the first resource stored is the bsl::couple.
    ///     T0 must be a trivial type.
    ///   @tparam T1 defines the first resource stored is the bsl::couple.
    ///     T1 must be a trivial type.
    ///
    template<typename T0, typename T1>
    class couple final
    {
        static_assert(std::is_trivial<T0>::value);
        static_assert(std::is_trivial<T1>::value);

    public:
        /// <!-- description -->
        ///   @brief Creates a default bsl::couple. The values of get0() and
        ///     get1() are undefined.
        ///   @include couple/constructor.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        constexpr couple() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a  bsl::couple given elem0 and elem1.
        ///   @include couple/constructor_values.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param elem0 the value to return from get0()
        ///   @param elem1 the value to return from get1()
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        constexpr couple(T0 const &elem0, T1 const &elem1) noexcept : m_elem0{elem0}, m_elem1{elem1}
        {}

        /// <!-- description -->
        ///   @brief Swaps the resources of two bsl::couple objects.
        ///   @include couple/swap.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param other the object to swap with
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        constexpr void
        swap(couple &other) noexcept
        {
            std::swap(m_elem0, other.m_elem0);
            std::swap(m_elem1, other.m_elem1);
        }

        /// <!-- description -->
        ///   @brief Returns the value provided to elem0 during construction
        ///   @include couple/get0.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value provided to elem0 during construction
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] constexpr T0 &
        get0() noexcept
        {
            return m_elem0;
        }

        /// <!-- description -->
        ///   @brief Returns the value provided to elem0 during construction
        ///   @include couple/get0.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value provided to elem0 during construction
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] constexpr T0 const &
        get0() const noexcept
        {
            return m_elem0;
        }

        /// <!-- description -->
        ///   @brief Returns the value provided to elem1 during construction
        ///   @include couple/get1.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value provided to elem1 during construction
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] constexpr T1 &
        get1() noexcept
        {
            return m_elem1;
        }

        /// <!-- description -->
        ///   @brief Returns the value provided to elem1 during construction
        ///   @include couple/get1.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value provided to elem1 during construction
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] constexpr T1 const &
        get1() const noexcept
        {
            return m_elem1;
        }

    private:
        /// @brief The first element stored in the bsl::couple
        T0 m_elem0;
        /// @brief The second element stored in the bsl::couple
        T1 m_elem1;
    };

    /// <!-- description -->
    ///   @brief Returns true if two bsl::couple objects are equal.
    ///   @include couple/comparison.cpp
    ///   @related bsl::couple
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T01 the type of the first element in the lhs bsl::couple
    ///   @tparam T02 the type of the second element in the lhs bsl::couple
    ///   @tparam T11 the type of the first element in the rhs bsl::couple
    ///   @tparam T12 the type of the second element in the rhs bsl::couple
    ///   @param lhs the left-hand side of the comparison
    ///   @param rhs the right-hand side of the comparison
    ///   @return true if the lhs is equal to the rhs, false otherwise
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    template<typename T01, typename T02, typename T11, typename T12>
    [[nodiscard]] constexpr bool
    operator==(couple<T01, T02> const &lhs, couple<T11, T12> const &rhs) noexcept
    {
        return (lhs.get0() == rhs.get0()) && (lhs.get1() == rhs.get1());
    }

    /// <!-- description -->
    ///   @brief Returns false if two bsl::couple objects are equal.
    ///   @include couple/comparison.cpp
    ///   @related bsl::couple
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T01 the type of the first element in the lhs bsl::couple
    ///   @tparam T02 the type of the second element in the lhs bsl::couple
    ///   @tparam T11 the type of the first element in the rhs bsl::couple
    ///   @tparam T12 the type of the second element in the rhs bsl::couple
    ///   @param lhs the left-hand side of the comparison
    ///   @param rhs the right-hand side of the comparison
    ///   @return false if the lhs is equal to the rhs, true otherwise
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    template<typename T01, typename T02, typename T11, typename T12>
    [[nodiscard]] constexpr bool
    operator!=(couple<T01, T02> const &lhs, couple<T11, T12> const &rhs) noexcept
    {
        return (lhs.get0() != rhs.get0()) || (lhs.get1() != rhs.get1());
    }
}    // namespace bsl

#endif
