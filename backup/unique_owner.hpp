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
/// @file unique_owner.hpp
///

#ifndef BSL_UNIQUE_OWNER_HPP
#define BSL_UNIQUE_OWNER_HPP

#include "fmt.hpp"

namespace bsl
{
    /// @brief the type definition for a deleter used by the bsl::unique_owner
    template<typename T>
    using deleter_type = void (*)(T &&) noexcept;

    /// <!-- description -->
    ///   @brief Unlike the gsl::owner, ths bsl::unique_owner is not a
    ///     decoration, but instead provides the facilities for actually owning
    ///     a resource. Specifically, if you "own" a resource, you are
    ///     responsible for releasing or freeing the resource when you lose
    ///     scope. Some improvements over the gsl::owner include:
    ///     - we do not allow the bsl::unique_owner to be copied, similar to
    ///       a std::unique_ptr.
    ///     - we require a "move" of the resource being owned. This is an
    ///       additional improvement over the std::unique_ptr which
    ///       constructs using a copy.
    ///     - unlike the gsl::owner, the bsl::unique_owner acts like a
    ///       std:unique_ptr, meaning a move ensures only one owner owns
    ///       the resource.
    ///     - unlike a std::unique_ptr, we allow any trivial type to be owned
    ///       which means you can, for example, own a structure that contains
    ///       more than one resource, ensuring you can own a ptr and size
    ///       without them having to be maintained separately.
    ///
    ///   @par Example:
    ///   @include unique_owner/overview.cpp
    ///
    /// <!-- notes -->
    ///   @note We do not fully mimic the std::unique_ptr, purposely leaving
    ///     out functions that over complicate the APIs like deleter
    ///     constructors, reset(), release(), get_deleter(), etc. This is all
    ///     done intentionally.
    ///   @note If the type T that you provide is a trival class or struct,
    ///     you might need to provide a custom operator==().
    ///
    /// <!-- template parameters -->
    ///   @tparam T denotes the type of resource being owned. T must be a
    ///     trivial type, and T{} must denote the default "invalid" state.
    ///     If get() == T{}, the deleter will not be called on destruction.
    ///
    template<typename T, deleter_type<T> D = discard<T>>
    class unique_owner final
    {
        static_assert(std::is_trivial<T>::value);
        static_assert(D != nullptr);

    public:
        /// <!-- description -->
        ///   @brief Creates a default bsl::unique_owner with an invalid state
        ///   @include unique_owner/constructor.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        constexpr unique_owner() noexcept : m_val{}
        {}

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
        unique_owner(unique_owner const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the value being copied
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        explicit unique_owner(T const &v) noexcept = delete;

        /// <!-- description -->
        ///   @brief Moves one bsl::unique_owner to another. Note that once
        ///     a move takes place, the bsl::unique_owner being moved from
        ///     is no longer valid and should not be used.
        ///   @include unique_owner/move_constructor_other.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param other the object being moved
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        constexpr unique_owner(unique_owner &&other) noexcept
        {
            m_val = other.m_val;
            other.m_val = {};
        }

        /// <!-- description -->
        ///   @brief Moves the provided value to the bsl::unique_owner so that
        ///     the bsl::unique_owner can take ownship. After the execute of
        ///     this function, the value being moved will be equal to T{} and
        ///     should not be used.
        ///   @include unique_owner/move_constructor_value.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value being moved
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        explicit constexpr unique_owner(T &&val) noexcept : m_val{val}
        {
            val = {};
        }

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
        unique_owner &operator=(unique_owner const &o) &noexcept = delete;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param v the value being copied
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        unique_owner &operator=(T const &v) &noexcept = delete;

        // clang-format off

        /// <!-- description -->
        ///   @brief Moves one bsl::unique_owner to another. Note that once
        ///     a move takes place, the bsl::unique_owner being moved from
        ///     is no longer valid and should not be used.
        ///   @include unique_owner/move_assignment_other.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param other the object being moved
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[maybe_unused]] constexpr unique_owner &
        operator=(unique_owner &&other) &noexcept
        {
            unique_owner tmp(std::move(other));
            this->swap(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Moves the provided value to the bsl::unique_owner so that
        ///     the bsl::unique_owner can take ownship. After the execute of
        ///     this function, the value being moved will be equal to T{} and
        ///     should not be used.
        ///   @include unique_owner/move_assignment_value.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value being moved
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[maybe_unused]] constexpr unique_owner &
        operator=(T &&val) &noexcept
        {
            T tmp(std::move(val));
            std::swap(m_val, tmp);
            return *this;
        }

        // clang-format on

        /// <!-- description -->
        ///   @brief Destroys the bsl::unique_owner. WHen this occurs, if
        ///     !(get() == T{}), T is destroyed by calling the provided
        ///     Deleter. By default this does nothing. If a Deleter is provided
        ///     the deleter is given the value returned to by get() using a
        ///     move indicating that the Deleter now owns the resource.
        ///   @include unique_owner/destructor.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        ~unique_owner() noexcept
        {
            if (!(this->get() == T{})) {
                D(std::move(m_val));
            }
        }

        /// <!-- description -->
        ///   @brief Swaps the resources of two bsl::unique_owner objects.
        ///   @include unique_owner/swap.cpp
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
        swap(unique_owner &other) noexcept
        {
            std::swap(m_val, other.m_val);
        }

        /// <!-- description -->
        ///   @brief Returns a constant reference to the resource owned by
        ///     the bsl::unique_owner
        ///   @include unique_owner/get.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns a constant reference to the resource owned by
        ///     the bsl::unique_owner
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] constexpr T const &
        get() const noexcept
        {
            return m_val;
        }

        /// <!-- description -->
        ///   @brief Returns whether or not the resource owned by the
        ///     bsl::unique_owner is valid or not. This is equivalent to
        ///     !(get() == T{}).
        ///   @include unique_owner/operator_bool.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns true if the resource owned by the
        ///     bsl::unique_owner is valid, false otherwise.
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return !(this->get() == T{});
        }

    private:
        /// @brief store the resource owned by the unique_owner
        T m_val;
    };

    /// <!-- description -->
    ///   @brief Returns true if two bsl::unique_owner objects are equal. This
    ///     is the same as lhs.get() == rhs.get()
    ///   @include unique_owner/comparison.cpp
    ///   @related bsl::unique_owner
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of resource owned by the lhs bsl::unique_owner
    ///   @tparam D1 the Deleter used by the lhs bsl::unique_owner
    ///   @tparam T2 the type of resource owned by the rhs bsl::unique_owner
    ///   @tparam D2 the Deleter used by the rhs bsl::unique_owner
    ///   @param lhs the left-hand side of the comparison
    ///   @param rhs the right-hand side of the comparison
    ///   @return true if the lhs is equal to the rhs, false otherwise
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    template<typename T1, deleter_type<T1> D1, typename T2, deleter_type<T2> D2>
    [[nodiscard]] constexpr bool
    operator==(unique_owner<T1, D1> const &lhs, unique_owner<T2, D2> const &rhs) noexcept
    {
        return lhs.get() == rhs.get();
    }

    /// <!-- description -->
    ///   @brief Returns false if two bsl::unique_owner objects are equal. This
    ///     is the same as !(lhs.get() == rhs.get())
    ///   @include unique_owner/comparison.cpp
    ///   @related bsl::unique_owner
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type of resource owned by the lhs bsl::unique_owner
    ///   @tparam D1 the Deleter used by the lhs bsl::unique_owner
    ///   @tparam T2 the type of resource owned by the rhs bsl::unique_owner
    ///   @tparam D2 the Deleter used by the rhs bsl::unique_owner
    ///   @param lhs the left-hand side of the comparison
    ///   @param rhs the right-hand side of the comparison
    ///   @return false if the lhs is equal to the rhs, true otherwise
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    template<typename T1, deleter_type<T1> D1, typename T2, deleter_type<T2> D2>
    [[nodiscard]] constexpr bool
    operator!=(unique_owner<T1, D1> const &lhs, unique_owner<T2, D2> const &rhs) noexcept
    {
        return !(lhs.get() == rhs.get());
    }

    /// <!-- description -->
    ///   @brief Implements std::swap for a bsl::unique_owner
    ///   @related bsl::unique_owner
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam T1 the type owned by the lhs
    ///   @tparam D1 the deleter type owned by the lhs
    ///   @tparam T2 the type owned by the rhs
    ///   @tparam D2 the deleter type owned by the rhs
    ///   @param lhs the left-hand side of the swap
    ///   @param rhs the right-hand side of the swap
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    template<typename T1, bsl::deleter_type<T1> D1, typename T2, bsl::deleter_type<T2> D2>
    constexpr void
    swap(bsl::unique_owner<T1, D1> const &lhs, bsl::unique_owner<T2, D2> const &rhs) noexcept
    {
        lhs.swap(rhs);
    }
}    // namespace bsl

#endif
