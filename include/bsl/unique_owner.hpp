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

#ifndef BSL_UNIQUE_OWNER_HPP
#define BSL_UNIQUE_OWNER_HPP

#include "nodelete.hpp"
#include "fmt.hpp"

namespace bsl
{

    /// @class unique_owner
    ///
    /// Unlike the gsl::owner, ths bsl::unique_owner is not a decoration, but
    /// instead provides the facilities for actually owning a resource.
    /// Specifically, if you "own" a resource, you are responsible for
    /// releasing or freeing the resource when you lose scope. The gsl::owner
    /// goes against the C++ Core Guidelines as it encourages the use of an
    /// owner whose lifetime is not tied to the lifetime of the owner. The
    /// bsl::unique_owner addresses this issue by mimicing the std::unique_ptr
    /// APIs, which means that the bsl::unique_owner is not a drop in
    /// replacement for a gsl::owner as you must execute get() to get access
    /// to the resource that it owns. Some other issues with the gsl::owner
    /// include the following:
    /// - you can copy a gsl::owner
    /// - the gsl::owner does not require a move on construction, resulting
    ///   in a copy.
    /// - a move of a gsl::owner does not properly initialize the object being
    ///   moved from, resulting in a copy
    ///
    /// It should be noted that we do not 100% mimic the std::unique_ptr, as
    /// it has some functionality that is really never used, and just
    /// overcomplicates things. For example, we require that the deleter is
    /// default constructable, and we do not provide constructor overloads for
    /// providing deleters with non-default construction. This feature is
    /// likely never used, evidence by the fact that make_unique doesn't even
    /// support it either. We also require that a default constructed T
    /// denotes the "invalid" state. If get() == T{}, the deleter is not called
    /// on destruction.
    ///
    /// EXPECTS: --
    /// - T is trivial
    /// - If get() == T{}, D() is not called on destruction
    ///
    template<typename T, typename D = bsl::nodelete<T>>
    class unique_owner final : public D
    {
        static_assert(std::is_trivial<T>::value);

    public:
        // ---------------------------------------------------------------------
        // Member Types

        /// @brief the type of resource being owned
        using value_type = T;
        /// @brief a reference to the type of resource being owned
        using reference = T &;
        /// @brief a const reference to the type of resource being owned
        using const_reference = T const &;
        /// @brief the type of Deleter used by this class
        using deleter_type = D;

        // ---------------------------------------------------------------------
        // Constructors/Destructors/Assignment

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr unique_owner() noexcept    // --
            : D{}, m_val{}
        {}

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr unique_owner(unique_owner const &o) noexcept = delete;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param val the value of type T to be copied
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr unique_owner(value_type const &val) noexcept = delete;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param other the object to be moved
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr unique_owner(unique_owner &&other) noexcept    // --
            : D{}, m_val{std::forward<value_type>(other.m_val)}
        {
            other.m_val = {};
        }

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param val the value of type T to be moved
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr unique_owner(value_type &&val) noexcept    // --
            : D{}, m_val{std::forward<value_type>(val)}
        {
            val = {};
        }

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
        constexpr unique_owner &operator=(unique_owner const &o) &noexcept = delete;

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param val the value of type T to be copied
        /// @return a reference to the newly copied object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr unique_owner &operator=(value_type const &val) &noexcept = delete;

        // clang-format off

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param other the object to be moved
        /// @return a reference to the newly moved object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[maybe_unused]] constexpr unique_owner &
        operator=(unique_owner &&other) &noexcept
        {
            if (*this == other) {
                return *this;
            }

            m_val = std::move(other.m_val);
            other.m_val = {};

            return *this;
        }

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param val the value of type T to be moved
        /// @return a reference to the newly moved object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[maybe_unused]] constexpr unique_owner &
        operator=(value_type &&val) &noexcept
        {
            m_val = std::move(val);
            val = {};

            return *this;
        }

        // clang-format on

        /// @brief destructor
        ///
        /// Destroys the resource owned by the owner by calling the Deleter
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~unique_owner() noexcept
        {
            if constexpr (!std::is_same<D, nodelete<T>>::value) {
                if (m_val != T{}) {
                    D::operator()(std::move(m_val));
                }
            }
        }

        // ---------------------------------------------------------------------
        // Modifiers

        /// @brief swap
        ///
        /// Swaps the contents of two unique_owner objects
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param other the unique_owner to swap with
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr void
        swap(T &other) noexcept
        {
            std::swap(m_val, other.m_val);
        }

        // ---------------------------------------------------------------------
        // Observers

        /// @brief get
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the contents of the resourece owned by the
        ///     unique_owner
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr const_reference
        get() const noexcept
        {
            return m_val;
        }

        /// @brief operator bool
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns true if the bsl::unique_owner owns a valid resource,
        ///     false otherwise
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] explicit constexpr operator bool() const noexcept
        {
            return m_val != T{};
        }

    private:
        /// @brief store the resource owned by the unique_owner
        value_type m_val;
    };

    /// @brief comparison ==
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left-hand side of the comparison
    /// @param rhs the right-hand side of the comparison
    /// @return true if the lhs and rhs are equal, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename T1, typename D1, typename T2, typename D2>
    [[nodiscard]] constexpr bool
    operator==(unique_owner<T1, D1> const &lhs, unique_owner<T2, D2> const &rhs) noexcept
    {
        return lhs.get() == rhs.get();
    }

    /// @brief comparison !=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left-hand side of the comparison
    /// @param rhs the right-hand side of the comparison
    /// @return false if the lhs and rhs are equal, true otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename T1, typename D1, typename T2, typename D2>
    [[nodiscard]] constexpr bool
    operator!=(unique_owner<T1, D1> const &lhs, unique_owner<T2, D2> const &rhs) noexcept
    {
        return lhs.get() != rhs.get();
    }
}    // namespace bsl

#endif
