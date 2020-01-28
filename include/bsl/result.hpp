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

#ifndef BSL_DETAILS_RESULT_HPP
#define BSL_DETAILS_RESULT_HPP

#include "errc_type.hpp"
#include "forward.hpp"
#include "in_place_t.hpp"
#include "move.hpp"
#include "new.hpp"
#include "swap.hpp"

#include "is_same.hpp"
#include "is_move_constructible.hpp"
#include "is_nothrow_move_constructible.hpp"
#include "is_trivially_destructible.hpp"

namespace bsl
{
    /// @class bsl::details::result
    ///
    /// <!-- description -->
    ///   @brief Provides the ability to return T or E from a function,
    ///     ensuring that T is only created if an error is not present.
    ///   @include result/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the nullable type
    ///   @tparam TAG the type used to store whether or not T is present
    ///
    template<typename T, typename E = errc_type<>>
    class result final
    {
        static_assert(!is_same<T, E>::value);
        static_assert(is_trivially_destructible<E>::value);
        static_assert(!is_move_constructible<T>::value || is_nothrow_move_constructible<T>::value);
        static_assert(!is_move_constructible<E>::value || is_nothrow_move_constructible<E>::value);

    public:
        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     my copying of "t"
        ///   @include result/constructor_copy_t.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the value being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's copy constructor throws
        ///
        explicit constexpr result(T const &t)    // PRQA S 2023
            : m_which{result_type::contains_t}, m_t{t}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     my moving "t"
        ///   @include result/constructor_move_t.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the value being moved
        ///
        explicit constexpr result(T &&t) noexcept    // PRQA S 2023
            : m_which{result_type::contains_t}, m_t{bsl::move(t)}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     my moving "t"
        ///   @include result/constructor_in_place_t.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip tells bsl::result to create T in place using T{args...}
        ///   @param args the arguments to create T with
        ///
        template<typename... ARGS>
        explicit constexpr result(in_place_t const ip, ARGS &&... args) noexcept // PRQA S 2023
            : m_which{result_type::contains_t}, m_t{bsl::forward<ARGS>(args)...}
        {
            bsl::discard(ip);
        }

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     my copying of "e"
        ///   @include result/constructor_copy_e.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param e the error code being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if E's copy constructor throws
        ///
        explicit constexpr result(E const &e)    // PRQA S 2023
            : m_which{result_type::contains_e}, m_e{e}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     my moving "e"
        ///   @include result/constructor_move_e.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param e the error code being moved
        ///
        explicit constexpr result(E &&e) noexcept    // PRQA S 2023
            : m_which{result_type::contains_e}, m_e{bsl::move(e)}
        {}

        /// <!-- description -->
        ///   @brief copy constructor
        ///   @include result/constructor_copy.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        ///   SUPPRESSION: PRQA 4285 - false positive
        ///   - We suppress this because A12-8-1 states a copy/move should
        ///     not have a side effect other than the copy/move itself.
        ///     This is a false positive because there are not side effects
        ///     in this code below. PRQA is not properly handling
        ///     the union as allowed by AUTOSAR.
        ///
        ///   SUPPRESSION: PRQA 4050 - false positive
        ///   - We suppress this because A12-1-1 states that all member
        ///     variables should be explicitly initialized. It does not
        ///     state that they must be in the initializer list.
        ///     Furthermore, it is impossible to initialize union members
        ///     in an initializer list in a copy/move constructor, which
        ///     PRQA should be capable of detecting.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T or E's copy constructor throws
        ///
        constexpr result(result const &o)    // PRQA S 4285 // PRQA S 2023
            : m_which{o.m_which}             // PRQA S 4050
        {
            if (result_type::contains_t == m_which) {
                details::initialize<T>(&m_t, o.m_t);
            }
            else {
                details::initialize<E>(&m_e, o.m_e);
            }
        }

        /// <!-- description -->
        ///   @brief move constructor
        ///   @include result/constructor_move.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states a you should not
        ///     overload any function that implements a forwarding reference.
        ///     Normally, we would make a new function, but since this is a
        ///     constructor, we have no choice but to overload. The use of
        ///     bsl::in_place_t specifically addresses the complaint in the
        ///     rule, and is the accepted solution in C++17
        ///
        ///   SUPPRESSION: PRQA 4285 - false positive
        ///   - We suppress this because A12-8-1 states a copy/move should
        ///     not have a side effect other than the copy/move itself.
        ///     This is a false positive because the only side effect is
        ///     the copy/move as required. PRQA is not properly handling
        ///     the union as allows by AUTOSAR.
        ///
        ///   SUPPRESSION: PRQA 4050 - false positive
        ///   - We suppress this because A12-1-1 states that all member
        ///     variables should be explicitly initialized. It does not
        ///     state that they must be in the initializer list.
        ///     Furthermore, it is impossible to initialize union members
        ///     in an initializer list in a copy/move constructor, which
        ///     PRQA should be capable of detecting.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr result(result &&o) noexcept    // PRQA S 4285 // PRQA S 2023
            : m_which{o.m_which}                 // PRQA S 4050
        {
            if (result_type::contains_t == m_which) {
                details::initialize<T>(&m_t, bsl::move(o.m_t));
            }
            else {
                details::initialize<E>(&m_e, bsl::move(o.m_e));
            }

            o.m_which = result_type::contains_e;
        }

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::result. Since
        ///     we require E to be trivially destructible, we only need to
        ///     call a destructor if this object contains a T
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~result() noexcept
        {
            if (result_type::contains_t == m_which) {
                m_t.T::~T();
            }
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///   @include result/assignment_copy.cpp
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
        ///   @throw throws if T or E's copy constructor throws
        ///
        [[maybe_unused]] constexpr result &
        operator=(result const &o) &
        {
            result tmp{o};
            exchange(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///   @include result/assignment_move.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr result &
            operator=(result &&o) &
            noexcept
        {
            result tmp{bsl::move(o)};
            exchange(*this, tmp);
            return *this;
        }

        /// <!-- description -->
        ///   @brief Exchanges (i.e., swaps) *this with other. We use the
        ///     name exchange instead of swap to prevent name collisions.
        ///   @include result/exchange.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param lhs the left hand side of the exchange
        ///   @param rhs the right hand side of the exchange
        ///
        static constexpr void
        exchange(result &lhs, result &rhs) noexcept
        {
            if (result_type::contains_t == lhs.m_which) {
                if (result_type::contains_t == rhs.m_which) {
                    bsl::swap(lhs.m_t, rhs.m_t);
                }
                else {
                    T tmp_t{bsl::move(lhs.m_t)};
                    E tmp_e{bsl::move(rhs.m_e)};
                    details::initialize<E>(&lhs.m_e, bsl::move(tmp_e));
                    details::initialize<T>(&rhs.m_t, bsl::move(tmp_t));
                }
            }
            else {
                if (result_type::contains_t == rhs.m_which) {
                    E tmp_e{bsl::move(lhs.m_e)};
                    T tmp_t{bsl::move(rhs.m_t)};
                    details::initialize<T>(&lhs.m_t, bsl::move(tmp_t));
                    details::initialize<E>(&rhs.m_e, bsl::move(tmp_e));
                }
                else {
                    bsl::swap(lhs.m_e, rhs.m_e);
                }
            }

            bsl::swap(lhs.m_which, rhs.m_which);
        }

        /// <!-- description -->
        ///   @brief Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///   @include result/get_if.cpp
        ///
        ///   SUPPRESSION: PRQA 4024 - false positive - non-automated
        ///   - We suppress this because A9-3-1 states that a class should
        ///     not return a non-const handle to an object. AUTOSAR
        ///     provides an exception for classes that mimic a smart
        ///     pointer or a container, which is what this class is doing.
        ///     It should be noted that such exceptions are likely not
        ///     detectable by PRQA, and thus, this suppression will likely
        ///     always be required.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        constexpr T *
        get_if() noexcept
        {
            if (result_type::contains_t == m_which) {
                return &m_t;    // PRQA S 4024
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///   @include result/get_if.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a handle to T if this object contains T,
        ///     otherwise it returns a nullptr.
        ///
        constexpr T const *
        get_if() const noexcept
        {
            if (result_type::contains_t == m_which) {
                return &m_t;
            }

            return nullptr;
        }

        /// <!-- description -->
        ///   @brief Returns an error code if this object contains E,
        ///     otherwise it returns "fallback".
        ///   @include result/errc.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param fallback returned if this bsl::result contains T
        ///   @return Returns an error code if this object contains E,
        ///     otherwise it returns "or".
        ///
        constexpr E
        errc(E const &fallback = E{}) const noexcept
        {
            if (result_type::contains_e == m_which) {
                return m_e;
            }

            return fallback;
        }

        /// <!-- description -->
        ///   @brief Returns true if the bsl::result contains T,
        ///     otherwise, if the bsl::result contains an error code,
        ///     returns false.
        ///   @include result/success.cpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the bsl::result contains T,
        ///     otherwise, if the bsl::result contains an error code,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        success() const noexcept
        {
            return result_type::contains_t == m_which;
        }

        /// <!-- description -->
        ///   @brief Returns true if the bsl::result contains E,
        ///     otherwise, if the bsl::result contains T,
        ///     returns false.
        ///   @include result/failure.cpp
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if the bsl::result contains E,
        ///     otherwise, if the bsl::result contains T,
        ///     returns false.
        ///
        [[nodiscard]] constexpr bool
        failure() const noexcept
        {
            return result_type::contains_e == m_which;
        }

    private:
        /// @brief defines what type the union stores
        enum class result_type : bsl::uint8
        {
            contains_t,
            contains_e
        };

        /// @brief stores which type the union stores
        result_type m_which;

        /// @brief Provides access to T or an error code
        ///
        ///   SUPPRESSION: PRQA 2176 - false positive
        ///   - We suppress this because A9-5-1 states that unions are
        ///     not allowed with the exception of tagged unions. In this
        ///     case, we have implemented a tagged union. We tried to keep
        ///     the implementation as close to the example in the spec as
        ///     possible, and PRQA is still not able to detect this.
        ///
        union    // PRQA S 2176
        {
            /// @brief stores T when not storing an error code
            T m_t;
            /// @brief stores an error code when not storing T
            E m_e;
        };
    };
}

#endif
