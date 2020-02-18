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
/// @file result.hpp
///

#ifndef BSL_RESULT_HPP
#define BSL_RESULT_HPP

#include "details/result_type.hpp"

#include "construct_at.hpp"
#include "errc_type.hpp"
#include "in_place.hpp"
#include "move.hpp"
#include "source_location.hpp"
#include "swap.hpp"

#include "enable_if.hpp"
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
        static_assert(!is_same<T, void>::value);
        static_assert(!is_move_constructible<T>::value || is_nothrow_move_constructible<T>::value);
        static_assert(!is_move_constructible<E>::value || is_nothrow_move_constructible<E>::value);
        static_assert(is_trivially_destructible<E>::value);

    public:
        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by copying "t"
        ///   @include result/constructor_copy.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the value being copied
        ///   @return a new bsl::result
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's copy constructor throws
        ///
        explicit constexpr result(T const &t) noexcept    // PRQA S 2023
            : m_which{details::result_type::contains_t}, m_t{t}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T,
        ///     by moving "t"
        ///   @include result/constructor_move.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the value being moved
        ///   @return a new bsl::result
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's copy constructor throws
        ///
        explicit constexpr result(T &&t) noexcept    // PRQA S 2023
            : m_which{details::result_type::contains_t}, m_t{bsl::move(t)}
        {}

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains T by constructing
        ///     T in place.
        ///   @include result/constructor_in_place.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param ip provide bsl::in_place to construct in place
        ///   @param args the arguments to create T with
        ///   @return a new bsl::result
        ///
        /// <!-- exceptions -->
        ///   @throw throws if T's constructor throws
        ///
        template<typename... ARGS>
        constexpr result(bsl::in_place_t const &ip, ARGS &&... args) noexcept    // PRQA S 2023
            : m_which{details::result_type::contains_t}, m_t{bsl::forward<ARGS>(args)...}
        {
            bsl::discard(ip);
        }

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     by copying "e"
        ///   @include result/constructor_errc_copy.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param e the error code being copied
        ///   @param sloc the source location of the error
        ///   @return a new bsl::result
        ///
        /// <!-- exceptions -->
        ///   @throw throws if E's copy constructor throws
        ///
        constexpr result(E const &e, sloc_type const &sloc) noexcept    // PRQA S 2023
            : m_which{details::result_type::contains_e}, m_e{e}
        {
            bsl::discard(sloc);
        }

        /// <!-- description -->
        ///   @brief Constructs a bsl::result that contains E,
        ///     by moving "e"
        ///   @include result/constructor_errc_move.cpp
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param e the error code being moved
        ///   @param sloc the source location of the error
        ///   @return a new bsl::result
        ///
        /// <!-- exceptions -->
        ///   @throw throws if E's copy constructor throws
        ///
        constexpr result(E &&e, sloc_type const &sloc) noexcept    // PRQA S 2023
            : m_which{details::result_type::contains_e}, m_e{bsl::move(e)}
        {
            bsl::discard(sloc);
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///   @include result/constructor_copy.cpp
        ///
        ///   SUPPRESSION: PRQA 4285 - false positive
        ///   - We suppress this because A12-8-1 states a copy/move should
        ///     not have a side effect other than the copy/move itself.
        ///     This is a false positive because there are not side effects
        ///     in this code below. PRQA is not properly handling
        ///     the union as allowed by AUTOSAR.
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        ///   SUPPRESSION: PRQA 4050 - false positive
        ///   - We suppress this because A12-1-1 states that all member
        ///     variables should be explicitly initialized. It does not
        ///     state that they must be in the initializer list.
        ///     Furthermore, it is impossible to initialize union members
        ///     in an initializer list in a copy/move constructor, which
        ///     PRQA should be capable of detecting, and it doesn't.
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
        constexpr result(result const &o)    // PRQA S 4285, 2023
            : m_which{o.m_which}             // PRQA S 4050
        {
            if (details::result_type::contains_t == m_which) {
                construct_at<T>(&m_t, o.m_t);
            }
            else {
                construct_at<E>(&m_e, o.m_e);
            }
        }

        /// <!-- description -->
        ///   @brief move constructor
        ///   @include result/constructor_move.cpp
        ///
        ///   SUPPRESSION: PRQA 4285 - false positive
        ///   - We suppress this because A12-8-1 states a copy/move should
        ///     not have a side effect other than the copy/move itself.
        ///     This is a false positive because the only side effect is
        ///     the copy/move as required. PRQA is not properly handling
        ///     the union as allows by AUTOSAR.
        ///
        ///   SUPPRESSION: PRQA 2023 - exception required
        ///   - We suppress this because A13-3-1 states that you should not
        ///     overload functions that contain a forwarding reference because
        ///     it is confusing to the user. PRQA is detecting the presence of
        ///     the in place constructor. In this case, there is nothing
        ///     ambiguous about this situation as the user has to explicitly
        ///     state bsl::in_place, which disambiguated which constructor the
        ///     user is intending to use. It should be noted that objects like
        ///     std::pair, std::tuple and std::variant, which are all encouraged
        ///     by the spec have the same issue with this rule, so it is clear
        ///     it needs a better definition to ensure the library the spec
        ///     demands can actually be compliant with the spec itself.
        ///
        ///   SUPPRESSION: PRQA 4050 - false positive
        ///   - We suppress this because A12-1-1 states that all member
        ///     variables should be explicitly initialized. It does not
        ///     state that they must be in the initializer list.
        ///     Furthermore, it is impossible to initialize union members
        ///     in an initializer list in a copy/move constructor, which
        ///     PRQA should be capable of detecting, and it doesn't.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr result(result &&o) noexcept    // PRQA S 4285, 2023
            : m_which{o.m_which}                 // PRQA S 4050
        {
            if (details::result_type::contains_t == m_which) {
                construct_at<T>(&m_t, bsl::move(o.m_t));
            }
            else {
                construct_at<E>(&m_e, bsl::move(o.m_e));
            }
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
            if (details::result_type::contains_t == m_which) {
                destroy_at(&m_t);
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
            if (details::result_type::contains_t == lhs.m_which) {
                if (details::result_type::contains_t == rhs.m_which) {
                    bsl::swap(lhs.m_t, rhs.m_t);
                }
                else {
                    E tmp_e{bsl::move(rhs.m_e)};
                    construct_at<T>(&rhs.m_t, bsl::move(lhs.m_t));
                    destroy_at(&lhs.m_t);
                    construct_at<E>(&lhs.m_e, bsl::move(tmp_e));
                }
            }
            else {
                if (details::result_type::contains_t == rhs.m_which) {
                    E tmp_e{bsl::move(lhs.m_e)};
                    construct_at<T>(&lhs.m_t, bsl::move(rhs.m_t));
                    destroy_at(&rhs.m_t);
                    construct_at<E>(&rhs.m_e, bsl::move(tmp_e));
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
            if (details::result_type::contains_t == m_which) {
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
            if (details::result_type::contains_t == m_which) {
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
            if (details::result_type::contains_e == m_which) {
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
            return details::result_type::contains_t == m_which;
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
            return details::result_type::contains_e == m_which;
        }

    private:
        /// @brief stores which type the union stores
        details::result_type m_which;

        /// @brief Provides access to T or an error code
        ///
        ///   SUPPRESSION: PRQA 2176 - false positive
        ///   - We suppress this because A9-5-1 states that unions are
        ///     not allowed with the exception of tagged unions. In this
        ///     case, we have implemented a tagged union. We tried to keep
        ///     the implementation as close to the example in the spec as
        ///     possible, and PRQA is still not able to detect this.
        ///
        ///   SUPPRESSION: PRQA 2176 - false positive
        ///   - We suppress this because A2-7-3 states that all class members
        ///     should be documented. This is clearly documented.
        ///
        union    // PRQA S 2176, 2026
        {
            /// @brief stores T when not storing an error code
            T m_t;
            /// @brief stores an error code when not storing T
            E m_e;
        };
    };
}

#endif
