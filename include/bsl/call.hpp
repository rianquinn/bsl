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
/// @file call.hpp
///

#ifndef BSL_CALL_HPP
#define BSL_CALL_HPP

#include "details/call_impl.hpp"
#include "forward.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Invokes the callable object "f".
    ///   @include example_call_overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre expects func != nullptr. Note that this pre-condition is
    ///     not validated as there is no way to report an error. We do
    ///     provide safe_call() versions of call() that resolve this
    ///     issue and should be used instead. call() is only provided
    ///     to ensure support with 3rd party libraries.
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam FUNC the type that defines the function being called
    ///   @param f a pointer to the function being called.
    ///   @return Returns the result of calling "f".
    ///
    template<typename FUNC>
    constexpr auto
    call(FUNC &&f) noexcept(// PRQA S 2023
        noexcept(details::call_impl<FUNC, void>::call(bsl::forward<FUNC>(f))))
        -> decltype(details::call_impl<FUNC, void>::call(bsl::forward<FUNC>(f)))
    {
        return details::call_impl<FUNC, void>::call(bsl::forward<FUNC>(f));
    }

    /// <!-- description -->
    ///   @brief Invokes the callable object "f" with arguments "tn".
    ///   @include example_call_overview.hpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because
    ///     it is confusing to the user. The call function as defined by
    ///     the C++ specification is violating this rule. Since this function
    ///     is used a lot, we have no choice but to implement it as is. A
    ///     better implementation of this function should have been to provide
    ///     two different versions, one for functions and one for member
    ///     functions, which would remove the need for this violation. As it
    ///     is today, call is confusing as it doesn't explicitly define
    ///     which parameter should be the
    ///
    /// <!-- contracts -->
    ///   @pre expects func != nullptr. Note that this pre-condition is
    ///     not validated as there is no way to report an error. We do
    ///     provide safe_call() versions of call() that resolve this
    ///     issue and should be used instead. call() is only provided
    ///     to ensure support with 3rd party libraries.
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam FUNC the type that defines the function being called
    ///   @tparam T1 the type that defines the provided object. If f is not a
    ///     member pointer or member object, T1 defines type of the first
    ///     argument passed to f.
    ///   @tparam TN the types that define the arguments passed to the
    ///     provided function when called.
    ///   @param f a pointer to the function being called.
    ///   @param t1 a reference, reference wrapper or pointer to the object
    ///     for which the function is called from. If f is not a member
    ///     pointer or member object, t1 is the first argument passed to
    ///     f.
    ///   @param tn the arguments passed to the function f when called.
    ///   @return Returns the result of calling "f" from "t1" with "tn"
    ///
    template<typename FUNC, typename T1, typename... TN>
    constexpr auto
    call(FUNC &&f, T1 &&t1, TN &&... tn) noexcept(    // PRQA S 2023
        noexcept(details::call_impl<FUNC, T1>::call(
            bsl::forward<FUNC>(f), bsl::forward<T1>(t1), bsl::forward<TN>(tn)...)))
        -> decltype(details::call_impl<FUNC, T1>::call(
            bsl::forward<FUNC>(f), bsl::forward<T1>(t1), bsl::forward<TN>(tn)...))
    {
        return details::call_impl<FUNC, T1>::call(
            bsl::forward<FUNC>(f), bsl::forward<T1>(t1), bsl::forward<TN>(tn)...);
    }
}

#endif
