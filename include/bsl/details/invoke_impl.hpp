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

#ifndef BSL_DETAILS_INVOKE_IMPL_HPP
#define BSL_DETAILS_INVOKE_IMPL_HPP

#include "../decay.hpp"
#include "../forward.hpp"
#include "../invoke_result.hpp"
#include "../is_base_of.hpp"
#include "../is_reference_wrapper.hpp"

namespace bsl
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements INVOKE as defined by the C++ specification.
        ///     Note that we use the name invoke_mfp as INVOKE is not
        ///     compliant with AUTOSAR as the only difference with the name
        ///     is the use of capitalization. Specifically, this is the
        ///     member function pointer variant of INVOKE which, given a
        ///     function, an object and a set of args will call the function.
        ///
        /// <!-- contracts -->
        ///   @pre expects func != nullptr. Note that this pre-condition is
        ///     not validated as there is no way to report an error. We do
        ///     provide safe_invoke() versions of invoke() that result this
        ///     issue and should be used instead. invoke() is only provided
        ///     to ensure support with 3rd party libraries.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam F the type that defines the function being called
        ///   @tparam U the type that defines the class that encapsulates the
        ///     function being called.
        ///   @tparam T the type that defines the provided object. Note that
        ///     normally, U == T, but if inheritance is used, it might not
        ///     which is why U is provided instead of just using T.
        ///   @tparam ARGS the types that define the arguments passed to the
        ///     provided function when called.
        ///   @param func a pointer to the function to call.
        ///   @param t the object that encapsulates the provided function.
        ///   @param a the arguments to pass to func
        ///   @return The result of calling "func" with "a"
        ///
        template<typename F, typename U, typename T, typename... ARGS>
        constexpr bsl::invoke_result_t<F, ARGS...>
        invoke_mfp(F U::*func, T &&t, ARGS &&... a)
        {
            if constexpr (is_base_of<U, decay_t<T>>::value) {
                return (bsl::forward<T>(t).*func)(bsl::forward<ARGS>(a)...);
            }
            else if constexpr (is_reference_wrapper<decay_t<T>>::value)
                return (bsl::forward<T>(t.get()).*func)(bsl::forward<ARGS>(a)...);
            else {
                return ((*bsl::forward<T>(t)).*func)(bsl::forward<ARGS>(a)...);
            }
        }

        /// <!-- description -->
        ///   @brief Implements INVOKE as defined by the C++ specification.
        ///     Note that we use the name invoke_mfp as INVOKE is not
        ///     compliant with AUTOSAR as the only difference with the name
        ///     is the use of capitalization. Specifically, this is the
        ///     member object pointer variant of INVOKE which, given a
        ///     function, an object and a set of args will call the function.
        ///
        /// <!-- contracts -->
        ///   @pre expects func != nullptr. Note that this pre-condition is
        ///     not validated as there is no way to report an error. We do
        ///     provide safe_invoke() versions of invoke() that result this
        ///     issue and should be used instead. invoke() is only provided
        ///     to ensure support with 3rd party libraries.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam F the type that defines the function being called
        ///   @tparam U the type that defines the class that encapsulates the
        ///     function being called.
        ///   @tparam T the type that defines the provided object. Note that
        ///     normally, U == T, but if inheritance is used, it might not
        ///     which is why U is provided instead of just using T.
        ///   @tparam ARGS the types that define the arguments passed to the
        ///     provided function when called.
        ///   @param func a pointer to the function to call.
        ///   @param t the object that encapsulates the provided function.
        ///   @return The result of calling "func" with "a"
        ///
        template<typename F, typename U, typename T, typename... ARGS>
        constexpr bsl::invoke_result_t<F, ARGS...>
        invoke_mop(F U::*func, T &&t)
        {
            if constexpr (is_base_of<T, decay_t<T>>::value) {
                return bsl::forward<T>(t).*func;
            }
            else if constexpr (is_reference_wrapper<decay_t<T>>::value)
                return bsl::forward<T>(t.get()).*func;
            else {
                return (*bsl::forward<T>(t)).*func;
            }
        }

        /// <!-- description -->
        ///   @brief Implements INVOKE as defined by the C++ specification.
        ///     Note that we use the name invoke_mfp as INVOKE is not
        ///     compliant with AUTOSAR as the only difference with the name
        ///     is the use of capitalization. Specifically, this is the
        ///     function pointer variant of INVOKE which, given a
        ///     function and a set of args will call the function.
        ///
        /// <!-- contracts -->
        ///   @pre expects func != nullptr. Note that this pre-condition is
        ///     not validated as there is no way to report an error. We do
        ///     provide safe_invoke() versions of invoke() that result this
        ///     issue and should be used instead. invoke() is only provided
        ///     to ensure support with 3rd party libraries.
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam F the type that defines the function being called
        ///   @tparam ARGS the types that define the arguments passed to the
        ///     provided function when called.
        ///   @param func a pointer to the function to call.
        ///   @param a the arguments to pass to func
        ///   @return The result of calling "func" with "a"
        ///
        template<class F, class... ARGS>
        constexpr bsl::invoke_result_t<F, ARGS...>
        invoke_impl(F &&func, ARGS &&... a)
        {
            return bsl::forward<F>(func)(bsl::forward<ARGS>(a)...);
        }
    }
}

#endif
