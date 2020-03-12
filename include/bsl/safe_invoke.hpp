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
/// @file safe_invoke.hpp
///

#ifndef BSL_SAFE_INVOKE_HPP
#define BSL_SAFE_INVOKE_HPP

#include "enable_if.hpp"
#include "invoke_result.hpp"
#include "is_void.hpp"
#include "result.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Invokes the callable object "func" with arguments "a". If
    ///     "func" is a nullptr, will return bsl::errc_nullptr_dereference,
    ///     otherwise returns the result of calling the object "func" with
    ///     with arguments "a".
    ///
    /// <!-- contracts -->
    ///   @pre none
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
    template<
        typename F,
        typename... ARGS,
        enable_if_t<!is_void<invoke_result_t<F, ARGS...>>::value> = true>
    [[nodiscard]] constexpr result<invoke_result_t<F, ARGS...>>
    safe_invoke(F &&func, ARGS &&... a)
    {
        if (nullptr == func) {
            return {bsl::errc_nullptr_dereference};
        }

        return {in_place, invoke(bsl::forward<F>(func), bsl::forward<ARGS>(a)...)};
    }

    /// <!-- description -->
    ///   @brief Invokes the callable object "func" with arguments "a". If
    ///     "func" is a nullptr, will return bsl::errc_nullptr_dereference,
    ///     otherwise returns the result of calling the object "func" with
    ///     with arguments "a".
    ///
    /// <!-- contracts -->
    ///   @pre none
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
    template<
        typename F,
        typename... ARGS,
        enable_if_t<is_void<invoke_result_t<F, ARGS...>>::value> = true>
    constexpr void
    safe_invoke(F &&func, ARGS &&... a)
    {
        if (nullptr != func) {
            invoke(bsl::forward<F>(func), bsl::forward<ARGS>(a)...);
        }
    }
}

#endif
