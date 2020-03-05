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
/// @file invoke.hpp
///

#ifndef BSL_INVOKE_HPP
#define BSL_INVOKE_HPP

#include "details/invoke_impl.hpp"

#include "forward.hpp"
#include "enable_if.hpp"
#include "invoke_result.hpp"
#include "is_void.hpp"
#include "is_member_function_pointer.hpp"
#include "is_member_object_pointer.hpp"
#include "result.hpp"

namespace bsl
{

    template<typename F, typename... ARGS>
    constexpr invoke_result_t<F, ARGS...>
    invoke(F &&func, ARGS &&... a)
    {
        // if constexpr (is_member_function_pointer<FUNC>::value) {
        //     return details::invoke_mfp(bsl::forward<F>(func), bsl::forward<ARGS>(a)...);
        // }
        // else if constexpr (is_member_object_pointer<FUNC>::value) {
        //     return details::invoke_mop(bsl::forward<F>(func), bsl::forward<ARGS>(a)...);
        // }
        // else {
            return details::invoke_impl(bsl::forward<F>(func), bsl::forward<ARGS>(a)...);
        // }
    }

    // template<typename F, typename... ARGS>
    // result<enable_if_t<!is_void<invoke_result_t<F, ARGS...>>::value, invoke_result_t<F, ARGS...>>>
    // safe_invoke(F &&func, ARGS &&... a)
    // {
    //     if (nullptr == func) {
    //         return {bsl::errc_nullptr_dereference};
    //     }

    //     return {inplace, details::invoke_impl(bsl::forward<F>(func), bsl::forward<ARGS>(a)...)};
    // }

    // template<typename F, typename... ARGS>
    // enable_if_t<is_void<invoke_result_t<F, ARGS...>>::value, void>
    // safe_invoke(F &&func, ARGS &&... a)
    // {
    //     if (nullptr != func) {
    //         return {inplace, details::invoke_impl(bsl::forward<F>(func), bsl::forward<ARGS>(a)...)};
    //     }
    // }
}

#endif
