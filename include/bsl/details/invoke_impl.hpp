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

#include "../print.hpp"

#include "../decay.hpp"
#include "../forward.hpp"
#include "../is_base_of.hpp"
#include "../is_member_function_pointer.hpp"
// #include "is_reference_wrapper.hpp"

namespace bsl
{
    namespace details
    {
        template<typename F, typename U, typename T, typename... ARGS>
        constexpr decltype(auto)
        invoke_impl(F U::*func, T &&t, ARGS &&... a)
        {
            if constexpr (is_member_function_pointer<decltype(func)>::value) {
                if constexpr (is_base_of<U, decay_t<T>>::value) {
                    print("%d\n", __LINE__);
                    return (bsl::forward<T>(t).*func)(bsl::forward<ARGS>(a)...);
                }
                // else if constexpr (is_reference_wrapper_v<decay_t<T1>>)
                //     return (t1.get().*f)(bsl::forward<ARGS>(a)...);
                else {
                    print("%d\n", __LINE__);
                    return ((*bsl::forward<T>(t)).*func)(bsl::forward<ARGS>(a)...);
                }
            }
            else {
                if constexpr (is_base_of<T, decay_t<T>>::value) {
                    print("%d\n", __LINE__);
                    return bsl::forward<T>(t).*func;
                }
                // else if constexpr (is_reference_wrapper_v<decay_t<T1>>)
                //     return t1.get().*f;
                else {
                    print("%d\n", __LINE__);
                    return (*bsl::forward<T>(t)).*func;
                }
            }
        }

        template<class F, class... ARGS>
        constexpr decltype(auto)
        invoke_impl(F &&func, ARGS &&... a)
        {
            print("%d\n", __LINE__);
            return bsl::forward<F>(func)(bsl::forward<ARGS>(a)...);
        }
    }
}

#endif
