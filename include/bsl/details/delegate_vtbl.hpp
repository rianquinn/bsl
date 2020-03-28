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

#ifndef BSL_DETAILS_DELEGATE_VTBL_HPP
#define BSL_DETAILS_DELEGATE_VTBL_HPP

#include "../construct_at.hpp"
#include "../destroy_at.hpp"
#include "../forward.hpp"
#include "../move.hpp"

namespace bsl
{
    namespace details
    {
        template<typename R, typename... ARGS>
        struct delegate_vtbl final
        {
            R (*m_call_func)(void const * const, ARGS &&...);
            void (*m_copy_func)(void * const, void * const);
            void (*m_move_func)(void * const, void * const);
            void (*m_free_func)(void * const);
        };

        template<typename FUNC>
        [[nodiscard]] static constexpr FUNC &
        get_func(void * const heap) noexcept
        {
            return *static_cast<FUNC *>(heap);
        }

        template<typename FUNC>
        [[nodiscard]] static constexpr FUNC const &
        get_func(void const * const heap) noexcept
        {
            return *static_cast<FUNC const *>(heap);
        }

        template<typename FUNC>
        constexpr void
        copy_func(void * const heap, FUNC const &func) noexcept
        {
            bsl::construct_at<FUNC>(heap, func);
        }

        template<typename FUNC>
        constexpr void
        move_func(void * const heap, FUNC &&func) noexcept
        {
            bsl::construct_at<FUNC>(heap, bsl::move(func));
        }

        template<typename FUNC, typename R, typename... ARGS>
        [[maybe_unused]] constexpr R
        call_func_generic(void const * const heap, ARGS &&... args) noexcept(false)
        {
            return get_func<FUNC>(heap)(bsl::forward<ARGS>(args)...);
        }

        template<typename FUNC>
        constexpr void
        copy_func_generic(void * const heap, void * const func) noexcept
        {
            copy_func<FUNC>(heap, get_func<FUNC>(func));
        }

        template<typename FUNC>
        constexpr void
        move_func_generic(void * const heap, void * const func) noexcept
        {
            move_func<FUNC>(heap, bsl::move(get_func<FUNC>(func)));
        }

        template<typename FUNC>
        constexpr void
        free_func_generic(void * const heap) noexcept
        {
            bsl::destroy_at<FUNC>(&get_func<FUNC>(heap));
        }

        template<typename FUNC, typename R, typename... ARGS>
        [[nodiscard]] static delegate_vtbl<R, ARGS...> *
        get_delegate_vtbl() noexcept
        {
            static delegate_vtbl<R, ARGS...> s_vtbl{
                &call_func_generic<FUNC, R, ARGS...>,
                &copy_func_generic<FUNC>,
                &move_func_generic<FUNC>,
                &free_func_generic<FUNC>
            };

            return &s_vtbl;
        }
    }
}

#endif
