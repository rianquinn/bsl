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
        /// @class bsl::delegate::delegate_vtbl
        ///
        /// <!-- description -->
        ///   @brief Stores the type erased versions of the copy, move and
        ///     free functions
        ///
        /// <!-- template parameters -->
        ///   @tparam R the return value of the delegate
        ///   @tparam ARGS the argument to pass to the delegate
        ///
        template<typename R, typename... ARGS>
        struct delegate_vtbl final
        {
            void (*m_copy_func)(void * const, void const * const);
            void (*m_move_func)(void * const, void * const);
            void (*m_free_func)(void * const);
        };

        /// <!-- description -->
        ///   @brief Converts a heap to a function.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to convert the heap to
        ///   @param heap the heap to convert to FUNC
        ///   @return A pointer to heap, as a FUNC
        ///
        template<typename FUNC>
        [[nodiscard]] static constexpr FUNC &
        get_func(void * const heap) noexcept
        {
            return *static_cast<FUNC *>(heap);
        }

        /// <!-- description -->
        ///   @brief Converts a heap to a function.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to convert the heap to
        ///   @param heap the heap to convert to FUNC
        ///   @return A pointer to heap, as a FUNC
        ///
        template<typename FUNC>
        [[nodiscard]] static constexpr FUNC const &
        get_func(void const * const heap) noexcept
        {
            return *static_cast<FUNC const *>(heap);
        }

        /// <!-- description -->
        ///   @brief Copies a provided function into a heap. This is the same
        ///     as saying func1 = func2 but using a placement new to some
        ///     heap memory. We use a heap so that we can store func when
        ///     it is either a function pointer, or when it is a lambda with
        ///     a capture list that stores a pointer to an object and a
        ///     member function pointer. Futhermore the heap is a void * to
        ///     support type erasure, allowing the delegate to be unaware as
        ///     to the signature of FUNC.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to copy
        ///   @param heap the memory to placement new into
        ///   @param func the function to copy
        ///
        template<typename FUNC>
        constexpr void
        copy_func(void * const heap, FUNC const &func) noexcept
        {
            bsl::construct_at<FUNC>(heap, func);
        }

        /// <!-- description -->
        ///   @brief Moves a provided function into a heap. This is the same
        ///     as saying func1 = bsl::move(func2) but using a placement new to
        ///     some heap memory. We use a heap so that we can store func when
        ///     it is either a function pointer, or when it is a lambda with
        ///     a capture list that stores a pointer to an object and a
        ///     member function pointer. Futhermore the heap is a void * to
        ///     support type erasure, allowing the delegate to be unaware as
        ///     to the signature of FUNC.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to move
        ///   @param heap the memory to placement new into
        ///   @param func the function to move
        ///
        template<typename FUNC>
        constexpr void
        move_func(void * const heap, FUNC &&func) noexcept
        {
            bsl::construct_at<FUNC>(heap, bsl::move(func));
        }

        /// <!-- description -->
        ///   @brief The type erased version of the wrapped function given
        ///     a pointer to the heap that is actually storing the wrapped
        ///     function. This is the indirection that the delegate calls
        ///     when calling the wrapped function. Remember the whole point
        ///     of a delegate is to be able to call either a function or a
        ///     member function pointer, without knowing which version it
        ///     has. The heap stores the function/member function pointer
        ///     information. Since this function's signature does not include
        ///     FUNC (only a void * and ARGS), a pointer to this function
        ///     can be stored and called by the delegate. All this function
        ///     has to do is convert the provided heap to FUNC and call it.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to move
        ///   @tparam R the return value of the function
        ///   @tparam ARGS the argument to pass to the function
        ///   @param heap the memory containing the wrapped function.
        ///   @param args the arguments to pass to the wrapped function.
        ///   @return Returns the result of executing the wrapped function.
        ///
        template<typename FUNC, typename R, typename... ARGS>
        [[maybe_unused]] constexpr R
        call_func_generic(void const * const heap, ARGS &&... args) noexcept(false)
        {
            return get_func<FUNC>(heap)(bsl::forward<ARGS>(args)...);
        }

        /// <!-- description -->
        ///   @brief This is the type erased version of copy_func. This is
        ///     needed because we cannot store a pointer to a function that
        ///     has FUNC in the signature in the delegate.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to copy
        ///   @param heap the memory to placement new into
        ///   @param func the function to copy
        ///
        template<typename FUNC>
        constexpr void
        copy_func_generic(void * const heap, void const * const func) noexcept
        {
            copy_func<FUNC>(heap, get_func<FUNC>(func));
        }

        /// <!-- description -->
        ///   @brief This is the type erased version of move_func. This is
        ///     needed because we cannot store a pointer to a function that
        ///     has FUNC in the signature in the delegate.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to move
        ///   @param heap the memory to placement new into
        ///   @param func the function to move
        ///
        template<typename FUNC>
        constexpr void
        move_func_generic(void * const heap, void * const func) noexcept
        {
            move_func<FUNC>(heap, bsl::move(get_func<FUNC>(func)));
        }

        /// <!-- description -->
        ///   @brief Destroys the delegate by calling the wrapped function's
        ///     destructor. The wrapped function is either a function pointer
        ///     or a lambda with a capture of a pointer to an object and a
        ///     member function pointer. As a result, this likely doesn't do
        ///     anything, but intead is here for completeness as eventually
        ///     we might want to add lambda/functor support, which would need
        ///     this.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to move
        ///   @param heap the memory to the function to destroy
        ///
        template<typename FUNC>
        constexpr void
        free_func_generic(void * const heap) noexcept
        {
            bsl::destroy_at<FUNC>(&get_func<FUNC>(heap));
        }

        /// <!-- description -->
        ///   @brief Returns delegate_vtbl given FUNC. Note that we return
        ///     a pointer to a static here instead of a fresh copy for each
        ///     delegate. This reduces the size of the delegate my exploiting
        ///     the fact this all of the logic above is only different if
        ///     FUNC is different. If FUNC is different, the compiler will
        ///     create another copy of this static for us and so we only need
        ///     a delegate_vtbl for each delegate type that has a different
        ///     FUNC... not for each instance of a delegate.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FUNC the function type to move
        ///   @tparam R the return value of the function
        ///   @tparam ARGS the argument to pass to the function
        ///   @return Returns delegate_vtbl given FUNC.
        ///
        template<typename FUNC, typename R, typename... ARGS>
        [[nodiscard]] static delegate_vtbl<R, ARGS...> *
        get_delegate_vtbl() noexcept
        {
            static delegate_vtbl<R, ARGS...> s_vtbl{
                &copy_func_generic<FUNC>,
                &move_func_generic<FUNC>,
                &free_func_generic<FUNC>
            };

            return &s_vtbl;
        }
    }
}

#endif
