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
/// @file function.hpp
///

#ifndef BSL_FUNCTION_HPP
#define BSL_FUNCTION_HPP

#include "details/cast.hpp"
#include "details/base_wrapper.hpp"
#include "details/func_wrapper.hpp"
#include "details/memfunc_wrapper.hpp"
#include "details/cmemfunc_wrapper.hpp"

#include "construct_at.hpp"
#include "aligned_storage.hpp"

// TODO: --
//
// Once we have access to C++20, we need to make the default constructor
// private. It must still exist, but simply marked as private. This will
// ensure the bsl::function is a POD type, but also requires a valid
// constructor. "constinit" will ensure the bsl::function can be created
// globally without introducing a runtime constructor which is not
// supported by AUTOSAR.
//

namespace bsl
{
    template<typename>
    class function;

    /// @class bsl::details::function
    ///
    /// <!-- description -->
    ///   @brief Implements a simplified version of std::function. Unlike
    ///     std::function, a bsl::function has the following differences:
    ///     - Lambda functions, and binding in general are not supported.
    ///       Instead, either use a function pointer, or a member function
    ///       pointer. The reason is this implementation attempts to reduce
    ///       the overhead of std::function, and dynamic memory is not
    ///       supported, so the bsl::function has a fixed amount of memory
    ///       that it can support for wrapping.
    ///     - Operator bool is not supported. Although, for now, a
    ///       bsl::function can be constructed without a valid function, the
    ///       intent is to remove this issue once we can use constinit from
    ///       C++20. Until then, an invalid bsl::function can be created
    ///       to ensure the bsl::function is a POD type that can be defined
    ///       globally while still supporting AUTOSAR. Any attempt to
    ///       execute an invalid bsl::function will result in UB, and do not
    ///       attempt to use a bsl::function as an optional (nullable type)
    ///       as this functionality will be removed in the future.
    ///     - Target access, non-member and helper functions are not supported.
    ///   @include function/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the function being wrapped
    ///   @tparam ARGS The arguments to the function being wrapped
    ///
    template<typename R, typename... ARGS>
    class function<R(ARGS...)> final
    {
        /// @brief stores the invoke wrapper
        aligned_storage_t<sizeof(void *) * 3> m_storage;

    public:
        /// <!-- description -->
        ///   @brief Default constructor. This is provided to support POD
        ///     style bsl::function objects ensuring a bsl::function can be
        ///     created as a global resource. Not that this will create an
        ///     invalid bsl::function. For this reason, once we have access to
        ///     "constinit", this constructor will be moved as it will no
        ///     longer be needed.
        ///   @include function/constructor.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        function() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a function pointer.
        ///   @include function/constructor_func.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function being wrapped
        ///
        explicit function(R (*const func)(ARGS...)) noexcept    // --
            : m_storage{}
        {
            static_assert(sizeof(m_storage) >= sizeof(details::func_wrapper<R(ARGS...)>));
            construct_at<details::func_wrapper<R(ARGS...)>>(&m_storage, func);
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a member function pointer.
        ///   @include function/constructor_memfunc.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T>
        explicit function(T &t, R (T::*const func)(ARGS...)) noexcept    // --
            : m_storage{}
        {
            static_assert(sizeof(m_storage) >= sizeof(details::memfunc_wrapper<T, R(ARGS...)>));
            construct_at<details::memfunc_wrapper<T, R(ARGS...)>>(&m_storage, t, func);
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a const member function
        ///     pointer.
        ///   @include function/constructor_cmemfunc.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T>
        explicit function(T const &t, R (T::*const func)(ARGS...) const) noexcept    // --
            : m_storage{}
        {
            static_assert(sizeof(m_storage) >= sizeof(details::cmemfunc_wrapper<T, R(ARGS...)>));
            construct_at<details::cmemfunc_wrapper<T, R(ARGS...)>>(&m_storage, t, func);
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::function by calling the wrapped function
        ///     with "args" and returning the result.
        ///   @include function/functor.cpp
        ///
        /// <!-- contracts -->
        ///   @pre assumes the bsl::function is valid
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///   @return returns the results of the wrapped function
        ///
        /// <!-- inputs/outputs -->
        ///   @throw throws if the wrapped function throws
        ///
        [[maybe_unused]] constexpr R
        operator()(ARGS &&... args) const
        {
            details::base_wrapper<R(ARGS...)> const *const ptr{
                details::cast<details::base_wrapper<R(ARGS...)>>(&m_storage)};

            return ptr->invoke(bsl::forward<ARGS>(args)...);
        }
    };
}

#endif
