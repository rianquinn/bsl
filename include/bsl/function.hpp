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

#include "aligned_storage.hpp"
#include "construct_at.hpp"
#include "result.hpp"

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
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::function's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_function_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the function being wrapped
    ///   @tparam ARGS The arguments to the function being wrapped
    ///
    template<typename R, typename... ARGS>
    class function<R(ARGS...)> final
    {
        /// @brief stores whether or not this function is valid
        bool m_valid;
        /// @brief stores the invoke wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::function is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::function should not include {},
        ///     ensuing it is a POD. As required by C++, the OS will zero
        ///     initialize the bsl::function for you, marking the bsl::function
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::function is initialized, which
        ///     most compilers will warn about.
        ///   @include function/example_function_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        function() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function being wrapped
        ///
        function(R (*const func)(ARGS...)) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<R(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<R(ARGS...)>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T &t, R (U::*const func)(ARGS...)) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, R(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::function is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include function/example_function_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T const &t, R (U::*const func)(ARGS...) const) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, R(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::function by calling the wrapped function
        ///     with "args" and returning the result.
        ///   @include function/example_function_functor.hpp
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
        [[nodiscard]] result<R>
        operator()(ARGS &&... args) const noexcept(false)
        {
            if (m_valid) {
                details::base_wrapper<R(ARGS...)> const *const ptr{
                    details::cast<details::base_wrapper<R(ARGS...)>>(&m_store)};

                return {bsl::in_place, ptr->invoke(bsl::forward<ARGS>(args)...)};
            }

            return {bsl::errc_bad_function};
        }

        /// <!-- description -->
        ///   @brief If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///   @include function/example_function_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

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
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::function's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_function_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam R the return value of the function being wrapped
    ///   @tparam ARGS The arguments to the function being wrapped
    ///
    template<typename R, typename... ARGS>
    class function<R(ARGS...) noexcept> final
    {
        /// @brief stores whether or not this function is valid
        bool m_valid;
        /// @brief stores the invoke wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::function is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::function should not include {},
        ///     ensuing it is a POD. As required by C++, the OS will zero
        ///     initialize the bsl::function for you, marking the bsl::function
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::function is initialized, which
        ///     most compilers will warn about.
        ///   @include function/example_function_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        function() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function being wrapped
        ///
        function(R (*const func)(ARGS...) noexcept) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<R(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<R(ARGS...) noexcept>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T &t, R (U::*const func)(ARGS...) noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, R(ARGS...) noexcept>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::function is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include function/example_function_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T const &t, R (U::*const func)(ARGS...) const noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, R(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, R(ARGS...) noexcept>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::function by calling the wrapped function
        ///     with "args" and returning the result.
        ///   @include function/example_function_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre assumes the bsl::function is valid
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///   @return returns the results of the wrapped function
        ///
        [[nodiscard]] result<R>
        operator()(ARGS &&... args) const noexcept
        {
            if (m_valid) {
                details::base_wrapper<R(ARGS...) noexcept> const *const ptr{
                    details::cast<details::base_wrapper<R(ARGS...) noexcept>>(&m_store)};

                return {bsl::in_place, ptr->invoke(bsl::forward<ARGS>(args)...)};
            }

            return {bsl::errc_bad_function};
        }

        /// <!-- description -->
        ///   @brief If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///   @include function/example_function_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

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
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::function's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_function_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam ARGS The arguments to the function being wrapped
    ///
    template<typename... ARGS>
    class function<void(ARGS...)> final
    {
        /// @brief stores whether or not this function is valid
        bool m_valid;
        /// @brief stores the invoke wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::function is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::function should not include {},
        ///     ensuing it is a POD. As required by C++, the OS will zero
        ///     initialize the bsl::function for you, marking the bsl::function
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::function is initialized, which
        ///     most compilers will warn about.
        ///   @include function/example_function_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        function() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function being wrapped
        ///
        function(void (*const func)(ARGS...)) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<void(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<void(ARGS...)>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T &t, void (U::*const func)(ARGS...)) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, void(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::function is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include function/example_function_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T const &t, void (U::*const func)(ARGS...) const) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, void(ARGS...)>>(&m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::function by calling the wrapped function
        ///     with "args".
        ///   @include function/example_function_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre assumes the bsl::function is valid
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///
        /// <!-- inputs/outputs -->
        ///   @throw throws if the wrapped function throws
        ///
        void
        operator()(ARGS &&... args) const noexcept(false)
        {
            if (m_valid) {
                details::base_wrapper<void(ARGS...)> const *const ptr{
                    details::cast<details::base_wrapper<void(ARGS...)>>(&m_store)};

                ptr->invoke(bsl::forward<ARGS>(args)...);
            }
        }

        /// <!-- description -->
        ///   @brief If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///   @include function/example_function_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

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
    ///     - Operator bool is not supported as AUTOSAR does not allow for
    ///       the use of the conversion operator. Instead, use valid().
    ///     - Target access, non-member and helper functions are not supported.
    ///     - Functions marked as "noexcept" are supported. If the function
    ///       is marked as noexcept, the resulting bsl::function's functor
    ///       will also be marked as noexcept and vice versa.
    ///   @include example_function_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam ARGS The arguments to the function being wrapped
    ///
    template<typename... ARGS>
    class function<void(ARGS...) noexcept> final
    {
        /// @brief stores whether or not this function is valid
        bool m_valid;
        /// @brief stores the invoke wrapper
        aligned_storage_t<sizeof(void *) * 3> m_store;

    public:
        /// <!-- description -->
        ///   @brief Provides support for ensuring that a bsl::function is a
        ///     POD type, allowing it to be defined as a global resource.
        ///     When used globally, a bsl::function should not include {},
        ///     ensuing it is a POD. As required by C++, the OS will zero
        ///     initialize the bsl::function for you, marking the bsl::function
        ///     as invalid. If you use this constructor locally, you must
        ///     include {} to ensure the bsl::function is initialized, which
        ///     most compilers will warn about.
        ///   @include function/example_function_default_constructor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        function() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a function pointer. If the
        ///     function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_func.hpp
        ///
        ///   SUPPRESSION: PRQA 2180 - false positive
        ///   - We suppress this because A12-1-4 states that all constructors
        ///     that are callable from a fundamental type should be marked as
        ///     explicit. This is not a fundamental type and there for does
        ///     not apply.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function being wrapped
        ///
        function(void (*const func)(ARGS...) noexcept) noexcept    // PRQA S 2180 // NOLINT
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::func_wrapper<void(ARGS...)>));

            if (m_valid) {
                construct_at<details::func_wrapper<void(ARGS...) noexcept>>(&m_store, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a member function pointer. If
        ///     the function pointer is a nullptr, the resulting bsl::function
        ///     is marked as invalid, and will always return an error when
        ///     executed.
        ///   @include function/example_function_constructor_memfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T &t, void (U::*const func)(ARGS...) noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::memfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::memfunc_wrapper<T, void(ARGS...) noexcept>>(
                    &m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Creates a bsl::function from a const member function
        ///     pointer. If the function pointer is a nullptr, the resulting
        ///     bsl::function is marked as invalid, and will always return an
        ///     error when executed.
        ///   @include function/example_function_constructor_cmemfunc.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t the object to execute the member function from
        ///   @param func a pointer to the function being wrapped
        ///
        template<typename T, typename U>
        function(T const &t, void (U::*const func)(ARGS...) const noexcept) noexcept    // --
            : m_valid{nullptr != func}, m_store{}
        {
            static_assert(sizeof(m_store) >= sizeof(details::cmemfunc_wrapper<T, void(ARGS...)>));

            if (m_valid) {
                construct_at<details::cmemfunc_wrapper<T, void(ARGS...) noexcept>>(
                    &m_store, t, func);
            }
        }

        /// <!-- description -->
        ///   @brief Execute the bsl::function by calling the wrapped function
        ///     with "args".
        ///   @include function/example_function_functor.hpp
        ///
        /// <!-- contracts -->
        ///   @pre assumes the bsl::function is valid
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param args the arguments to pass to the wrapped function
        ///
        void
        operator()(ARGS &&... args) const noexcept
        {
            if (m_valid) {
                details::base_wrapper<void(ARGS...) noexcept> const *const ptr{
                    details::cast<details::base_wrapper<void(ARGS...) noexcept>>(&m_store)};

                ptr->invoke(bsl::forward<ARGS>(args)...);
            }
        }

        /// <!-- description -->
        ///   @brief If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///   @include function/example_function_valid.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return If the bsl::function is valid, returns true, otherwise
        ///     returns false.
        ///
        [[nodiscard]] bool
        valid() const noexcept
        {
            return m_valid;
        }
    };

    /// @brief deduction guideline for bsl::function
    function()->function<void() noexcept>;

    /// @brief deduction guideline for bsl::function
    template<typename R, typename... ARGS>
    function(R (*)(ARGS...))->function<R(ARGS...)>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename R, typename... ARGS>
    function(T &t, R (U::*)(ARGS...))->function<R(ARGS...)>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename R, typename... ARGS>
    function(T const &t, R (U::*)(ARGS...) const)->function<R(ARGS...)>;

    /// @brief deduction guideline for bsl::function
    template<typename R, typename... ARGS>
    function(R (*)(ARGS...) noexcept)->function<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename R, typename... ARGS>
    function(T &t, R (U::*)(ARGS...) noexcept)->function<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename R, typename... ARGS>
    function(T const &t, R (U::*)(ARGS...) const noexcept)->function<R(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::function
    template<typename... ARGS>
    function(void (*)(ARGS...))->function<void(ARGS...)>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename... ARGS>
    function(T &t, void (U::*)(ARGS...))->function<void(ARGS...)>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename... ARGS>
    function(T const &t, void (U::*)(ARGS...) const)->function<void(ARGS...)>;

    /// @brief deduction guideline for bsl::function
    template<typename... ARGS>
    function(void (*)(ARGS...) noexcept)->function<void(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename... ARGS>
    function(T &t, void (U::*)(ARGS...) noexcept)->function<void(ARGS...) noexcept>;

    /// @brief deduction guideline for bsl::function
    template<typename T, typename U, typename... ARGS>
    function(T const &t, void (U::*)(ARGS...) const noexcept)->function<void(ARGS...) noexcept>;
}

#endif
