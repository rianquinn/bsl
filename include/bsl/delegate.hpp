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
/// @file delegate.hpp
///

#ifndef BSL_DELEGATE_HPP
#define BSL_DELEGATE_HPP

#include "details/delegate_vtbl.hpp"

#include "cstdint.hpp"
#include "aligned_storage.hpp"
#include "is_void.hpp"
#include "result.hpp"

namespace bsl
{
    template<typename F>
    class delegate;

    /// @brief the total size of the heap
    constexpr bsl::uintmax delegate_heap_size{32};
    /// @brief the alignment of the heap
    constexpr bsl::uintmax delegate_heap_align{32};

    template<typename R, typename... ARGS>
    class delegate<R(ARGS...)> // NOLINT
    {
        /// @brief memory used to store the wrapped function
        aligned_storage_t<delegate_heap_size, delegate_heap_align> m_heap;
        /// @brief dispatcher that type erases the wrapped function's signature
        details::delegate_vtbl<R, ARGS...> *m_vtbl;

    public:
        /// @brief the return type of the wrapped function.
        using result_type = R;

        /// <!-- description -->
        ///   @brief Default constructor that creates a delegate with
        ///     m_heap and m_vtbl all set to 0. Note that like other types
        ///     in the BSL, the bsl::delegate is a POD type. This
        ///     means that when declaring a global, default constructed
        ///     bsl::delegate, DO NOT include the {} for
        ///     initialization. Instead, remove the {} and the global
        ///     bsl::delegate will be included in the BSS section of
        ///     the executable, and initialized to 0 for you. All other
        ///     instantiations of a bsl::delegate (or any POD
        ///     type), should be initialized using {} to ensure the POD is
        ///     properly initialized. Using the above method for global
        ///     initialization ensures that global constructors are not
        ///     executed at runtime, which is required by AUTOSAR.
        ///   @include delegate/example_delegate_default_constructor.hpp
        ///
        constexpr delegate() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::delegate that wraps a function pointer.
        ///   @include delegate/example_delegate_fp_constructor.hpp
        ///
        /// <!-- inputs/outputs -->
        ///   @param func a pointer to the function to wrap
        ///
        explicit constexpr delegate(R(* func)(ARGS...)) noexcept
            : m_heap{}, m_vtbl{}
        {
            if (nullptr != func) {
                m_vtbl = details::get_delegate_vtbl<decltype(func), R, ARGS...>();
                details::copy_func(&m_heap, func);
            }
        }

        template<typename T, typename U>
        constexpr delegate(T *t, R (U::*mfp)(ARGS...)) noexcept
            : m_heap{}, m_vtbl{}
        {
            if (nullptr != mfp) {
                auto func = [mfp, t](ARGS && ...args) -> R {
                    return (t->*mfp)(bsl::forward<ARGS>(args)...);
                };

                m_vtbl = details::get_delegate_vtbl<decltype(func), R, ARGS...>();
                details::copy_func(&m_heap, func);
            }
        }

        template<typename T, typename U>
        constexpr delegate(T *t, R (U::*mfp)(ARGS...) const) noexcept
            : m_heap{}, m_vtbl{}
        {
            if (nullptr != mfp) {
                auto func = [mfp, t](ARGS && ...args) -> R {
                    return (t->*mfp)(bsl::forward<ARGS>(args)...);
                };

                m_vtbl = details::get_delegate_vtbl<decltype(func), R, ARGS...>();
                details::copy_func(&m_heap, func);
            }
        }

        constexpr delegate(delegate const &other) noexcept
            : m_heap{}, m_vtbl{other.m_vtbl}
        {
            m_vtbl->m_copy_func(&m_heap, &other.m_heap);
        }

        constexpr delegate(delegate &&other) noexcept
            : m_heap{}, m_vtbl{bsl::move(other.m_vtbl)}
        {
            m_vtbl->m_move_func(&m_heap, &other.m_heap);
        }

        constexpr delegate &
        operator=(delegate const &other) &noexcept
        {
            m_vtbl = other.m_vtbl;
            m_vtbl->m_copy_func(&m_heap, &other.m_heap);

            return *this;
        }

        constexpr delegate &
        operator=(delegate &&other) &noexcept
        {

        }


        // /// Destructor
        // ///
        // ~delegate()
        // {
        //     if (m_vtbl) {
        //         m_vtbl->destroy(m_state);
        //     }

        //     m_vtbl = nullptr;
        //     m_call = nullptr;
        // }

        [[maybe_unused]] constexpr result<R>
        operator()(ARGS... args) const
        {
            if (nullptr == m_vtbl) {
                return {bsl::errc_bad_function};
            }

            return {bsl::in_place, m_vtbl->m_call_func(&m_heap, bsl::forward<ARGS>(args)...)};
        }

        [[nodiscard]] constexpr bool
        empty() const noexcept
        {
            return nullptr == m_vtbl;
        }
    };

    /// @brief deduction guideline for bsl::delegate
    delegate()->delegate<void() noexcept>;

    /// @brief deduction guideline for bsl::delegate
    template<typename R, typename... ARGS>
    explicit delegate(R (*)(ARGS...)) -> delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T *t, R (U::*)(ARGS...)) -> delegate<R(ARGS...)>;

    /// @brief deduction guideline for bsl::delegate
    template<typename T, typename U, typename R, typename... ARGS>
    delegate(T *t, R (U::*)(ARGS...) const) -> delegate<R(ARGS...)>;
}

#endif

































// namespace bsl
// {
//     namespace details
//     {
//         template<typename T>
//         [[nodiscard]] constexpr auto
//         delegate_type() noexcept -> type_identity<>
//         {}
//     }

//     template<typename FUNC, typename T = void>
//     class delegate;

//     /// <!-- description -->
//     ///   @brief Implements a simplified version of std::function. Unlike
//     ///     std::function, a bsl::delegate has the following differences:
//     ///     - Lambda functions, and binding in general are not supported.
//     ///       Instead, either use a function pointer, or a member function
//     ///       pointer. The reason is this implementation attempts to reduce
//     ///       the overhead of std::function, and dynamic memory is not
//     ///       supported, so the bsl::delegate has a fixed amount of memory
//     ///       that it can support for wrapping.
//     ///     - Operator bool is not supported as AUTOSAR does not allow for
//     ///       the use of the conversion operator. Instead, use valid().
//     ///     - Target access, non-member and helper functions are not supported.
//     ///     - Functions marked as "noexcept" are supported. If the function
//     ///       is marked as noexcept, the resulting bsl::delegate's functor
//     ///       will also be marked as noexcept and vice versa.
//     ///   @include example_delegate_overview.hpp
//     ///
//     /// <!-- template parameters -->
//     ///   @tparam R the return value of the delegate being wrapped
//     ///   @tparam ARGS The arguments to the delegate being wrapped
//     ///
//     template<typename T, typename R, typename... ARGS>
//     class delegate<R(ARGS...), T> final
//     {
//         /// @brief stores a pointer to an object (if there is one)
//         T *m_t;

//         union
//         {
//             /// @brief stores a pointer to the function to delegate
//             R (*m_fp)(ARGS...);
//             /// @brief stores a pointer to the member function to delegate
//             R (T::*m_mfp)(ARGS...);
//         }

//         public :
//             /// @brief alias for: R
//             using result_type = R;

//         /// <!-- description -->
//         ///   @brief Provides support for ensuring that a bsl::delegate is a
//         ///     POD type, allowing it to be defined as a global resource.
//         ///     When used globally, a bsl::delegate should not include {},
//         ///     as required by AUTOSAR. The OS will automatically zero
//         ///     initialize the bsl::delegate for you, marking the bsl::delegate
//         ///     as invalid. If you use this constructor locally, you must
//         ///     include {} to ensure the bsl::delegate is initialized, which
//         ///     most compilers will warn about.
//         ///   @include delegate/example_delegate_default_constructor.hpp
//         ///
//         constexpr delegate() noexcept = default;

//         /// <!-- description -->
//         ///   @brief Creates a bsl::delegate from a function pointer. If the
//         ///     function pointer is a nullptr, the resulting bsl::delegate
//         ///     is marked as invalid, and will always return an error when
//         ///     executed.
//         ///   @include delegate/example_delegate_constructor_func.hpp
//         ///
//         ///   SUPPRESSION: PRQA 2180 - false positive
//         ///   - We suppress this because A12-1-4 states that all constructors
//         ///     that are callable from a fundamental type should be marked as
//         ///     explicit. This is not a fundamental type and there for does
//         ///     not apply.
//         ///
//         /// <!-- inputs/outputs -->
//         ///   @param func a pointer to the delegate being wrapped
//         ///
//         constexpr delegate(R (*const func)(ARGS...)) noexcept    // PRQA S 2180 // NOLINT
//             : m_t{}, m_fp{func}
//         {}

//         /// <!-- description -->
//         ///   @brief Creates a bsl::delegate from a member function pointer. If
//         ///     the function pointer is a nullptr, the resulting bsl::delegate
//         ///     is marked as invalid, and will always return an error when
//         ///     executed.
//         ///   @include delegate/example_delegate_constructor_memfunc.hpp
//         ///
//         /// <!-- inputs/outputs -->
//         ///   @param t the object to execute the member function from
//         ///   @param func a pointer to the delegate being wrapped
//         ///
//         template<typename U>
//         delegate(T *t, R (U::*const func)(ARGS...)) noexcept    // --
//             : m_t{t}, m_mfp{func}
//         {}

//         // /// <!-- description -->
//         // ///   @brief Creates a bsl::delegate from a const member function
//         // ///     pointer. If the function pointer is a nullptr, the resulting
//         // ///     bsl::delegate is marked as invalid, and will always return an
//         // ///     error when executed.
//         // ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
//         // ///
//         // /// <!-- inputs/outputs -->
//         // ///   @param t the object to execute the member function from
//         // ///   @param func a pointer to the delegate being wrapped
//         // ///
//         // template<typename T, typename U>
//         // delegate(T const &t, R (U::*const func)(ARGS...) const) noexcept    // --
//         //     : m_valid{nullptr != func}, m_store{}
//         // {
//         //     static_assert(sizeof(m_store) >= sizeof(details::cdelegate_impl_mfp<T, R(ARGS...)>));

//         //     if (m_valid) {
//         //         construct_at<details::cdelegate_impl_mfp<T, R(ARGS...)>>(&m_store, t, func);
//         //     }
//         // }

//         /// <!-- description -->
//         ///   @brief Execute the bsl::delegate by calling the wrapped function
//         ///     with "args" and returning the result.
//         ///   @include delegate/example_delegate_functor.hpp
//         ///
//         /// <!-- inputs/outputs -->
//         ///   @param args the arguments to pass to the wrapped function
//         ///   @return returns the results of the wrapped function
//         ///
//         /// <!-- inputs/outputs -->
//         ///   @throw throws if the wrapped function throws
//         ///
//         [[nodiscard]] result<R>
//         operator()(ARGS &&... args) const
//         {
//             if (nullptr == m_func) {
//                 return {bsl::errc_bad_function};
//             }
//             if constexpr (!is_void<T>::value) {
//                 return {bsl::in_place, invoke(m_func, m_t, bsl::forward<ARGS>(args)...)};
//             }

//             return {bsl::in_place, invoke(m_func, bsl::forward<ARGS>(args)...)};
//         }

//         /// <!-- description -->
//         ///   @brief Returns true if the delegate is not holding a valid
//         ///     function pointer. Returns false otherwise.
//         ///   @include delegate/example_delegate_empty.hpp
//         ///
//         /// <!-- inputs/outputs -->
//         ///   @return Returns true if the delegate is not holding a valid
//         ///     function pointer. Returns false otherwise.
//         ///
//         [[nodiscard]] bool
//         empty() const noexcept
//         {
//             return nullptr == m_func;
//         }
//     };

//     // /// @cond doxygen off

//     // /// @class bsl::delegate
//     // ///
//     // /// <!-- description -->
//     // ///   @brief Implements a simplified version of std::function. Unlike
//     // ///     std::function, a bsl::delegate has the following differences:
//     // ///     - Lambda functions, and binding in general are not supported.
//     // ///       Instead, either use a function pointer, or a member function
//     // ///       pointer. The reason is this implementation attempts to reduce
//     // ///       the overhead of std::function, and dynamic memory is not
//     // ///       supported, so the bsl::delegate has a fixed amount of memory
//     // ///       that it can support for wrapping.
//     // ///     - Operator bool is not supported as AUTOSAR does not allow for
//     // ///       the use of the conversion operator. Instead, use valid().
//     // ///     - Target access, non-member and helper functions are not supported.
//     // ///     - Functions marked as "noexcept" are supported. If the function
//     // ///       is marked as noexcept, the resulting bsl::delegate's functor
//     // ///       will also be marked as noexcept and vice versa.
//     // ///   @include example_delegate_overview.hpp
//     // ///
//     // /// <!-- template parameters -->
//     // ///   @tparam R the return value of the delegate being wrapped
//     // ///   @tparam ARGS The arguments to the delegate being wrapped
//     // ///
//     // template<typename R, typename... ARGS>
//     // class delegate<R(ARGS...) noexcept> final
//     // {
//     //     /// @brief stores whether or not this delegate is valid
//     //     bool m_valid;
//     //     /// @brief stores the call wrapper
//     //     aligned_storage_t<sizeof(void *) * 3> m_store;

//     // public:
//     //     /// @brief alias for: R
//     //     using result_type = R;

//     //     /// <!-- description -->
//     //     ///   @brief Provides support for ensuring that a bsl::delegate is a
//     //     ///     POD type, allowing it to be defined as a global resource.
//     //     ///     When used globally, a bsl::delegate should not include {},
//     //     ///     as required by AUTOSAR. The OS will automatically zero
//     //     ///     initialize the bsl::delegate for you, marking the bsl::delegate
//     //     ///     as invalid. If you use this constructor locally, you must
//     //     ///     include {} to ensure the bsl::delegate is initialized, which
//     //     ///     most compilers will warn about.
//     //     ///   @include delegate/example_delegate_default_constructor.hpp
//     //     ///
//     //     delegate() noexcept = default;

//     //     /// <!-- description -->
//     //     ///   @brief Creates a bsl::delegate from a function pointer. If the
//     //     ///     function pointer is a nullptr, the resulting bsl::delegate
//     //     ///     is marked as invalid, and will always return an error when
//     //     ///     executed.
//     //     ///   @include delegate/example_delegate_constructor_func.hpp
//     //     ///
//     //     ///   SUPPRESSION: PRQA 2180 - false positive
//     //     ///   - We suppress this because A12-1-4 states that all constructors
//     //     ///     that are callable from a fundamental type should be marked as
//     //     ///     explicit. This is not a fundamental type and there for does
//     //     ///     not apply.
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param func a pointer to the delegate being wrapped
//     //     ///
//     //     delegate(R (*const func)(ARGS...) noexcept) noexcept    // PRQA S 2180 // NOLINT
//     //         : m_valid{nullptr != func}, m_store{}
//     //     {
//     //         static_assert(sizeof(m_store) >= sizeof(details::delegate_impl_fp<R(ARGS...)>));

//     //         if (m_valid) {
//     //             construct_at<details::delegate_impl_fp<R(ARGS...) noexcept>>(&m_store, func);
//     //         }
//     //     }

//     //     /// <!-- description -->
//     //     ///   @brief Creates a bsl::delegate from a member function pointer. If
//     //     ///     the function pointer is a nullptr, the resulting bsl::delegate
//     //     ///     is marked as invalid, and will always return an error when
//     //     ///     executed.
//     //     ///   @include delegate/example_delegate_constructor_memfunc.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param t the object to execute the member function from
//     //     ///   @param func a pointer to the delegate being wrapped
//     //     ///
//     //     template<typename T, typename U>
//     //     delegate(T &t, R (U::*const func)(ARGS...) noexcept) noexcept    // --
//     //         : m_valid{nullptr != func}, m_store{}
//     //     {
//     //         static_assert(sizeof(m_store) >= sizeof(details::delegate_impl_mfp<T, R(ARGS...)>));

//     //         if (m_valid) {
//     //             construct_at<details::delegate_impl_mfp<T, R(ARGS...) noexcept>>(&m_store, &t, func);
//     //         }
//     //     }

//     //     // /// <!-- description -->
//     //     // ///   @brief Creates a bsl::delegate from a const member function
//     //     // ///     pointer. If the function pointer is a nullptr, the resulting
//     //     // ///     bsl::delegate is marked as invalid, and will always return an
//     //     // ///     error when executed.
//     //     // ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
//     //     // ///
//     //     // /// <!-- inputs/outputs -->
//     //     // ///   @param t the object to execute the member function from
//     //     // ///   @param func a pointer to the delegate being wrapped
//     //     // ///
//     //     // template<typename T, typename U>
//     //     // delegate(T const &t, R (U::*const func)(ARGS...) const noexcept) noexcept    // --
//     //     //     : m_valid{nullptr != func}, m_store{}
//     //     // {
//     //     //     static_assert(sizeof(m_store) >= sizeof(details::cdelegate_impl_mfp<T, R(ARGS...)>));

//     //     //     if (m_valid) {
//     //     //         construct_at<details::cdelegate_impl_mfp<T, R(ARGS...) noexcept>>(&m_store, t, func);
//     //     //     }
//     //     // }

//     //     /// <!-- description -->
//     //     ///   @brief Execute the bsl::delegate by calling the wrapped function
//     //     ///     with "args" and returning the result.
//     //     ///   @include delegate/example_delegate_functor.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param args the arguments to pass to the wrapped function
//     //     ///   @return returns the results of the wrapped function
//     //     ///
//     //     [[nodiscard]] result<R>
//     //     operator()(ARGS &&... args) const noexcept
//     //     {
//     //         if (m_valid) {
//     //             details::delegate_impl<R(ARGS...) noexcept> const *const ptr{
//     //                 details::cast<details::delegate_impl<R(ARGS...) noexcept>>(&m_store)};

//     //             return {bsl::in_place, ptr->call(bsl::forward<ARGS>(args)...)};
//     //         }

//     //         return {bsl::errc_bad_function};
//     //     }

//     //     /// <!-- description -->
//     //     ///   @brief If the bsl::delegate is valid, returns true, otherwise
//     //     ///     returns false.
//     //     ///   @include delegate/example_delegate_valid.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @return If the bsl::delegate is valid, returns true, otherwise
//     //     ///     returns false.
//     //     ///
//     //     [[nodiscard]] bool
//     //     valid() const noexcept
//     //     {
//     //         return m_valid;
//     //     }
//     // };

//     // /// @class bsl::delegate<void(ARGS...)>
//     // ///
//     // /// <!-- description -->
//     // ///   @brief Implements a simplified version of std::function. Unlike
//     // ///     std::function, a bsl::delegate has the following differences:
//     // ///     - Lambda functions, and binding in general are not supported.
//     // ///       Instead, either use a function pointer, or a member function
//     // ///       pointer. The reason is this implementation attempts to reduce
//     // ///       the overhead of std::function, and dynamic memory is not
//     // ///       supported, so the bsl::delegate has a fixed amount of memory
//     // ///       that it can support for wrapping.
//     // ///     - Operator bool is not supported as AUTOSAR does not allow for
//     // ///       the use of the conversion operator. Instead, use valid().
//     // ///     - Target access, non-member and helper functions are not supported.
//     // ///     - Functions marked as "noexcept" are supported. If the function
//     // ///       is marked as noexcept, the resulting bsl::delegate's functor
//     // ///       will also be marked as noexcept and vice versa.
//     // ///   @include example_delegate_overview.hpp
//     // ///
//     // /// <!-- template parameters -->
//     // ///   @tparam ARGS The arguments to the delegate being wrapped
//     // ///
//     // template<typename... ARGS>
//     // class delegate<void(ARGS...)> final
//     // {
//     //     /// @brief stores whether or not this delegate is valid
//     //     bool m_valid;
//     //     /// @brief stores the call wrapper
//     //     aligned_storage_t<sizeof(void *) * 3> m_store;

//     // public:
//     //     /// @brief alias for: void
//     //     using result_type = void;

//     //     /// <!-- description -->
//     //     ///   @brief Provides support for ensuring that a bsl::delegate is a
//     //     ///     POD type, allowing it to be defined as a global resource.
//     //     ///     When used globally, a bsl::delegate should not include {},
//     //     ///     as required by AUTOSAR. The OS will automatically zero
//     //     ///     initialize the bsl::delegate for you, marking the bsl::delegate
//     //     ///     as invalid. If you use this constructor locally, you must
//     //     ///     include {} to ensure the bsl::delegate is initialized, which
//     //     ///     most compilers will warn about.
//     //     ///   @include delegate/example_delegate_default_constructor.hpp
//     //     ///
//     //     delegate() noexcept = default;

//     //     /// <!-- description -->
//     //     ///   @brief Creates a bsl::delegate from a function pointer. If the
//     //     ///     function pointer is a nullptr, the resulting bsl::delegate
//     //     ///     is marked as invalid, and will always return an error when
//     //     ///     executed.
//     //     ///   @include delegate/example_delegate_constructor_func.hpp
//     //     ///
//     //     ///   SUPPRESSION: PRQA 2180 - false positive
//     //     ///   - We suppress this because A12-1-4 states that all constructors
//     //     ///     that are callable from a fundamental type should be marked as
//     //     ///     explicit. This is not a fundamental type and there for does
//     //     ///     not apply.
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param func a pointer to the delegate being wrapped
//     //     ///
//     //     delegate(void (*const func)(ARGS...)) noexcept    // PRQA S 2180 // NOLINT
//     //         : m_valid{nullptr != func}, m_store{}
//     //     {
//     //         static_assert(sizeof(m_store) >= sizeof(details::delegate_impl_fp<void(ARGS...)>));

//     //         if (m_valid) {
//     //             construct_at<details::delegate_impl_fp<void(ARGS...)>>(&m_store, func);
//     //         }
//     //     }

//     //     /// <!-- description -->
//     //     ///   @brief Creates a bsl::delegate from a member function pointer. If
//     //     ///     the function pointer is a nullptr, the resulting bsl::delegate
//     //     ///     is marked as invalid, and will always return an error when
//     //     ///     executed.
//     //     ///   @include delegate/example_delegate_constructor_memfunc.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param t the object to execute the member function from
//     //     ///   @param func a pointer to the delegate being wrapped
//     //     ///
//     //     template<typename T, typename U>
//     //     delegate(T &t, void (U::*const func)(ARGS...)) noexcept    // --
//     //         : m_valid{nullptr != func}, m_store{}
//     //     {
//     //         static_assert(sizeof(m_store) >= sizeof(details::delegate_impl_mfp<T, void(ARGS...)>));

//     //         if (m_valid) {
//     //             construct_at<details::delegate_impl_mfp<T, void(ARGS...)>>(&m_store, &t, func);
//     //         }
//     //     }

//     //     // /// <!-- description -->
//     //     // ///   @brief Creates a bsl::delegate from a const member function
//     //     // ///     pointer. If the function pointer is a nullptr, the resulting
//     //     // ///     bsl::delegate is marked as invalid, and will always return an
//     //     // ///     error when executed.
//     //     // ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
//     //     // ///
//     //     // /// <!-- inputs/outputs -->
//     //     // ///   @param t the object to execute the member function from
//     //     // ///   @param func a pointer to the delegate being wrapped
//     //     // ///
//     //     // template<typename T, typename U>
//     //     // delegate(T const &t, void (U::*const func)(ARGS...) const) noexcept    // --
//     //     //     : m_valid{nullptr != func}, m_store{}
//     //     // {
//     //     //     static_assert(sizeof(m_store) >= sizeof(details::cdelegate_impl_mfp<T, void(ARGS...)>));

//     //     //     if (m_valid) {
//     //     //         construct_at<details::cdelegate_impl_mfp<T, void(ARGS...)>>(&m_store, t, func);
//     //     //     }
//     //     // }

//     //     /// <!-- description -->
//     //     ///   @brief Execute the bsl::delegate by calling the wrapped function
//     //     ///     with "args".
//     //     ///   @include delegate/example_delegate_functor.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param args the arguments to pass to the wrapped function
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @throw throws if the wrapped function throws
//     //     ///
//     //     void
//     //     operator()(ARGS &&... args) const noexcept(false)
//     //     {
//     //         if (m_valid) {
//     //             details::delegate_impl<void(ARGS...)> const *const ptr{
//     //                 details::cast<details::delegate_impl<void(ARGS...)>>(&m_store)};

//     //             ptr->call(bsl::forward<ARGS>(args)...);
//     //         }
//     //     }

//     //     /// <!-- description -->
//     //     ///   @brief If the bsl::delegate is valid, returns true, otherwise
//     //     ///     returns false.
//     //     ///   @include delegate/example_delegate_valid.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @return If the bsl::delegate is valid, returns true, otherwise
//     //     ///     returns false.
//     //     ///
//     //     [[nodiscard]] bool
//     //     valid() const noexcept
//     //     {
//     //         return m_valid;
//     //     }
//     // };

//     // /// @class bsl::delegate<void(ARGS...) noexcept>
//     // ///
//     // /// <!-- description -->
//     // ///   @brief Implements a simplified version of std::function. Unlike
//     // ///     std::function, a bsl::delegate has the following differences:
//     // ///     - Lambda functions, and binding in general are not supported.
//     // ///       Instead, either use a function pointer, or a member function
//     // ///       pointer. The reason is this implementation attempts to reduce
//     // ///       the overhead of std::function, and dynamic memory is not
//     // ///       supported, so the bsl::delegate has a fixed amount of memory
//     // ///       that it can support for wrapping.
//     // ///     - Operator bool is not supported as AUTOSAR does not allow for
//     // ///       the use of the conversion operator. Instead, use valid().
//     // ///     - Target access, non-member and helper functions are not supported.
//     // ///     - Functions marked as "noexcept" are supported. If the function
//     // ///       is marked as noexcept, the resulting bsl::delegate's functor
//     // ///       will also be marked as noexcept and vice versa.
//     // ///   @include example_delegate_overview.hpp
//     // ///
//     // /// <!-- template parameters -->
//     // ///   @tparam ARGS The arguments to the delegate being wrapped
//     // ///
//     // template<typename... ARGS>
//     // class delegate<void(ARGS...) noexcept> final
//     // {
//     //     /// @brief stores whether or not this delegate is valid
//     //     bool m_valid;
//     //     /// @brief stores the call wrapper
//     //     aligned_storage_t<sizeof(void *) * 3> m_store;

//     // public:
//     //     /// @brief alias for: void
//     //     using result_type = void;

//     //     /// <!-- description -->
//     //     ///   @brief Provides support for ensuring that a bsl::delegate is a
//     //     ///     POD type, allowing it to be defined as a global resource.
//     //     ///     When used globally, a bsl::delegate should not include {},
//     //     ///     as required by AUTOSAR. The OS will automatically zero
//     //     ///     initialize the bsl::delegate for you, marking the bsl::delegate
//     //     ///     as invalid. If you use this constructor locally, you must
//     //     ///     include {} to ensure the bsl::delegate is initialized, which
//     //     ///     most compilers will warn about.
//     //     ///   @include delegate/example_delegate_default_constructor.hpp
//     //     ///
//     //     delegate() noexcept = default;

//     //     /// <!-- description -->
//     //     ///   @brief Creates a bsl::delegate from a function pointer. If the
//     //     ///     function pointer is a nullptr, the resulting bsl::delegate
//     //     ///     is marked as invalid, and will always return an error when
//     //     ///     executed.
//     //     ///   @include delegate/example_delegate_constructor_func.hpp
//     //     ///
//     //     ///   SUPPRESSION: PRQA 2180 - false positive
//     //     ///   - We suppress this because A12-1-4 states that all constructors
//     //     ///     that are callable from a fundamental type should be marked as
//     //     ///     explicit. This is not a fundamental type and there for does
//     //     ///     not apply.
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param func a pointer to the delegate being wrapped
//     //     ///
//     //     delegate(void (*const func)(ARGS...) noexcept) noexcept    // PRQA S 2180 // NOLINT
//     //         : m_valid{nullptr != func}, m_store{}
//     //     {
//     //         static_assert(sizeof(m_store) >= sizeof(details::delegate_impl_fp<void(ARGS...)>));

//     //         if (m_valid) {
//     //             construct_at<details::delegate_impl_fp<void(ARGS...) noexcept>>(&m_store, func);
//     //         }
//     //     }

//     //     /// <!-- description -->
//     //     ///   @brief Creates a bsl::delegate from a member function pointer. If
//     //     ///     the function pointer is a nullptr, the resulting bsl::delegate
//     //     ///     is marked as invalid, and will always return an error when
//     //     ///     executed.
//     //     ///   @include delegate/example_delegate_constructor_memfunc.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param t the object to execute the member function from
//     //     ///   @param func a pointer to the delegate being wrapped
//     //     ///
//     //     template<typename T, typename U>
//     //     delegate(T &t, void (U::*const func)(ARGS...) noexcept) noexcept    // --
//     //         : m_valid{nullptr != func}, m_store{}
//     //     {
//     //         static_assert(sizeof(m_store) >= sizeof(details::delegate_impl_mfp<T, void(ARGS...)>));

//     //         if (m_valid) {
//     //             construct_at<details::delegate_impl_mfp<T, void(ARGS...) noexcept>>(&m_store, &t, func);
//     //         }
//     //     }

//     //     // /// <!-- description -->
//     //     // ///   @brief Creates a bsl::delegate from a const member function
//     //     // ///     pointer. If the function pointer is a nullptr, the resulting
//     //     // ///     bsl::delegate is marked as invalid, and will always return an
//     //     // ///     error when executed.
//     //     // ///   @include delegate/example_delegate_constructor_cmemfunc.hpp
//     //     // ///
//     //     // /// <!-- inputs/outputs -->
//     //     // ///   @param t the object to execute the member function from
//     //     // ///   @param func a pointer to the delegate being wrapped
//     //     // ///
//     //     // template<typename T, typename U>
//     //     // delegate(T const &t, void (U::*const func)(ARGS...) const noexcept) noexcept    // --
//     //     //     : m_valid{nullptr != func}, m_store{}
//     //     // {
//     //     //     static_assert(sizeof(m_store) >= sizeof(details::cdelegate_impl_mfp<T, void(ARGS...)>));

//     //     //     if (m_valid) {
//     //     //         construct_at<details::cdelegate_impl_mfp<T, void(ARGS...) noexcept>>(
//     //     //             &m_store, t, func);
//     //     //     }
//     //     // }

//     //     /// <!-- description -->
//     //     ///   @brief Execute the bsl::delegate by calling the wrapped function
//     //     ///     with "args".
//     //     ///   @include delegate/example_delegate_functor.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @param args the arguments to pass to the wrapped function
//     //     ///
//     //     void
//     //     operator()(ARGS &&... args) const noexcept
//     //     {
//     //         if (m_valid) {
//     //             details::delegate_impl<void(ARGS...) noexcept> const *const ptr{
//     //                 details::cast<details::delegate_impl<void(ARGS...) noexcept>>(&m_store)};

//     //             ptr->call(bsl::forward<ARGS>(args)...);
//     //         }
//     //     }

//     //     /// <!-- description -->
//     //     ///   @brief If the bsl::delegate is valid, returns true, otherwise
//     //     ///     returns false.
//     //     ///   @include delegate/example_delegate_valid.hpp
//     //     ///
//     //     /// <!-- inputs/outputs -->
//     //     ///   @return If the bsl::delegate is valid, returns true, otherwise
//     //     ///     returns false.
//     //     ///
//     //     [[nodiscard]] bool
//     //     valid() const noexcept
//     //     {
//     //         return m_valid;
//     //     }
//     // };

//     /// @brief deduction guideline for bsl::delegate
//     delegate()->delegate<void() noexcept>;

//     /// @brief deduction guideline for bsl::delegate
//     template<typename R, typename... ARGS>
//     delegate(R (*)(ARGS...)) -> delegate<R(ARGS...), void>;

//     /// @brief deduction guideline for bsl::delegate
//     template<typename T, typename U, typename R, typename... ARGS>
//     delegate(T *t, R (U::*)(ARGS...)) -> delegate<R(ARGS...), T>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename R, typename... ARGS>
//     // delegate(T const &t, R (U::*)(ARGS...) const) -> delegate<R(ARGS...)>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename R, typename... ARGS>
//     // delegate(R (*)(ARGS...) noexcept) -> delegate<R(ARGS...) noexcept>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename R, typename... ARGS>
//     // delegate(T &t, R (U::*)(ARGS...) noexcept) -> delegate<R(ARGS...) noexcept>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename R, typename... ARGS>
//     // delegate(T const &t, R (U::*)(ARGS...) const noexcept) -> delegate<R(ARGS...) noexcept>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename... ARGS>
//     // delegate(void (*)(ARGS...)) -> delegate<void(ARGS...)>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename... ARGS>
//     // delegate(T &t, void (U::*)(ARGS...)) -> delegate<void(ARGS...)>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename... ARGS>
//     // delegate(T const &t, void (U::*)(ARGS...) const) -> delegate<void(ARGS...)>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename... ARGS>
//     // delegate(void (*)(ARGS...) noexcept) -> delegate<void(ARGS...) noexcept>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename... ARGS>
//     // delegate(T &t, void (U::*)(ARGS...) noexcept) -> delegate<void(ARGS...) noexcept>;

//     // /// @brief deduction guideline for bsl::delegate
//     // template<typename T, typename U, typename... ARGS>
//     // delegate(T const &t, void (U::*)(ARGS...) const noexcept) -> delegate<void(ARGS...) noexcept>;

//     /// @endcond doxygen on
