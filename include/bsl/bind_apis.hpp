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
/// @file bind_apis.hpp
///

#ifndef BSL_BIND_APIS_HPP
#define BSL_BIND_APIS_HPP

namespace bsl
{
    /// @class bsl::bind_apis
    ///
    /// <!-- description -->
    ///   @brief Binds a set of APIs (i.e., and interface) to an implementation
    ///     for those APIs. This is the foundational class to our Static
    ///     Interface Pattern, which can be used to implement S.O.L.I.D.
    ///     without the need for virtual inheritance. This not only ensures
    ///     we have well defined interfaces, it supports better unit testing
    ///     as each set of APIs can be mocked using template substitution
    ///     instead of mocking. To implement the static interface pattern,
    ///     this class uses Curiously Recurring Template Pattern. The overall
    ///     goal of this class is to hide the nasty details of this pattern,
    ///     ensuring interfaces and implementations can be developed without
    ///     the rest of the code becoming unreadable.
    ///   @include bind_apis/overview.cpp
    ///
    ///   SUPPRESSION: PRQA 2023 - exception required
    ///   - We suppress this because A13-3-1 states that you should not
    ///     overload functions that contain a forwarding reference because it
    ///     is confusing to the user. PRQA is detecting the presence of a
    ///     default copy/move constructor and stating that these default
    ///     functions are overloading our constructor which provides a direct
    ///     pass-through to the implementation. In this case, there is nothing
    ///     ambiguous to the user about this situation, and the spec doesn't
    ///     state whether PRQA is correct or not as the examples all discuss
    ///     explicit function definitons and not implicitly default functions.
    ///     For this reason, PRQA is free to assume this rule includes
    ///     implicitly defaulted functions, and therefore, an exception to this
    ///     rule is required. It should be noted that objects like std::pair,
    ///     std::tuple and std::variant, which are all encouraged by the
    ///     spec have the same issue with this rule, so it is clear it needs
    ///     a better definition to ensure the library the spec demands can
    ///     actually be compliant with the spec itself.
    ///
    /// <!-- template parameters -->
    ///   @tparam APIS the type that defines the APIs to bind. Note that the
    ///     APIs type must be default constructable, and subclassable.
    ///   @tparam IMPL the implementation to bind to the provide APIs. Note
    ///     that the IMPL type must provide an implementation of the functions
    ///     expected by the APIs.
    ///
    template<template<typename> class APIS, typename IMPL>
    class bind_apis final : public APIS<bind_apis<APIS, IMPL>>    // PRQA S 2023
    {
    public:
        /// @brief defines the implementation's type used for static calls
        using impl_type = IMPL;

        /// <!-- description -->
        ///   @brief Used to create an object that has a set of APIs bound to
        ///     to an implementation. All of the arguments are passed to the
        ///     implementation.
        ///   @include  bind_apis/constructor.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam ARGS the argument types
        ///   @param args the arguments to pass to the implementation
        ///
        /// <!-- exceptions -->
        ///   @throw throws if impl throws
        ///
        template<typename... ARGS>
        explicit bind_apis(ARGS &&... args)
            : APIS<bind_apis<APIS, IMPL>>{}, m_d{bsl::forward<ARGS>(args)...}
        {}

    protected:
        /// <!-- description -->
        ///   @brief Returns a reference to the implementation of the bound
        ///     object given a pointer to the APIs. This is used by the APIs
        ///     to convert "this" into a reference to the implementation so
        ///     that the APIs can call into the implementation to execute the
        ///     API itself.
        ///
        ///   SUPPRESSION: PRQA 3070 - exception required
        ///   - We suppress this because M5-2-3 states that a downcast is
        ///     not allowed. Although this is a down cast, it is not a virtual
        ///     downcast. In other words, this downcast is safe as it is
        ///     statically enforceable at compile time as this implements the
        ///     CFTP. This rule also states that something might change in the
        ///     future. We use the CFTP specifically to detect this type of
        ///     issue at compile time (its the whole reason we have the static
        ///     interface pattern). In other words, in this case, the rule
        ///     does not apply as the complaint is satisfied.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param apis a pointer to the APIs.
        ///   @return a reference to the implementation of the provided APIs.
        ///
        /// <!-- exceptions -->
        ///   @throw throws if impl throws
        ///
        constexpr static IMPL &
        impl(APIS<bind_apis<APIS, IMPL>> *const apis)
        {
            return static_cast<bind_apis<APIS, IMPL> *>(apis)->m_d;    // PRQA S 3070
        }

        /// <!-- description -->
        ///   @brief Returns a reference to the implementation of the bound
        ///     object given a pointer to the APIs. This is used by the APIs
        ///     to convert "this" into a reference to the implementation so
        ///     that the APIs can call into the implementation to execute the
        ///     API itself.
        ///
        ///   SUPPRESSION: PRQA 3070 - exception required
        ///   - We suppress this because M5-2-3 states that a downcast is
        ///     not allowed. Although this is a down cast, it is not a virtual
        ///     downcast. In other words, this downcast is safe as it is
        ///     statically enforceable at compile time as this implements the
        ///     CFTP. This rule also states that something might change in the
        ///     future. We use the CFTP specifically to detect this type of
        ///     issue at compile time (its the whole reason we have the static
        ///     interface pattern). In other words, in this case, the rule
        ///     does not apply as the complaint is satisfied.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param apis a pointer to the APIs.
        ///   @return a reference to the implementation of the provided APIs.
        ///
        /// <!-- exceptions -->
        ///   @throw throws if impl throws
        ///
        constexpr static IMPL const &
        impl(APIS<bind_apis<APIS, IMPL>> const *const apis)
        {
            return static_cast<bind_apis<APIS, IMPL> const *>(apis)->m_d;    // PRQA S 3070
        }

    private:
        /// @brief stores the implementation of the APIs.
        IMPL m_d;
    };
}

#endif
