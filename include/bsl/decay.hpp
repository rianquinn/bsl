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
/// @file decay.hpp
///

#ifndef BSL_DECAY_HPP
#define BSL_DECAY_HPP

#include "add_pointer.hpp"
#include "conditional.hpp"
#include "is_array.hpp"
#include "is_function.hpp"
#include "remove_const.hpp"
#include "remove_extent.hpp"
#include "remove_reference.hpp"
#include "type_identity.hpp"

namespace bsl
{
    /// @class bsl::decay
    ///
    /// <!-- description -->
    ///   @brief Applies lvalue-to-rvalue, array-to-pointer, and
    ///     function-to-pointer implicit conversions to the type T,
    ///     removes cv-qualifiers, and defines the resulting type as the
    ///     member typedef type
    ///   @include decay/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to add a const qualifier to
    ///
    template<typename T>
    class decay final :
        public type_identity<typename conditional<
            is_array<typename remove_reference<T>::type>::value,
            typename remove_extent<typename remove_reference<T>::type>::type *,
            typename conditional<
                is_function<typename remove_reference<T>::type>::value,
                typename add_pointer<typename remove_reference<T>::type>::type,
                typename remove_const<typename remove_reference<T>::type>::type>::type>::type>
    {};
}

#endif
