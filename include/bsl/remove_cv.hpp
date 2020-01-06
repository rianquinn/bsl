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
/// @file remove_cv.hpp
///

#ifndef BSL_REMOVE_CV_HPP
#define BSL_REMOVE_CV_HPP

#include "remove_const.hpp"
#include "remove_volatile.hpp"

namespace bsl
{
    /// @class bsl::remove_cv
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that its topmost cv-qualifiers are removed.
    ///   @include remove_cv/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to remove the CV qualifer from
    ///
    template<class T>
    struct remove_cv : enable_if<true, remove_const_t<remove_volatile_t<T>>>
    {};

    /// @brief a helper that reduces the verbosity of std::remove_cv
    template<typename T>
    using remove_cv_t = typename remove_cv<T>::type;
}    // namespace bsl

#endif
