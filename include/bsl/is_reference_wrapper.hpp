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
/// @file is_reference_wrapper.hpp
///

#ifndef BSL_IS_REFERENCE_WRAPPER_HPP
#define BSL_IS_REFERENCE_WRAPPER_HPP

#include "true_type.hpp"
#include "false_type.hpp"

namespace bsl
{
    /// @brief reference_wrapper prototype
    template<typename T>
    class reference_wrapper;

    /// @class bsl::is_reference_wrapper
    ///
    /// <!-- description -->
    ///   @brief If the provided type is a reference_wrapper (taking into
    ///     account const qualifications), provides the member constant value
    ///     equal to true. Otherwise the member constant value is false.
    ///   @include example_is_reference_wrapper_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    class is_reference_wrapper final : public false_type
    {};

    /// @cond --

    template<typename T>
    class is_reference_wrapper<reference_wrapper<T>> final : public true_type
    {};

    template<typename T>
    class is_reference_wrapper<reference_wrapper<T> const> final : public true_type
    {};

    /// @endcond --
}

#endif
