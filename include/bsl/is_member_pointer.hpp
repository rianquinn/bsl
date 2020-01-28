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
/// @file is_member_pointer.hpp
///

#ifndef BSL_IS_MEMBER_POINTER_HPP
#define BSL_IS_MEMBER_POINTER_HPP

namespace bsl
{
    /// @class bsl::is_member_pointer
    ///
    /// <!-- description -->
    ///   @brief If the provided type is a member pointer type (taking into
    ///     account const qualifications), provides the member constant value
    ///     equal to true. Otherwise the member constant value is false.
    ///   @include is_member_pointer/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to query
    ///
    template<typename T>
    struct is_member_pointer final
    {
        /// @brief the boolean that answers the type trait query
        static constexpr bool value{false};
    };

    /// @cond

    template<typename T, typename U>
    struct is_member_pointer<T U::*> final
    {
        static constexpr bool value{true};
    };

    template<typename T, typename U>
    struct is_member_pointer<T U::*const> final
    {
        static constexpr bool value{true};
    };

    /// @endcond
}

#endif
