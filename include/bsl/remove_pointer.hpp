/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
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
/// @file remove_pointer.hpp
///

#ifndef BSL_REMOVE_POINTER_HPP
#define BSL_REMOVE_POINTER_HPP

namespace bsl
{
    /// @class bsl::remove_pointer
    ///
    /// <!-- description -->
    ///   @brief Provides the member typedef type which is the same as T,
    ///     except that its topmost pointer is removed.
    ///   @include example_remove_pointer_overview.hpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type to remove the pointer from
    ///
    template<typename T>
    struct remove_pointer final
    {
        /// @brief provides the member typedef "type"
        using type = T;
    };

    /// @brief a helper that reduces the verbosity of bsl::remove_pointer
    template<typename T>
    using remove_pointer_t = typename remove_pointer<T>::type;

    /// @cond doxygen off

    template<typename T>
    struct remove_pointer<T *> final
    {
        /// @brief provides the member typedef "type"
        using type = T;
    };

    template<typename T>
    struct remove_pointer<T *const> final
    {
        /// @brief provides the member typedef "type"
        using type = T;
    };

    /// @endcond doxygen on
}

#endif
