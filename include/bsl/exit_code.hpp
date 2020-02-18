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
/// @file exit_code.hpp
///

#ifndef BSL_EXIT_CODE_HPP
#define BSL_EXIT_CODE_HPP

#include "cstdint.hpp"

namespace bsl
{
    /// @enum bsl::exit_code
    ///
    /// <!-- description -->
    ///   @brief Defines the supported exit codes that are passed to bsl::exit
    ///     or returned from bsl_main(). These are similar to EXIT_SUCCESS
    ///     and EXIT_FAILURE without the use of macros.
    ///
    enum class exit_code : bsl::int32
    {
        /// @brief represents a successful exit
        exit_success = 0,
        /// @brief represents a failed exit
        exit_failure = 1
    };
}

#endif
