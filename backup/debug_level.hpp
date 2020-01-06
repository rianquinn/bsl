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
/// @file debug_level.hpp
///

#ifndef BSL_DEBUG_LEVEL_HPP
#define BSL_DEBUG_LEVEL_HPP

#include "types.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Defines the different supported debug levels used by the
    ///     debug statements in debug.hpp
    ///
    enum class debug_level_t : std::uint32_t {
        verbosity_level_0 = 0,
        verbosity_level_1 = 1,
        verbosity_level_2 = 2,
        verbosity_level_3 = 3
    };

    /// @brief used to state that a debug statement should be included in -v
    constexpr debug_level_t V{debug_level_t::verbosity_level_1};
    /// @brief used to state that a debug statement should be included in -vv
    constexpr debug_level_t VV{debug_level_t::verbosity_level_2};
    /// @brief used to state that a debug statement should be included in -vvv
    constexpr debug_level_t VVV{debug_level_t::verbosity_level_3};
}    // namespace bsl

#endif
