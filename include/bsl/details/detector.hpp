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

#ifndef BSL_DETAILS_DETECTOR_HPP
#define BSL_DETAILS_DETECTOR_HPP

#include "../void_t.hpp"

namespace bsl
{
    namespace details
    {
        /// @class bsl::detector
        ///
        /// <!-- description -->
        ///   @brief If the provided operation is detected, provides the
        ///     member constant value equal to true. Otherwise the member
        ///     constant value is false.
        ///   @include detector/overview.cpp
        ///
        /// <!-- template parameters -->
        ///   @tparam T the type to query
        ///
        template<typename Default, typename, template<typename...> class Op, typename... Args>
        struct detector final
        {
            /// @brief the boolean that answers the type trait query
            static constexpr bool value{false};
        };

        /// @cond

        template<typename Default, template<typename...> class Op, typename... Args>
        struct detector<Default, bsl::void_t<Op<Args...>>, Op, Args...> final
        {
            /// @brief the boolean that answers the type trait query
            static constexpr bool value{true};
        };

        /// @endcond
    }
}

#endif
