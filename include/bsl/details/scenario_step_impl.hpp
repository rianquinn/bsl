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

#ifndef BSL_DETAILS_SCENARIO_STEP_IMPL_HPP
#define BSL_DETAILS_SCENARIO_STEP_IMPL_HPP

#include "ut_helpers.hpp"

namespace bsl
{
    namespace details
    {
        class scenario_step_impl final
        {
        public:
            constexpr scenario_step_impl() noexcept = default;

            template<typename FUNC>
            [[maybe_unused]] constexpr scenario_step_impl &
            operator=(FUNC &&func) noexcept
            {
                bsl::forward<FUNC>(func)();
                return *this;    // PRQA S 2880
            }

            constexpr scenario_step_impl(scenario_step_impl const &o) noexcept = delete;
            constexpr scenario_step_impl(scenario_step_impl &&o) noexcept = delete;

            [[maybe_unused]] constexpr scenario_step_impl &
            operator=(scenario_step_impl const &o) &noexcept = delete;
            [[maybe_unused]] constexpr scenario_step_impl &
            operator=(scenario_step_impl &&o) &noexcept = delete;

            ~scenario_step_impl() noexcept = default;
        };
    }
}

#endif
