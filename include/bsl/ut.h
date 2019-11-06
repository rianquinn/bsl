//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BSL_UT_H
#define BSL_UT_H

#include "console_colors.h"
#include "source_location.h"

#include <list>
#include <iostream>

// -----------------------------------------------------------------------------
// Definition
// -----------------------------------------------------------------------------

namespace bsl
{
    class test_case
    {
        using name_type = const char *;
        using test_type = void (*)(void);

    public:
        explicit constexpr test_case(name_type name) :
            m_name{name}
        {}

        ~test_case();

        constexpr auto
        operator=(test_type test) -> test_case &
        {
            m_test = test;
            return *this;
        }

    private:
        name_type m_name;
        test_type m_test{};

    public:
        // clang-format off
        test_case(const test_case &) = default;
        test_case &operator=(const test_case &) = default;
        test_case(test_case &&) noexcept = default;
        test_case &operator=(test_case &&) noexcept = default;
        // clang-format on
    };

    namespace details::ut
    {
        class runner
        {
            std::list<test_case> m_test_cases;
        };

        inline runner g_runner;
    }

    test_case::~test_case()
    {
        details::ut::m_test_cases.push_back(*this);
    }
}

#endif
