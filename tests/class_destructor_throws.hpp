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

#ifndef TESTS_CLASS_DESTRUCTOR_THROWS_HPP
#define TESTS_CLASS_DESTRUCTOR_THROWS_HPP

namespace test
{
    class class_destructor_throws final
    {
    public:
        constexpr class_destructor_throws() noexcept = default;
        constexpr ~class_destructor_throws() noexcept(false) = default;
        constexpr class_destructor_throws(class_destructor_throws const &) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(class_destructor_throws const &) &noexcept
            -> class_destructor_throws & = default;
        constexpr class_destructor_throws(class_destructor_throws &&) noexcept = default;
        [[maybe_unused]] constexpr auto operator=(class_destructor_throws &&) &noexcept
            -> class_destructor_throws & = default;
    };
}

#endif