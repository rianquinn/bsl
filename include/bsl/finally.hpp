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

#ifndef BSL_FINALLY_HPP
#define BSL_FINALLY_HPP

#include <utility>
#include <type_traits>

namespace bsl
{
    template<
        typename FUNC,
        std::enable_if_t<std::is_nothrow_invocable_v<FUNC>> * = nullptr>
    class finally
    {
        FUNC m_func{};

    public:
        explicit constexpr finally(FUNC &&func) noexcept :
            m_func(std::move(func))
        {}

        ~finally() noexcept
        {
            m_func();
        }

        finally(const finally &) = delete;
        auto operator=(const finally &) -> finally & = delete;
        finally(finally &&) noexcept = delete;
        auto operator=(finally &&) noexcept -> finally & = delete;
    };

    template<typename FUNC>
    finally(FUNC &&func)->finally<FUNC>;

}    // namespace bsl

#endif
