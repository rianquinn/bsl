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

#ifndef BSL_FINALLY
#define BSL_FINALLY

// clang-format off

namespace bsl
{
    ///
    template<
        typename FUNC,
        std::enable_if_t<std::is_nothrow_invocable_v<FUNC>, int> = 0>
    class finally
    {
        FUNC m_func{};

    public:
        explicit finally(FUNC &&func) noexcept :
            m_func(std::move(func))
        {}

        ~finally() noexcept
        {
            m_func();
        }

    public:
        finally(const finally &) = delete;
        finally &operator=(const finally &) = delete;
        finally(finally &&) noexcept = delete;
        finally &operator=(finally &&) noexcept = delete;
    };

}    // namespace bsl

// clang-format on

#endif