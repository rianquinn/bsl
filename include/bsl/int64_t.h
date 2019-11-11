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

#include "contracts.h"

#include <cstdint>
#include <type_traits>

namespace bsl
{
    // ----------------------------------------------------------------------
    // int64_t
    // ----------------------------------------------------------------------

    class int64_t
    {
        using value_type = ::int64_t;
        value_type m_val{};

    public:
        constexpr int64_t() noexcept = default;
        ~int64_t() noexcept = default;

        explicit constexpr int64_t(value_type val) noexcept : m_val{val}
        {}

        constexpr int64_t(const int64_t &val) noexcept : m_val{val.m_val}
        {}

        constexpr auto
        operator=(const int64_t &val) noexcept -> int64_t &
        {
            m_val = val.m_val;
            return *this;
        }

        constexpr int64_t(int64_t &&val) noexcept : m_val{val.m_val}
        {}

        constexpr auto
        operator=(int64_t &&val) noexcept -> int64_t &
        {
            m_val = val.m_val;
            return *this;
        }

        constexpr operator value_type() const noexcept
        {
            return m_val;
        }

        constexpr auto
        get() const noexcept -> value_type
        {
            return m_val;
        }

        template<typename T>
        auto
        narrow() const -> T
        {
            if constexpr (std::is_unsigned_v<T>) {
                bsl::ensures(m_val >= 0);
            }

            auto result = static_cast<T>(m_val);
            bsl::ensures(static_cast<value_type>(result) == m_val);
            return result;
        }

        // narrow
        // to_string
        // to_hex_string
        // to_ptr (uint64_t only)
        // from pointer constructor (uint64_t only)
        // + - * ^ & | ~ < > += -= *= ^= &= |= << >> >>= <<= == != <= >= ++ --
        // / % ! /= %= <=> (since C++20) && ||  , ->* -> ( ) [ ] co_await (since
        // C++20)
    };
}    // namespace bsl

// -------------------------------------------------------------------------
// int64_t rational operators
// -------------------------------------------------------------------------

template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
constexpr auto
operator==(const bsl::int64_t &lhs, const T rhs) noexcept -> bool
{
    if constexpr (std::is_same_v<T, int64_t>) {
        return lhs.get() == rhs;
    }

    if constexpr (std::is_signed_v<T>) {
        return lhs.get() == static_cast<int64_t>(rhs);
    }

    return lhs.narrow<T>() == rhs;
}

template<typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
constexpr auto
operator!=(const bsl::int64_t &lhs, const T rhs) noexcept -> bool
{
    return !(lhs == rhs);
}

static_assert(sizeof(bsl::int64_t) == 8);
static_assert(sizeof(void *) == 8);    // 64 bit check
