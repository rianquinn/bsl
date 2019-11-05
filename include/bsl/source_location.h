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

#ifndef BSL_SOURCE_LOCATION
#define BSL_SOURCE_LOCATION

#include <cstdint>

namespace bsl
{
    class source_location
    {
        using file_type = const char *;
        using func_type = const char *;
        using line_type = std::uint_least32_t;
        using column_type = std::uint_least32_t;

        constexpr source_location(
            file_type file, func_type func, line_type line) noexcept :
            m_file{file}, m_func{func}, m_line{line}
        {}

    public:
        static constexpr auto
        current(
            file_type file = __builtin_FILE(),
            func_type func = __builtin_FUNCTION(),
            line_type line = __builtin_LINE()) noexcept -> source_location
        {
            return {file, func, line};
        }

        [[nodiscard]] constexpr auto
        file() const noexcept -> file_type
        {
            return m_file;
        }

        [[nodiscard]] constexpr auto
        function() const noexcept -> file_type
        {
            return m_func;
        }

        [[nodiscard]] constexpr auto
        line() const noexcept -> line_type
        {
            return m_line;
        }

        [[nodiscard]] static constexpr auto
        column() noexcept -> column_type
        {
            return 0;
        }

    private:
        file_type m_file;
        file_type m_func;
        line_type m_line;
    };
}    // namespace bsl

#endif
