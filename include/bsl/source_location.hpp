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

#ifndef BSL_SOURCE_LOCATION_HPP
#define BSL_SOURCE_LOCATION_HPP

#include <cstdint>

namespace bsl
{
    /// Source Location
    ///
    /// The following implements the source_location specification that will
    /// eventually be included in C++20. For more information on how this
    /// works, please see the following:
    ///
    /// https://en.cppreference.com/w/cpp/utility/source_location
    ///
    class source_location
    {
        using file_type = const char *;
        using func_type = const char *;
        using line_type = std::int_least32_t;
        using column_type = std::int_least32_t;

        constexpr source_location(
            const file_type file,
            const func_type func,
            const line_type line) noexcept :
            m_file{file}, m_func{func}, m_line{line}
        {}

    public:
        /// Default Constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr source_location() noexcept = default;

        /// Current
        ///
        /// Returns the current source location
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param file defaults to the current file
        /// @param func defaults to the current function
        /// @param line defaults to the current line
        /// @return current source location
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        static constexpr auto
        current(
            file_type file = __builtin_FILE(),
            func_type func = __builtin_FUNCTION(),
            line_type line = __builtin_LINE()) noexcept -> source_location
        {
            return {file, func, line};
        }

        /// File Name
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return source location file name
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr auto
        file_name() const noexcept -> file_type
        {
            return m_file;
        }

        /// Function Name
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return source location function name
        /// @throw none
        ///
        [[nodiscard]] constexpr auto
        function_name() const noexcept -> func_type
        {
            return m_func;
        }

        /// Line
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return source location line
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr auto
        line() const noexcept -> line_type
        {
            return m_line;
        }

        /// Column
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return always 0 as the column is not supported
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr auto
        column() noexcept -> column_type
        {
            return 0;
        }

    private:
        file_type m_file{};
        func_type m_func{};
        line_type m_line{};
    };

    /// Here
    ///
    /// This provides a less verbose version of source_location::current()
    /// to help reduce how large this code must be. They are equivalent, and
    /// should not produce any additional overhead in release mode.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param loc the current source location
    /// @return the provided loc
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    constexpr auto
    here(source_location loc = source_location::current()) noexcept
        -> source_location
    {
        return loc;
    }
}    // namespace bsl

#endif
