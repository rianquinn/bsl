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

#include "fmt.hpp"

namespace bsl
{
    /// @class source_location
    ///
    /// The following implements the source_location specification that will
    /// eventually be included in C++20. We make some changes to the
    /// specification to support AUTOSAR, but these changes should not change
    /// how the code is compiled or used.
    ///
    class source_location final
    {
        /// @brief defines the file name type
        using file_type = cstr_type;
        /// @brief defines the function name type
        using func_type = cstr_type;
        /// @brief defines the line location type
        using line_type = std::int_least32_t;

        /// @brief private constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param current_file the file name of the source
        /// @param current_func the function name of the source
        /// @param current_line the line location of the source
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr source_location(
            file_type const current_file,
            func_type const current_func,
            line_type const current_line) noexcept
            : m_file{current_file}, m_func{current_func}, m_line{current_line}
        {}

    public:
        /// @brief default constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr source_location() noexcept : m_file{"unknown"}, m_func{"unknown"}, m_line{-1}
        {}

        /// @brief current
        ///
        /// Returns the current source location
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param current_file defaults to the current file
        /// @param current_func defaults to the current function
        /// @param current_line defaults to the current line
        /// @return current source location
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        static constexpr source_location
        current(
            file_type const current_file = BSL_BUILTIN_FILE,
            func_type const current_func = BSL_BUILTIN_FUNCTION,
            line_type const current_line = BSL_BUILTIN_LINE) noexcept
        {
            return {current_file, current_func, current_line};
        }

        /// @brief file_name
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return source location file name
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr file_type
        file_name() const noexcept
        {
            return m_file;
        }

        /// @brief function_name
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return source location function name
        /// @throw none
        ///
        [[nodiscard]] constexpr func_type
        function_name() const noexcept
        {
            return m_func;
        }

        /// @brief line
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return source location line
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr line_type
        line() const noexcept
        {
            return m_line;
        }

    private:
        /// @brief stores the file name of the source
        file_type m_file;
        /// @brief stores the function name of the source
        func_type m_func;
        /// @brief stores the line location of the source
        line_type m_line;
    };

    /// @brief here
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
    constexpr source_location
    here(source_location const &loc = source_location::current()) noexcept
    {
        return loc;
    }

    /// @brief operator <<
    ///
    /// Provides support for outputing a bsl::source_location.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param os the stream to output the source location to
    /// @param sloc the source location to output
    /// @return a reference to the output stream provided
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    inline std::ostream &
    operator<<(std::ostream &os, source_location const &sloc)
    {
        os << fmt::format("{}   here{}", magenta, reset_color);
        os << fmt::format(" --> ");
        os << fmt::format("{}{}{}", yellow, sloc.file_name(), reset_color);
        os << fmt::format(": ");
        os << fmt::format("{}{}{}", cyan, sloc.line(), reset_color);

        return os;
    }

    /// @brief defines a source location
    using sloc_type = source_location;
}    // namespace bsl

#endif
