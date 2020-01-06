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
    /// Final Act
    ///
    ///
    ///
    /// It should be noted that this should not be used globally. Most static
    /// analysis tools will detect the use of global destructors, but just
    /// in case, do not use this globally as it requires a destructor which
    /// may not be called on exit.
    ///
    template<typename FUNC, std::enable_if_t<std::is_nothrow_invocable_v<FUNC>> * = nullptr>
    class final_act final
    {
        FUNC m_func{};
        bool m_invoked{};

    public:
        /// Default Constructor
        ///
        /// Creates the bsl::final_act class. When this class
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr final_act(FUNC &&func) noexcept : m_func(std::move(func))
        {}

        final_act(final_act &&other) noexcept : m_invoked{std::exchange(other.m_invoked, true)}
        {}

        final_act &
            operator=(final_act &&other) &
            noexcept
        {
            if (this != &other) {
                m_invoked = std::exchange(other.m_invoked, true);
            }

            return *this;
        }

        inline void
        ignore() noexcept
        {
            m_invoked = true;
        }

        /// Destructor
        ///
        /// Calls the function provided during construction.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~final_act() noexcept
        {
            if (!m_invoked) {
                m_func();
            }
        }

        final_act(const final_act &) = delete;               ///< S
        final_act &operator=(const final_act &) = delete;    ///< S
    };

    template<typename FUNC, std::enable_if_t<std::is_nothrow_invocable_v<FUNC>> * = nullptr>
    [[nodiscard]] inline auto
    finally(FUNC &&func) noexcept -> final_act<FUNC>
    {
        return final_act<FUNC>(std::forward<FUNC>(func));
    }

}    // namespace bsl

#endif
