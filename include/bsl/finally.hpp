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
    /// Finally
    ///
    /// The bsl::finally class is different than the gsl::finally class in
    /// that, we do not support moves or copies. It is a non-move, non-copy
    /// type. This removes the need for a boolean type, providing the compiler
    /// with more options for optimizing away to class completely. We also
    /// leverage C++17 so there is no need for the function wrappers, and
    /// we can ensure the function is marked as noexcept, so that static
    /// analysis engines can determine if you are accidentally calling a
    /// function that is not marked as noexcept from the finally function.
    ///
    /// It should be noted that this should not be used globally. Most static
    /// analysis tools will detect the use of global destructors, but just
    /// in case, do not use this globally as it requires a destructor which
    /// may not be called on exit.
    ///
    template<
        typename FUNC,
        std::enable_if_t<std::is_nothrow_invocable_v<FUNC>> * = nullptr>
    class finally
    {
        FUNC m_func{};

    public:
        /// Default Constructor
        ///
        /// Creates the bsl::finally class in place. Then ths class loses
        /// scope, the provided function will be called.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr finally(FUNC &&func) noexcept :
            m_func(std::move(func))
        {}

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
        ~finally() noexcept
        {
            m_func();
        }

        /// @cond

        finally(const finally &) = delete;
        auto operator=(const finally &) -> finally & = delete;
        finally(finally &&) noexcept = delete;
        auto operator=(finally &&) noexcept -> finally & = delete;

        /// @endcond
    };

    template<typename FUNC>
    finally(FUNC &&func)->finally<FUNC>;

}    // namespace bsl

#endif
