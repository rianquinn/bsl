/// @copyright
/// Copyright (C) 2019 Assured Information Security, Inc.
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
///
/// @file reference_wrapper.hpp
///

#ifndef BSL_REFERENCE_WRAPPER_HPP
#define BSL_REFERENCE_WRAPPER_HPP

namespace bsl
{
    /// @class
    ///
    /// <!-- description -->
    ///   @brief bsl::reference_wrapper is a class template that wraps a
    ///     reference in a copyable, assignable object. It is frequently used
    ///     as a mechanism to store references inside containers and
    ///     a bsl::result which cannot normally hold references. Unlike an
    ///     std::reference_wrapper, a bsl::reference_wrapper does not support
    ///     callable object, nor does it support an implicit conversion
    ///     constructor. The bsl::reference_wrapper requires explicit
    ///     construction. It should be noted that a bsl::reference_wrapper is
    ///     purposely not a POD, meaning it cannot be used in global space.
    ///     Use a pointer intead.
    ///   @include reference_wrapper/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of reference to wrap
    ///
    template<typename T>
    class reference_wrapper final
    {
    public:
        /// <!-- description -->
        ///   @brief Creates a reference wrapper given a reference to an
        ///     object "t" of type "T".
        ///   @include reference_wrapper/construct.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param t a reference to an instance of T that is being wrapped
        ///
        constexpr reference_wrapper(T &t) noexcept : m_ptr{&t}
        {}

        /// <!-- description -->
        ///   @brief Returns a reference to a previously wrapped T
        ///   @include reference_wrapper/get.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns a reference to a previously wrapped T
        ///
        constexpr T &
        get() const noexcept
        {
            return *m_ptr;
        }

    private:
        /// @brief stores a pointer to the wrapped T
        T *m_ptr;
    };
}

#endif
