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
/// @file integral_constant.hpp
///

#ifndef BSL_INTEGRAL_CONSTANT_HPP
#define BSL_INTEGRAL_CONSTANT_HPP

namespace bsl
{
    /// @class bsl::integral_constant
    ///
    /// <!-- description -->
    ///   @brief Wraps a static constant of type T. It is the base
    ///     class for the C++ type traits used for SFINAE
    ///   @include integral_constant/overview.cpp
    ///
    /// <!-- template parameters -->
    ///   @tparam T the type of integral constant being defined
    ///   @tparam val the value of integral contant being defined
    ///
    template<typename T, T val>
    struct integral_constant
    {
        /// @brief stores the value of the integral constant
        static constexpr T value{val};

        /// <!-- description -->
        ///   @brief Conversion function that returns the value of the
        ///     integral constant.
        ///
        /// <!-- notes -->
        ///   @note Unlike the std::integral_constant, this function is labeled
        ///     as explicit as per the AUTOSAR specification
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the integral constant
        ///
        explicit constexpr operator T() const noexcept
        {
            return val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of the integral constant. This function
        ///     enables bsl::integral_constant to serve as a source of
        ///     compile-time function objects.
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @return returns the value of the integral constant.
        ///
        constexpr T
        operator()() const noexcept
        {
            return val;
        }
    };
}    // namespace bsl

#endif
