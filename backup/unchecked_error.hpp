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
/// @file unchecked_error.hpp
///

#ifndef BSL_UNCHECKED_ERROR_HPP
#define BSL_UNCHECKED_ERROR_HPP

#include "exception.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief This class provides the base type for all unchecked exceptions
    ///     types defined by the AUTOSAR specification.
    ///   @include unchecked_error/overview.cpp
    ///
    class unchecked_error : public exception
    {
    public:
        /// <!-- description -->
        ///   @brief Constructs a bsl::unchecked_error
        ///   @include unchecked_error/constructor_desc_comm_sloc.cpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param desc a description of the exception type
        ///   @param comm a comment to add to the exception
        ///   @param sloc the source location of the exception
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        unchecked_error(
            cstr_type const &desc,
            cstr_type const &comm,
            sloc_type const &sloc = bsl::here()) noexcept
            : exception{desc, comm, sloc}
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::unchecked_error
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        ~unchecked_error() noexcept override = default;

    protected:
        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        unchecked_error(unchecked_error const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        unchecked_error(unchecked_error &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[maybe_unused]] unchecked_error &operator=(unchecked_error const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        /// <!-- exceptions -->
        ///   @throw [checked] none
        ///   @throw [unchecked] none
        ///
        [[maybe_unused]] unchecked_error &operator=(unchecked_error &&o) &noexcept = default;
    };
}    // namespace bsl

#endif
