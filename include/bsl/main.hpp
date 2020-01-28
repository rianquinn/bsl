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
/// @file main.hpp
///

#ifndef BSL_MAIN_HPP
#define BSL_MAIN_HPP

#include <bsl/arguments.hpp>
#include <bsl/exit_code.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides a prototype to the entry point function used by the
    ///     BSL. Users should implement this function (in the bsl namespace)
    ///     as their entry point (i.e., main) instead of implementing main
    ///     directly.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments passed to the application
    ///   @return exit_success on success, exit_failure otherwise
    ///
    bsl::exit_code entry(bsl::arguments const &args) noexcept;
}    // namespace bsl

/// <!-- description -->
///   @brief Provides the "main" function for any C++ application. Instead of
///     the user providing the main function, we provide it for them, ensuring
///     that the proper init/fini code is executed. We also ensure the user
///     has clean input/output from our provided bsl::entry function, including
///     a safer arguments list and well defined output exit codes.
///   @include main/overview.cpp
///
///   SUPPRESSION: PRQA 1067 - exception required
///   - We suppress this because A3-1-1 states that functions defined in a
///     header should either be a template, or inline, preventing multiple
///     definitons. In this case, the main() function cannot be defined as
///     a template or inline. Since we do not support shared libraries, this
///     is a none issue as the compiler will detect the presence of shared
///     libraries and error out. In otherwords, this is being checked by
///     the compiler, so PRQA doesn't need to perform this check for us.
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @param argc the total number of arguments passed to the application
///   @param argv the arguments passed to the application
///   @return 0 on success, non-0 on failure
///
bsl::int32
main(bsl::int32 const argc, bsl::cstr_type const *const argv) noexcept    // PRQA S 1067
{
    return static_cast<bsl::int32>(bsl::entry({argc, argv}));
}

#endif
