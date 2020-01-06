///
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

#include <bsl/debug.hpp>

namespace
{
    /// <!-- description -->
    ///   @brief This function demonstrates how to use a bsl::source_location
    ///     as a default argument to a function. This provides a means to get
    ///     call site information for the call to foo(), which can then be used
    ///     for debugging later. If the bsl::source_location is added to a debug
    ///     statement whose debug level is set to V or higher, or is provided to
    ///     a contract call, the compiler will optimize out the source location
    ///     information when it is not in use, providing a means to add debug
    ///     information to function calls without incuring additional overhead
    ///     in a release mode build.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param sloc the call site information for foo()
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    void
    foo(bsl::sloc_type const &sloc = bsl::here()) noexcept
    {
        bsl::debug<bsl::V>("{}\n", sloc);
    }
}    // namespace

/// <!-- description -->
///   @brief example
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @return EXIT_SUCCESS
///
/// <!-- exceptions -->
///   @throw [checked] none
///   @throw [unchecked] none
///
std::int32_t
main() noexcept
{
    foo();
}
