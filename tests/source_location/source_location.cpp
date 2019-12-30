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

#include "../../include/bsl/checked_error.hpp"
#include "../../include/bsl/unique_owner.hpp"
#include "../../include/bsl/contracts.hpp"
#include "../../include/bsl/convert.hpp"
#include "../../include/bsl/integer.hpp"
#include <iostream>

// verify copy does not compile
// verify doxygen errors on all examples in 2025
// file:///home/rianquinn/perforce/Helix-QAC-2019.2/components/qacpp-4.5.0/doc-en_US/messages/2025.html
// verify that 0xFFFFFFFF on a 16 bit constexpr causes a compiler error.

namespace
{
    constexpr bsl::uint64_t g_i1{bsl::to_uint64(42)};
    constexpr bsl::uint64_t g_i2{bsl::to_uint64(23)};

    static_assert(!(g_i1 == g_i2));
    static_assert(g_i1 != g_i2);
    static_assert(g_i1 > g_i2);
    static_assert(g_i1 >= g_i2);
    static_assert(!(g_i1 < g_i2));
    static_assert(!(g_i1 <= g_i2));
}

/// Unit Test Entry Point
///
/// expects: none
/// ensures: none
///
/// @return EXIT_SUCCESS on UT success, EXIT_FAILURE otherwise
/// @throw [checked]: none
/// @throw [unchecked]: none
///
std::int32_t
main()
{
    try {
        bsl::expects(true);
        bsl::ensures(true);
        bsl::confirm(true);
        bsl::expects_false(false);
        bsl::ensures_false(false);
        bsl::confirm_false(false);
        bsl::expects_audit(true);
        bsl::ensures_audit(true);
        bsl::confirm_audit(true);
        bsl::expects_audit_false(false);
        bsl::ensures_audit_false(false);
        bsl::confirm_audit_false(false);

        bsl::unique_owner<std::int32_t> const g_yourmom{0};
        std::cout << g_yourmom.get() << "\n";
        std::cout << bsl::unsign(1) << "\n";
        std::cout << bsl::convert<std::uintmax_t>(1) << "\n";

        constexpr bsl::int32_t blah1{1};
        std::cout << blah1 << "\n";

        throw bsl::checked_error{"checked_error", "hello world", bsl::here()};
    }
    catch (bsl::checked_error const &e) {
        try {
            std::cout << e << "\n";
        }
        catch (...) {
        }
    }
    catch (...) {
    }

    try {
        throw bsl::unchecked_error{"unchecked_error", "hello world", bsl::here()};
    }
    catch (bsl::unchecked_error const &e) {
        try {
            std::cout << e << "\n";
        }
        catch (...) {
        }
    }
    catch (...) {
    }

    try {
        std::cout << bsl::here() << "\n";
    }
    catch (...) {
    }

    try {
        bsl::fail();
    }
    catch (bsl::unchecked_error const &e) {
        try {
            std::cout << e << "\n";
        }
        catch (...) {
        }
    }
    catch (...) {
    }

    return 0;
}
