/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
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

#include <bsl/array.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
    class fixture_t final
    {
        bsl::array<bool, 5> arr{};

    public:
        [[nodiscard]] constexpr bool
        test_member_const() const
        {
            bsl::discard(arr.at_if(0));
            bsl::discard(arr.front());
            bsl::discard(arr.front_if());
            bsl::discard(arr.back());
            bsl::discard(arr.back_if());
            bsl::discard(arr.data());
            bsl::discard(arr.begin());
            bsl::discard(arr.cbegin());
            bsl::discard(arr.end());
            bsl::discard(arr.cend());
            bsl::discard(arr.iter(0));
            bsl::discard(arr.citer(0));
            bsl::discard(arr.rbegin());
            bsl::discard(arr.crbegin());
            bsl::discard(arr.rend());
            bsl::discard(arr.crend());
            bsl::discard(arr.riter(0));
            bsl::discard(arr.criter(0));
            bsl::discard(arr.empty());
            bsl::discard(arr.size());
            bsl::discard(arr.max_size());
            bsl::discard(arr.size_bytes());

            return true;
        }

        [[nodiscard]] constexpr bool
        test_member_nonconst()
        {
            bsl::discard(arr.at_if(0));
            bsl::discard(arr.front());
            bsl::discard(arr.front_if());
            bsl::discard(arr.back());
            bsl::discard(arr.back_if());
            bsl::discard(arr.data());
            bsl::discard(arr.begin());
            bsl::discard(arr.end());
            bsl::discard(arr.iter(0));
            bsl::discard(arr.rbegin());
            bsl::discard(arr.rend());
            bsl::discard(arr.riter(0));
            bsl::discard(arr.empty());
            bsl::discard(arr.size());
            bsl::discard(arr.max_size());
            bsl::discard(arr.size_bytes());

            return true;
        }
    };

    constexpr fixture_t fixture1{};
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    using namespace bsl;

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            fixture_t fixture2{};
            bsl::ut_then{} = [&fixture2]() {
                static_assert(fixture1.test_member_const());
                ut_check(fixture2.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
