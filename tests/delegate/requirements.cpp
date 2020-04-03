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

#include <bsl/delegate.hpp>
#include <bsl/ut.hpp>

namespace
{
    [[nodiscard]] constexpr bool
    test_func(bool const val)
    {
        return val;
    }

    [[nodiscard]] constexpr bool
    test_func_noexcept(bool const val) noexcept
    {
        return val;
    }

    class myclass final
    {
    public:
        [[nodiscard]] constexpr bool
        test_memfunc(bool const val)    // NOLINT
        {
            return val;
        }

        [[nodiscard]] constexpr bool
        test_memfunc_noexcept(bool const val) noexcept    // NOLINT
        {
            return val;
        }

        [[nodiscard]] constexpr bool
        test_cmemfunc(bool const val) const    // NOLINT
        {
            return val;
        }

        [[nodiscard]] constexpr bool
        test_cmemfunc_noexcept(bool const val) const noexcept    // NOLINT
        {
            return val;
        }
    };

    class fixture_t final
    {
        bsl::delegate<bool(bool)> d{&test_func};
        bsl::delegate<bool(bool) noexcept> d_noexcept{&test_func_noexcept};

    public:
        [[nodiscard]] bool
        test_member_const() const
        {
            bsl::discard(d(true));
            bsl::discard(d.empty());
            bsl::discard(d_noexcept(true));
            bsl::discard(d_noexcept.empty());

            return true;
        }

        [[nodiscard]] bool
        test_member_nonconst()
        {
            bsl::discard(d(true));
            bsl::discard(d.empty());
            bsl::discard(d_noexcept(true));
            bsl::discard(d_noexcept.empty());

            return true;
        }
    };

    bsl::delegate<void()> d;
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

    bsl::ut_scenario{"verify supports global POD"} = []() {
        bsl::discard(d);
    };

    bsl::ut_scenario{"verify noexcept"} = []() {
        bsl::ut_given{} = []() {
            myclass c{};
            bsl::ut_then{} = []() {
                static_assert(noexcept(delegate<bool()>{}));
                static_assert(noexcept(delegate{&test_func}));
                static_assert(noexcept(delegate{&test_func_noexcept}));
                static_assert(noexcept(delegate{&c, &myclass::test_memfunc}));
                static_assert(noexcept(delegate{&c, &myclass::test_memfunc_noexcept}));
                static_assert(noexcept(delegate{&c, &myclass::test_cmemfunc}));
                static_assert(noexcept(delegate{&c, &myclass::test_cmemfunc_noexcept}));
                static_assert(!noexcept(delegate{&test_func}(true)));
                static_assert(noexcept(delegate{&test_func_noexcept}(true)));
                static_assert(noexcept(delegate{&test_func}.empty()));
                static_assert(noexcept(delegate{&test_func_noexcept}.empty()));
            };
        };
    };

    bsl::ut_scenario{"verify constness"} = []() {
        bsl::ut_given{} = []() {
            fixture_t fixture{};
            bsl::ut_then{} = [&fixture]() {
                ut_check(fixture.test_member_const());
                ut_check(fixture.test_member_nonconst());
            };
        };
    };

    return bsl::ut_success();
}
