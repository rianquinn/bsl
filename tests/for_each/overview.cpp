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

#include <bsl/for_each.hpp>
#include <bsl/discard.hpp>
#include <bsl/ut.hpp>

namespace
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"

    // clang-format off

    constexpr void
    test_func1(bsl::int32 const &elem, bsl::uintmax index) noexcept
    {
        bsl::discard(elem);
        bsl::discard(index);
    }

    constexpr void
    test_func2(bsl::int32 const &elem, bsl::uintmax index)
    {
        bsl::discard(elem);
        bsl::discard(index);
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32
    test_array(bsl::int32 (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, [&answer](auto &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32
    test_array(bsl::int32 const (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, [&answer](auto const &elem, auto index) {
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32
    test_array_ptr(bsl::int32 (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
         bsl::for_each(array, N, [&answer](auto &elem, auto index) {    // NOLINT
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32
    test_array_ptr(bsl::int32 const (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, N, [&answer](auto const &elem, auto index) {    // NOLINT
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    [[nodiscard]] constexpr bsl::int32
    test_array_ptr_nullptr() noexcept    // NOLINT
    {
        bsl::int32 *array{};
        bsl::int32 answer{};
        bsl::for_each(array, 6, [&answer](auto &elem, auto index) {    // NOLINT
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    template<bsl::uintmax N>
    [[nodiscard]] constexpr bsl::int32
    test_array_ptr_0_size(bsl::int32 const (&array)[N]) noexcept    // NOLINT
    {
        bsl::int32 answer{};
        bsl::for_each(array, 0, [&answer](auto &elem, auto index) {    // NOLINT
            bsl::discard(index);
            answer += elem;
        });

        return answer;
    }

    // clang-format on

#pragma clang diagnostic pop
}

/// <!-- description -->
///   @brief Main function for this unit test. If a call to ut_check() fails
///     the application will fast fail. If all calls to ut_check() pass, this
///     function will successfully return with bsl::exit_success.
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @return Always returns bsl::exit_success.
///
bsl::exit_code
main() noexcept
{
    using namespace bsl;

    bsl::ut_scenario{"for_each array size 1"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[1]{42};                       // NOLINT
            bsl::ut_then{} = [&array]() {                  // NOLINT
                bsl::ut_check(test_array(array) == 42);    // NOLINT
                static_assert(test_array({42}) == 42);     // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[1]{42};                           // NOLINT
            bsl::ut_then{} = [&array]() {                      // NOLINT
                bsl::ut_check(test_array_ptr(array) == 42);    // NOLINT
                static_assert(test_array_ptr({42}) == 42);     // NOLINT
            };
        };
    };

    bsl::ut_scenario{"for_each array size 6"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                       // NOLINT
            bsl::ut_then{} = [&array]() {                                    // NOLINT
                bsl::ut_check(test_array(array) == 108);                     // NOLINT
                static_assert(test_array({4, 8, 15, 16, 23, 42}) == 108);    // NOLINT
            };
        };

        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                           // NOLINT
            bsl::ut_then{} = [&array]() {                                        // NOLINT
                bsl::ut_check(test_array_ptr(array) == 108);                     // NOLINT
                static_assert(test_array_ptr({4, 8, 15, 16, 23, 42}) == 108);    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"except"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                       // NOLINT
            bsl::ut_then{} = []() {                                          // NOLINT
                static_assert(!noexcept(for_each(array, test_func2)));       // NOLINT
                static_assert(!noexcept(for_each(array, 6, test_func2)));    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"noexcept"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                      // NOLINT
            bsl::ut_then{} = []() {                                         // NOLINT
                static_assert(noexcept(for_each(array, test_func1)));       // NOLINT
                static_assert(noexcept(for_each(array, 6, test_func1)));    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"nullptr"} = []() {
        bsl::ut_given{} = []() {
            bsl::ut_then{} = []() {                              // NOLINT
                bsl::ut_check(test_array_ptr_nullptr() == 0);    // NOLINT
                static_assert(test_array_ptr_nullptr() == 0);    // NOLINT
            };
        };
    };

    bsl::ut_scenario{"0 size"} = []() {
        bsl::ut_given{} = []() {
            bsl::int32 array[6]{4, 8, 15, 16, 23, 42};                                // NOLINT
            bsl::ut_then{} = [&array]() {                                             // NOLINT
                bsl::ut_check(test_array_ptr_0_size(array) == 0);                     // NOLINT
                static_assert(test_array_ptr_0_size({4, 8, 15, 16, 23, 42}) == 0);    // NOLINT
            };
        };
    };

    return bsl::ut_success();
}
