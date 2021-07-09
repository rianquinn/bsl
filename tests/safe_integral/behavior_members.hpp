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

#include <bsl/convert.hpp>
#include <bsl/numeric_limits.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/ut.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Used to execute the actual checks. We put the checks in this
    ///     function so that we can validate the tests both at compile-time
    ///     and at run-time. If a bsl::ut_check fails, the tests will either
    ///     fail fast at run-time, or will produce a compile-time error.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success.
    ///
    [[nodiscard]] constexpr auto
    tests_members() noexcept -> bsl::exit_code
    {
        bsl::ut_scenario{"default constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == 0);
                    bsl::ut_check(!val.invalid());
                };
            };
        };

        bsl::ut_scenario{"value constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == 42);
                    bsl::ut_check(!val.invalid());
                };
            };
        };

        bsl::ut_scenario{"value/error constructor"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val == 42);
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"value assignment"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{23, false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val = 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"get"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.get() == 42);
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.get() == 0);
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"data"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_val.data() == 42);
                    bsl::ut_check(!mut_val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*val.data() == 42);
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*mut_val.data() == 42);
                    bsl::ut_check(mut_val.invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(*val.data() == 42);
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"operator bool"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!!val);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val);
                };
            };
        };

        bsl::ut_scenario{"max"} = []() noexcept {
            bsl::ut_check(bsl::safe_uintmax::max() == bsl::numeric_limits<bsl::uintmax>::max());

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val1{23, false};
                bsl::safe_int32 const val2{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2) == 42);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{23, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.max(42) == 42);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val1{23, true};
                bsl::safe_int32 const val2{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val1{23, false};
                bsl::safe_int32 const val2{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val1{23, true};
                bsl::safe_int32 const val2{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.max(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{23, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.max(42).invalid());
                };
            };
        };

        bsl::ut_scenario{"min"} = []() noexcept {
            bsl::ut_check(bsl::safe_uintmax::min() == bsl::numeric_limits<bsl::uintmax>::min());

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val1{23, false};
                bsl::safe_int32 const val2{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2) == 23);
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{23, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.min(42) == 23);
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val1{23, true};
                bsl::safe_int32 const val2{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val1{23, false};
                bsl::safe_int32 const val2{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val1{23, true};
                bsl::safe_int32 const val2{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val1.min(val2).invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{23, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.min(42).invalid());
                };
            };
        };

        bsl::ut_scenario{"is_signed_type"} = []() noexcept {
            bsl::ut_check(bsl::safe_intmax::is_signed_type());
            bsl::ut_check(!bsl::safe_uintmax::is_signed_type());
        };

        bsl::ut_scenario{"is_unsigned_type"} = []() noexcept {
            bsl::ut_check(!bsl::safe_intmax::is_unsigned_type());
            bsl::ut_check(bsl::safe_uintmax::is_unsigned_type());
        };

        bsl::ut_scenario{"is_pos"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{0};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{-42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_pos());
                };
            };
        };

        bsl::ut_scenario{"is_neg int8"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int8 const val{-42_i8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int8 const val{0_i8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int8 const val{42_i8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int8 const val{-42_i8, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg int16"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int16 const val{-42_i16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int16 const val{0_i16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int16 const val{42_i16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int16 const val{-42_i16, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg int32"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{-42_i32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{0_i32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42_i32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{-42_i32, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg int64"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int64 const val{-42_i64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int64 const val{0_i64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int64 const val{42_i64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int64 const val{-42_i64, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg intmax"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_intmax const val{-42_imax};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_intmax const val{0_imax};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_intmax const val{42_imax};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_intmax const val{-42_imax, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg uint8"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint8 const val{0_u8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint8 const val{42_u8};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint8 const val{42_u8, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg uint16"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint16 const val{0_u16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint16 const val{42_u16};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint16 const val{42_u16, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg uint32"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint32 const val{0_u32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint32 const val{42_u32};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint32 const val{42_u32, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg uint64"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint64 const val{0_u64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint64 const val{42_u64};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uint64 const val{42_u64, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_neg uintmax"} = []() noexcept {
            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uintmax const val{0_umax};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uintmax const val{42_umax};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_uintmax const val{42_umax, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_neg());
                };
            };
        };

        bsl::ut_scenario{"is_zero"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{0};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{-42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{0, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero());
                };
            };
        };

        bsl::ut_scenario{"is_zero_or_invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{0};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero_or_invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{-42};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_zero_or_invalid());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{0, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_zero_or_invalid());
                };
            };
        };

        bsl::ut_scenario{"invalid"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, false};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.invalid());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{42, true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.invalid());
                };
            };
        };

        bsl::ut_scenario{"is_max"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{bsl::safe_int32::max()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_max());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{bsl::safe_int32::min()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_max());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{bsl::safe_int32::max().get(), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_max());
                };
            };
        };

        bsl::ut_scenario{"is_min"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{bsl::safe_int32::min()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(val.is_min());
                };
            };

            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 const val{bsl::safe_int32::max()};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_min());
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 const val{bsl::safe_int32::min().get(), true};
                bsl::ut_then{} = [&]() noexcept {
                    bsl::ut_check(!val.is_min());
                };
            };
        };

        bsl::ut_scenario{"add assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == 42 + 42);
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{1, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{42, false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, false};
                bsl::safe_int32 mut_val2{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 += mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"add assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 + 42);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += 1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += 1;
                    mut_val += 1;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val += 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{23};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == 42 - 23);
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{-1, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{23, false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, false};
                bsl::safe_int32 mut_val2{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 -= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"sub assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= 23;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 - 23);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= (1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= (-1);
                    mut_val -= (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val -= 23;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == 42 * 42);
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{2};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-2};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{2};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::max()};
                bsl::safe_int32 mut_val2{2, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{42, false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, false};
                bsl::safe_int32 mut_val2{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 *= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mul assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 * 42);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= 2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= (-2);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= 2;
                    mut_val *= 2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val *= 42;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{23};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == 42 / 23);
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{0};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{0};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{0, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{23, false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, false};
                bsl::safe_int32 mut_val2{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 /= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"div assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= 23;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 / 23);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= 0;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= 0;
                    mut_val /= 0;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= (-1);
                    mut_val /= (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val /= 23;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{23};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1 == 42 % 23);
                        bsl::ut_check(!mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{0};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{0};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42};
                bsl::safe_int32 mut_val2{0, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{bsl::numeric_limits<bsl::int32>::min()};
                bsl::safe_int32 mut_val2{-1, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{23, false};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, false};
                bsl::safe_int32 mut_val2{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val1{42, true};
                bsl::safe_int32 mut_val2{23, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val1 %= mut_val2;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val1.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"mod assign with mut_value"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= 23;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 % 23);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= 0;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= 0;
                    mut_val %= 0;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= (-1);
                    mut_val %= (-1);
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    mut_val %= 23;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"inc"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 + 1);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::max()};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    ++mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        bsl::ut_scenario{"dec"} = []() noexcept {
            bsl::ut_given{} = []() noexcept {
                bsl::safe_int32 mut_val{42};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val == 42 - 1);
                        bsl::ut_check(!mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{bsl::numeric_limits<bsl::int32>::min()};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };

            bsl::ut_given_at_runtime{} = []() noexcept {
                bsl::safe_int32 mut_val{42, true};
                bsl::ut_when{} = [&]() noexcept {
                    --mut_val;
                    bsl::ut_then{} = [&]() noexcept {
                        bsl::ut_check(mut_val.invalid());
                    };
                };
            };
        };

        return bsl::ut_success();
    }
}
