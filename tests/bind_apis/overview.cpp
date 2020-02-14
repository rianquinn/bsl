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

#include <bsl/ut.hpp>
#include "test_bind_apis_apis.hpp"
#include "test_bind_apis_impl.hpp"

namespace bsl
{
    /// <!-- description -->
    ///   @brief Provides the example's main function
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param args the arguments passed to the application
    ///   @return exit_success on success, exit_failure otherwise
    ///
    bsl::exit_code
    entry(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);

        bsl::ut_scenario{"constructor"} = ([]() {
            bsl::ut_given{} = ([]() {
                bsl::ut_then{} = ([]() {
                    bsl::ut_check(
                        true == test_bind_apis<test_bind_apis_impl>::static_func_example(42));
                    bsl::ut_check(
                        false == test_bind_apis<test_bind_apis_impl>::static_func_example(43));
                });
            });
        });

        bsl::ut_scenario{"constructor"} = ([]() {
            bsl::ut_given{} = ([]() {
                test_bind_apis<test_bind_apis_impl> const test{42};

                bsl::ut_then{} = ([&test]() {
                    bsl::ut_check(true == test.member_func_example(42));
                    bsl::ut_check(false == test.member_func_example(43));
                });
            });
        });

        bsl::ut_scenario{"make (constructor with error handling)"} = ([]() {
            bsl::ut_given{} = ([]() {
                if (auto const impl = test_bind_apis_impl::make(42).get_if()) {
                    test_bind_apis<test_bind_apis_impl> const test{*impl};

                    bsl::ut_then{} = ([&test]() {
                        bsl::ut_check(true == test.member_func_example(42));
                        bsl::ut_check(false == test.member_func_example(43));
                    });
                }
            });

            bsl::ut_given{} = ([]() {
                if (auto const impl = test_bind_apis_impl::make(43).get_if()) {
                    bsl::ut_then{} = ([]() {
                        return bsl::ut_failure();
                    });
                }
            });
        });

        return bsl::ut_success();
    }
}
