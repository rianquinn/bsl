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

#include <bsl/function.hpp>
#include <bsl/is_pod.hpp>
#include <bsl/move.hpp>
#include "test_function_func.hpp"
#include "test_function_memfunc.hpp"
#include "test_function_cmemfunc.hpp"

namespace bsl
{
    /// @brief Provides a global POD type for testing
    static bsl::function<bool(bsl::int32 const &)> g_func;

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
        static_assert(is_pod<bsl::function<bool(bsl::int32 const &)>>::value);

        bsl::ut_scenario{"empty"} = []() {
            bsl::ut_given{} = []() {
                bsl::function<bool(bsl::int32 const &)> const func{&test_function_func};
                bsl::ut_when{} = [&func]() {
                    g_func = func;
                    bsl::ut_then{} = []() {
                        bsl::ut_check(g_func(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"function pointer"} = []() {
            bsl::ut_given{} = []() {
                bsl::function<bool(bsl::int32 const &)> const func{&test_function_func};
                bsl::ut_then{} = [&func]() {
                    bsl::ut_check(func(42));
                };
            };
        };

        bsl::ut_scenario{"member function pointer"} = []() {
            bsl::ut_given{} = []() {
                test_function_memfunc test{};
                bsl::function<bool(bsl::int32 const &)> const func{
                    test, &test_function_memfunc::is_answer};
                bsl::ut_then{} = [&func]() {
                    bsl::ut_check(func(42));
                };
            };
        };

        bsl::ut_scenario{"const member function pointer"} = []() {
            bsl::ut_given{} = []() {
                test_function_cmemfunc const test{};
                bsl::function<bool(bsl::int32 const &)> const func{
                    test, &test_function_cmemfunc::is_answer};
                bsl::ut_then{} = [&func]() {
                    bsl::ut_check(func(42));
                };
            };
        };

        bsl::ut_scenario{"function pointer copy construct"} = []() {
            bsl::ut_given{} = []() {
                bsl::function<bool(bsl::int32 const &)> const func1{&test_function_func};
                bsl::function<bool(bsl::int32 const &)> const func2{func1};
                bsl::ut_then{} = [&func1, &func2]() {
                    bsl::ut_check(func1(42));
                    bsl::ut_check(func2(42));
                };
            };
        };

        bsl::ut_scenario{"function pointer move construct"} = []() {
            bsl::ut_given{} = []() {
                bsl::function<bool(bsl::int32 const &)> func1{&test_function_func};
                bsl::function<bool(bsl::int32 const &)> const func2{bsl::move(func1)};
                bsl::ut_then{} = [&func2]() {
                    bsl::ut_check(func2(42));
                };
            };
        };

        bsl::ut_scenario{"member function pointer copy construct"} = []() {
            bsl::ut_given{} = []() {
                test_function_memfunc test{};
                bsl::function<bool(bsl::int32 const &)> const func1{
                    test, &test_function_memfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> const func2{func1};
                bsl::ut_then{} = [&func1, &func2]() {
                    bsl::ut_check(func1(42));
                    bsl::ut_check(func2(42));
                };
            };
        };

        bsl::ut_scenario{"member function pointer move construct"} = []() {
            bsl::ut_given{} = []() {
                test_function_memfunc test{};
                bsl::function<bool(bsl::int32 const &)> func1{test,
                                                              &test_function_memfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> const func2{bsl::move(func1)};
                bsl::ut_then{} = [&func2]() {
                    bsl::ut_check(func2(42));
                };
            };
        };

        bsl::ut_scenario{"const member function pointer copy construct"} = []() {
            bsl::ut_given{} = []() {
                test_function_cmemfunc const test{};
                bsl::function<bool(bsl::int32 const &)> const func1{
                    test, &test_function_cmemfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> const func2{func1};
                bsl::ut_then{} = [&func1, &func2]() {
                    bsl::ut_check(func1(42));
                    bsl::ut_check(func2(42));
                };
            };
        };

        bsl::ut_scenario{"const member function pointer move construct"} = []() {
            bsl::ut_given{} = []() {
                test_function_cmemfunc const test{};
                bsl::function<bool(bsl::int32 const &)> func1{test,
                                                              &test_function_cmemfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> const func2{bsl::move(func1)};
                bsl::ut_then{} = [&func2]() {
                    bsl::ut_check(func2(42));
                };
            };
        };

        bsl::ut_scenario{"function pointer copy assignment"} = []() {
            bsl::ut_given{} = []() {
                bsl::function<bool(bsl::int32 const &)> const func1{&test_function_func};
                bsl::function<bool(bsl::int32 const &)> func2{};
                bsl::ut_when{} = [&func1, &func2]() {
                    func2 = func1;
                    bsl::ut_then{} = [&func1, &func2]() {
                        bsl::ut_check(func1(42));
                        bsl::ut_check(func2(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"function pointer move assignment"} = []() {
            bsl::ut_given{} = []() {
                bsl::function<bool(bsl::int32 const &)> func1{&test_function_func};
                bsl::function<bool(bsl::int32 const &)> func2{};
                bsl::ut_when{} = [&func1, &func2]() {
                    func2 = bsl::move(func1);
                    bsl::ut_then{} = [&func2]() {
                        bsl::ut_check(func2(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"member function pointer copy assignment"} = []() {
            bsl::ut_given{} = []() {
                test_function_memfunc test{};
                bsl::function<bool(bsl::int32 const &)> const func1{
                    test, &test_function_memfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> func2{};
                bsl::ut_when{} = [&func1, &func2]() {
                    func2 = func1;
                    bsl::ut_then{} = [&func1, &func2]() {
                        bsl::ut_check(func1(42));
                        bsl::ut_check(func2(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"member function pointer move assignment"} = []() {
            bsl::ut_given{} = []() {
                test_function_memfunc test{};
                bsl::function<bool(bsl::int32 const &)> func1{test,
                                                              &test_function_memfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> func2{};
                bsl::ut_when{} = [&func1, &func2]() {
                    func2 = bsl::move(func1);
                    bsl::ut_then{} = [&func2]() {
                        bsl::ut_check(func2(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"const member function pointer copy assignment"} = []() {
            bsl::ut_given{} = []() {
                test_function_cmemfunc const test{};
                bsl::function<bool(bsl::int32 const &)> const func1{
                    test, &test_function_cmemfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> func2{};
                bsl::ut_when{} = [&func1, &func2]() {
                    func2 = func1;
                    bsl::ut_then{} = [&func1, &func2]() {
                        bsl::ut_check(func1(42));
                        bsl::ut_check(func2(42));
                    };
                };
            };
        };

        bsl::ut_scenario{"const member function pointer move assignment"} = []() {
            bsl::ut_given{} = []() {
                test_function_cmemfunc const test{};
                bsl::function<bool(bsl::int32 const &)> func1{test,
                                                              &test_function_cmemfunc::is_answer};
                bsl::function<bool(bsl::int32 const &)> func2{};
                bsl::ut_when{} = [&func1, &func2]() {
                    func2 = bsl::move(func1);
                    bsl::ut_then{} = [&func2]() {
                        bsl::ut_check(func2(42));
                    };
                };
            };
        };

        return bsl::ut_success();
    };
};
