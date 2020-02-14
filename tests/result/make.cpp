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

#include <bsl/result.hpp>
#include "test_result_monitor.hpp"

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
        bsl::set_ut_reset_handler(&test_result_monitor_reset);

        bsl::ut_scenario{"make copy t"} = []() {
            bsl::ut_given{} = []() {
                test_result_monitor const t{};
                result<test_result_monitor> const test{t};

                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(1 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };

            bsl::ut_check(2 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"make move t"} = []() {
            bsl::ut_given{} = []() {
                test_result_monitor t{};
                result<test_result_monitor> const test{bsl::move(t)};

                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(1 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };

            bsl::ut_check(2 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"make in place"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> const test{bsl::in_place};

                bsl::ut_then{} = [&test]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test.success());
                    bsl::ut_check(test.errc() == bsl::errc_success);
                };
            };

            bsl::ut_check(1 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"make errc"} = []() {
            bsl::ut_given{} = []() {
                bsl::errc_type<> const myerror{42};
                result<test_result_monitor> const test{myerror, bsl::here()};

                bsl::ut_then{} = [&test, &myerror]() {
                    bsl::ut_check(0 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test.failure());
                    bsl::ut_check(test.errc() == myerror);
                };
            };

            bsl::ut_check(0 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"make move"} = []() {
            bsl::ut_given{} = []() {
                bsl::errc_type<> myerror{42};
                result<test_result_monitor> const test{bsl::move(myerror), bsl::here()};

                bsl::ut_then{} = [&test, &myerror]() {
                    bsl::ut_check(0 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test.failure());
                    bsl::ut_check(test.errc() == myerror);
                };
            };

            bsl::ut_check(0 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"copy with t"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> const test1{bsl::in_place};
                result<test_result_monitor> const test2{test1};

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(1 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test1.success());
                    bsl::ut_check(test2.success());
                };
            };

            bsl::ut_check(2 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"copy with errc"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> const test1{bsl::errc_failure, bsl::here()};
                result<test_result_monitor> const test2{test1};

                bsl::ut_then{} = [&test1, &test2]() {
                    bsl::ut_check(0 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test1.failure());
                    bsl::ut_check(test2.failure());
                };
            };

            bsl::ut_check(0 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"move with t"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> test1{bsl::in_place};
                result<test_result_monitor> const test2{bsl::move(test1)};

                bsl::ut_then{} = [&test2]() {
                    bsl::ut_check(1 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(1 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test2.success());
                };
            };

            bsl::ut_check(2 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"move with errc"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> test1{bsl::errc_failure, bsl::here()};
                result<test_result_monitor> const test2{bsl::move(test1)};

                bsl::ut_then{} = [&test2]() {
                    bsl::ut_check(0 == test_result_monitor_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_constructor());
                    bsl::ut_check(0 == test_result_monitor_move_constructor());
                    bsl::ut_check(0 == test_result_monitor_copy_assignment());
                    bsl::ut_check(0 == test_result_monitor_move_assignment());
                    bsl::ut_check(test2.failure());
                };
            };

            bsl::ut_check(0 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"copy assignment with t"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> const test1{bsl::in_place};
                result<test_result_monitor> test2{bsl::in_place};

                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;

                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(2 == test_result_monitor_constructor());
                        bsl::ut_check(1 == test_result_monitor_copy_constructor());
                        bsl::ut_check(1 == test_result_monitor_move_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_assignment());
                        bsl::ut_check(2 == test_result_monitor_move_assignment());
                        bsl::ut_check(2 == test_result_monitor_destructor());
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };

            bsl::ut_check(4 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"move assignment with t"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> test1{bsl::in_place};
                result<test_result_monitor> test2{bsl::in_place};

                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);

                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(2 == test_result_monitor_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_constructor());
                        bsl::ut_check(2 == test_result_monitor_move_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_assignment());
                        bsl::ut_check(2 == test_result_monitor_move_assignment());
                        bsl::ut_check(2 == test_result_monitor_destructor());
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };

            bsl::ut_check(4 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"copy assignment with t/e"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> const test1{bsl::in_place};
                result<test_result_monitor> test2{bsl::errc_failure, bsl::here()};

                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;

                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(1 == test_result_monitor_constructor());
                        bsl::ut_check(1 == test_result_monitor_copy_constructor());
                        bsl::ut_check(1 == test_result_monitor_move_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_assignment());
                        bsl::ut_check(0 == test_result_monitor_move_assignment());
                        bsl::ut_check(1 == test_result_monitor_destructor());
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };

            bsl::ut_check(3 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"copy assignment with e/t"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> const test1{bsl::errc_failure, bsl::here()};
                result<test_result_monitor> test2{bsl::in_place};

                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = test1;

                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(1 == test_result_monitor_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_constructor());
                        bsl::ut_check(1 == test_result_monitor_move_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_assignment());
                        bsl::ut_check(0 == test_result_monitor_move_assignment());
                        bsl::ut_check(2 == test_result_monitor_destructor());
                        bsl::ut_check(test1.failure());
                        bsl::ut_check(test2.failure());
                    };
                };
            };

            bsl::ut_check(2 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"move assignment with t/e"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> test1{bsl::in_place};
                result<test_result_monitor> test2{bsl::errc_failure, bsl::here()};

                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);

                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(1 == test_result_monitor_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_constructor());
                        bsl::ut_check(2 == test_result_monitor_move_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_assignment());
                        bsl::ut_check(0 == test_result_monitor_move_assignment());
                        bsl::ut_check(1 == test_result_monitor_destructor());
                        bsl::ut_check(test1.success());
                        bsl::ut_check(test2.success());
                    };
                };
            };

            bsl::ut_check(3 == test_result_monitor_destructor());
        };

        bsl::ut_scenario{"move assignment with e/t"} = []() {
            bsl::ut_given{} = []() {
                result<test_result_monitor> test1{bsl::errc_failure, bsl::here()};
                result<test_result_monitor> test2{bsl::in_place};

                bsl::ut_when{} = [&test1, &test2]() {
                    test2 = bsl::move(test1);

                    bsl::ut_then{} = [&test1, &test2]() {
                        bsl::ut_check(1 == test_result_monitor_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_constructor());
                        bsl::ut_check(1 == test_result_monitor_move_constructor());
                        bsl::ut_check(0 == test_result_monitor_copy_assignment());
                        bsl::ut_check(0 == test_result_monitor_move_assignment());
                        bsl::ut_check(2 == test_result_monitor_destructor());
                        bsl::ut_check(test1.failure());
                        bsl::ut_check(test2.failure());
                    };
                };
            };

            bsl::ut_check(2 == test_result_monitor_destructor());
        };

        return bsl::ut_success();
    }
}

// test a void type
// test a l-value reference type
// test a const type
// test a const reference type
