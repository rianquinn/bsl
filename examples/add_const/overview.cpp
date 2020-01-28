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

#include <bsl/discard.hpp>
#include <bsl/main.hpp>

#include <bsl/is_const.hpp>
#include <bsl/add_const.hpp>
#include <bsl/remove_const.hpp>

#include <bsl/result.hpp>

#include <stdio.h>    // PRQA S 1014 // PRQA S 5188

namespace bsl
{
    /// @class test_monitor
    ///
    /// <!-- description -->
    ///   @brief test class for monitoring bsl::result
    ///
    class test_monitor final // PRQA S 5215
    {
    public:
        /// <!-- description -->
        ///   @brief default constructor
        ///
        test_monitor() noexcept
        {
            printf("Constructed\n");
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        test_monitor(test_monitor const &o) noexcept
        {
            bsl::discard(o);
            printf("Copy-constructed\n");
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        test_monitor(test_monitor &&o) noexcept
        {
            bsl::discard(o);
            printf("Move-constructed\n");
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///   @return *this
        ///
        [[maybe_unused]] test_monitor &
            operator=(test_monitor const &o) &
            noexcept
        {
            bsl::discard(o);
            printf("copy-assigned\n");

            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to move
        ///   @return *this
        ///
        [[maybe_unused]] test_monitor &
            operator=(test_monitor &&o) &
            noexcept
        {
            bsl::discard(o);
            printf("move-assigned\n");

            return *this;
        }

        /// <!-- description -->
        ///   @brief destructor
        ///
        ~test_monitor() noexcept
        {
            printf("Destructed\n");
        }
    };

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

        bsl::result<test_monitor> const test1{test_monitor{}};
        printf("--------------------------\n");
        bsl::result<test_monitor> test2{test1};
        printf("--------------------------\n");
        bsl::result<test_monitor> test3{bsl::move(test2)};
        printf("--------------------------\n");
        bsl::result<test_monitor> test4{test_monitor{}};
        printf("--------------------------\n");
        bsl::result<test_monitor> test5{test_monitor{}};
        printf("--------------------------\n");
        test4 = test3;
        printf("--------------------------\n");
        test5 = bsl::move(test4);

        if (auto const ptr = test4.get_if()) {
            *ptr = test_monitor{};
        }

        bsl::discard(test1);
        bsl::discard(test2);
        bsl::discard(test3);
        bsl::discard(test4);
        bsl::discard(test5);

        printf("--------------------------\n");
        bsl::result<test_monitor> const test10{bsl::errc_failure};
        bsl::result<test_monitor> const test11{bsl::errc_precondition};

        bsl::discard(test10);
        bsl::discard(test11);

        static_assert(bsl::is_const<bsl::add_const_t<bool>>::value);
        static_assert(bsl::is_const<bsl::add_const_t<bool const>>::value);
        static_assert(!bsl::is_const<bsl::remove_const_t<bool>>::value);
        static_assert(!bsl::is_const<bsl::remove_const_t<bool const>>::value);

        return bsl::exit_code::exit_success;
    }
}
