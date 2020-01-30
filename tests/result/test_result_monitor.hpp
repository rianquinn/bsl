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

#ifndef BSL_TEST_MONITOR_HPP
#define BSL_TEST_MONITOR_HPP

#include <bsl/discard.hpp>
#include <bsl/cstdint.hpp>

namespace bsl
{
    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of default constructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of default constructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_constructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_constructor{};
        return s_test_result_monitor_constructor;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of copy constructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of copy constructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_copy_constructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_copy_constructor{};
        return s_test_result_monitor_copy_constructor;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of move constructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of move constructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_move_constructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_move_constructor{};
        return s_test_result_monitor_move_constructor;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of copy assignments that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of copy assignments that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_copy_assignment() noexcept
    {
        static bsl::int64 s_test_result_monitor_copy_assignment{};
        return s_test_result_monitor_copy_assignment;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of move assignments that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of move assignments that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_move_assignment() noexcept
    {
        static bsl::int64 s_test_result_monitor_move_assignment{};
        return s_test_result_monitor_move_assignment;
    }

    /// <!-- description -->
    ///   @brief Returns a reference to a global test variable for tracking
    ///     the total number of destructors that have executed.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return a reference to a global test variable for tracking
    ///     the total number of destructors that have executed.
    ///
    template<typename T = void>
    bsl::int64 &
    test_result_monitor_destructor() noexcept
    {
        static bsl::int64 s_test_result_monitor_destructor{};
        return s_test_result_monitor_destructor;
    }

    /// <!-- description -->
    ///   @brief Resets all of the stats
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    template<typename T = void>
    void
    test_result_monitor_reset() noexcept
    {
        test_result_monitor_constructor() = 0;
        test_result_monitor_copy_constructor() = 0;
        test_result_monitor_move_constructor() = 0;
        test_result_monitor_copy_assignment() = 0;
        test_result_monitor_move_assignment() = 0;
        test_result_monitor_destructor() = 0;
    }

    /// @class bsl::example_class_base
    ///
    /// <!-- description -->
    ///   @brief A simple class for monitoring construction and assignment
    ///     stats.
    ///
    class test_result_monitor final
    {
    public:
        /// <!-- description -->
        ///   @brief default constructor
        ///
        test_result_monitor() noexcept
        {
            test_result_monitor_constructor()++;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        test_result_monitor(test_result_monitor const &o) noexcept
        {
            bsl::discard(o);
            test_result_monitor_copy_constructor()++;
        }

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///
        test_result_monitor(test_result_monitor &&o) noexcept
        {
            bsl::discard(o);
            test_result_monitor_move_constructor()++;
        }

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to copy
        ///   @return *this
        ///
        [[maybe_unused]] test_result_monitor &
            operator=(test_result_monitor const &o) &
            noexcept
        {
            bsl::discard(o);
            test_result_monitor_copy_assignment()++;

            return *this;
        }

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object to move
        ///   @return *this
        ///
        [[maybe_unused]] test_result_monitor &
            operator=(test_result_monitor &&o) &
            noexcept
        {
            bsl::discard(o);
            test_result_monitor_move_assignment()++;

            return *this;
        }

        /// <!-- description -->
        ///   @brief destructor
        ///
        ~test_result_monitor() noexcept
        {
            test_result_monitor_destructor()++;
        }
    };
}

#endif
