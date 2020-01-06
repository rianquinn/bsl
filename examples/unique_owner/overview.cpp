///
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

#include <bsl/couple.hpp>
#include <bsl/unique_owner.hpp>
#include <bsl/contracts.hpp>

#include <deque>

namespace
{
    /// @brief defines the resource type we will use
    using myresource = bsl::couple<std::int32_t, std::deque<std::int32_t> *>;

    /// <!-- description -->
    ///   @brief Defines our custom deleter that will delete the resource once
    ///     it is no longer in use. In this case, we will take the value that was
    ///     owned and push it back onto a stack.
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param resource the resource owned by the bsl::unique_owner
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] none
    ///
    void
    mydeleter(myresource &&resource) noexcept
    {
        try {
            if (nullptr == resource.get1()) {
                bsl::fatal(bsl::here(), "corrupt stack pointer");
            }

            resource.get1()->emplace_back(resource.get0());
        }
        catch (...) {
            // handle as needed
        }
    }

    /// <!-- description -->
    ///   @brief Dumps the contents of a stack to the console
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param stack the stack to dump to the console
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] possible
    ///
    void
    dump_stack(std::deque<std::int32_t> const &stack)
    {
        for (std::int32_t const &val : stack) {
            fmt::print("{} ", val);
        }

        fmt::print("{}\n", stack);
    }

    /// <!-- description -->
    ///   @brief Makes an owner by popping a val from the stack and "owning" that
    ///     value until the owner loses scope, in which case the value is pushed
    ///     back onto the stack.
    ///
    /// <!-- contracts -->
    ///   @pre stack is not empty
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @return the new owner
    ///
    /// <!-- exceptions -->
    ///   @throw [checked] none
    ///   @throw [unchecked] possible
    ///
    bsl::unique_owner<myresource, &mydeleter>
    make_myowner(std::deque<std::int32_t> &stack)
    {
        bsl::expects(!stack.empty());

        const auto val{stack.back()};
        stack.pop_back();

        return bsl::unique_owner<myresource, &mydeleter>{{val, &stack}};
    }
}    // namespace

/// <!-- description -->
///   @brief example
///
/// <!-- contracts -->
///   @pre none
///   @post none
///
/// <!-- inputs/outputs -->
///   @return EXIT_SUCCESS
///
/// <!-- exceptions -->
///   @throw [checked] none
///   @throw [unchecked] none
///
std::int32_t
main() noexcept
{
    try {
        std::deque<std::int32_t> mystack{4, 8, 15, 16, 23, 42};
        dump_stack(mystack);

        {
            const auto res{make_myowner(mystack)};
            dump_stack(mystack);
        }

        dump_stack(mystack);
    }
    catch (...) {
    }
}
