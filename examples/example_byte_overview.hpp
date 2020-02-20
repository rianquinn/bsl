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

#ifndef EXAMPLE_BYTE_OVERVIEW_HPP
#define EXAMPLE_BYTE_OVERVIEW_HPP

#include <bsl/discard.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/arguments.hpp>

#include <bsl/print.hpp>
#include <bsl/byte.hpp>
#include <bsl/is_pod.hpp>

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
    [[maybe_unused]] inline bsl::exit_code
    example_byte_overview(bsl::arguments const &args) noexcept
    {
        bsl::discard(args);
        static_assert(is_pod<bsl::byte>::value);

        bsl::byte mybyte{1};
        bsl::print("byte: %u\n", mybyte.to_integer<bsl::uint32>());

        mybyte <<= 1U;
        bsl::print("byte: %u\n", mybyte.to_integer());
        mybyte >>= 1U;
        bsl::print("byte: %u\n", mybyte.to_integer());

        bsl::print("byte: %u\n", (mybyte << 1U).to_integer());
        bsl::print("byte: %u\n", (mybyte >> 1U).to_integer());

        mybyte &= bsl::byte{0};
        bsl::print("byte: %u\n", mybyte.to_integer());

        mybyte |= bsl::byte{1};
        bsl::print("byte: %u\n", mybyte.to_integer());

        mybyte ^= bsl::byte{1};
        bsl::print("byte: %u\n", mybyte.to_integer());

        bsl::print("byte: %u\n", (mybyte | bsl::byte{1}).to_integer());
        bsl::print("byte: %u\n", (mybyte & bsl::byte{1}).to_integer());
        bsl::print("byte: %u\n", (mybyte ^ bsl::byte{1}).to_integer());
        bsl::print("byte: %x\n", (~mybyte).to_integer());

        return bsl::exit_success;
    }
}

#endif
