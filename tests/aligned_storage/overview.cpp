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

#include <bsl/aligned_storage.hpp>
#include <bsl/alignment_of.hpp>

namespace
{
    template<typename T>
    constexpr void
    test_aligned_storage() noexcept
    {
        using namespace bsl;

        constexpr bsl::uintmax align = alignment_of<T>::value;
        constexpr bsl::uintmax bytes = sizeof(T);

        static_assert(alignment_of<aligned_storage_t<bytes, align>>::value == align);
        static_assert(sizeof(aligned_storage_t<bytes, align>) >= bytes);
    }
}

bsl::exit_code
main()
{
    using namespace bsl;

    test_aligned_storage<bsl::int8>();
    test_aligned_storage<bsl::int16>();
    test_aligned_storage<bsl::int32>();
    test_aligned_storage<bsl::int64>();

    test_aligned_storage<bsl::uint8>();
    test_aligned_storage<bsl::uint16>();
    test_aligned_storage<bsl::uint32>();
    test_aligned_storage<bsl::uint64>();

    test_aligned_storage<bsl::uint8[BSL_PAGE_SIZE]>();    // NOLINT

    return ut_success();
}
