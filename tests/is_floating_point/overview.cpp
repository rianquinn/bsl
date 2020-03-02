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

#include <bsl/is_floating_point.hpp>
#include <bsl/ut.hpp>

namespace
{
    class myclass final
    {};

    struct mystruct final
    {};

    union myunion final
    {};

    enum class myenum : bsl::int32
    {
    };

    class myclass_abstract    // NOLINT
    {
    public:
        virtual ~myclass_abstract() noexcept = default;
        virtual void foo() noexcept = 0;
    };

    class myclass_base
    {};

    class myclass_subclass : public myclass_base
    {};
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
main()
{
    using namespace bsl;

    static_assert(!is_floating_point<bool>::value);
    static_assert(!is_floating_point<bool const>::value);
    static_assert(!is_floating_point<bsl::int8>::value);
    static_assert(!is_floating_point<bsl::int8 const>::value);
    static_assert(!is_floating_point<bsl::int16>::value);
    static_assert(!is_floating_point<bsl::int16 const>::value);
    static_assert(!is_floating_point<bsl::int32>::value);
    static_assert(!is_floating_point<bsl::int32 const>::value);
    static_assert(!is_floating_point<bsl::int64>::value);
    static_assert(!is_floating_point<bsl::int64 const>::value);
    static_assert(!is_floating_point<bsl::int_least8>::value);
    static_assert(!is_floating_point<bsl::int_least8 const>::value);
    static_assert(!is_floating_point<bsl::int_least16>::value);
    static_assert(!is_floating_point<bsl::int_least16 const>::value);
    static_assert(!is_floating_point<bsl::int_least32>::value);
    static_assert(!is_floating_point<bsl::int_least32 const>::value);
    static_assert(!is_floating_point<bsl::int_least64>::value);
    static_assert(!is_floating_point<bsl::int_least64 const>::value);
    static_assert(!is_floating_point<bsl::int_fast8>::value);
    static_assert(!is_floating_point<bsl::int_fast8 const>::value);
    static_assert(!is_floating_point<bsl::int_fast16>::value);
    static_assert(!is_floating_point<bsl::int_fast16 const>::value);
    static_assert(!is_floating_point<bsl::int_fast32>::value);
    static_assert(!is_floating_point<bsl::int_fast32 const>::value);
    static_assert(!is_floating_point<bsl::int_fast64>::value);
    static_assert(!is_floating_point<bsl::int_fast64 const>::value);
    static_assert(!is_floating_point<bsl::intptr>::value);
    static_assert(!is_floating_point<bsl::intptr const>::value);
    static_assert(!is_floating_point<bsl::intmax>::value);
    static_assert(!is_floating_point<bsl::intmax const>::value);
    static_assert(!is_floating_point<bsl::uint8>::value);
    static_assert(!is_floating_point<bsl::uint8 const>::value);
    static_assert(!is_floating_point<bsl::uint16>::value);
    static_assert(!is_floating_point<bsl::uint16 const>::value);
    static_assert(!is_floating_point<bsl::uint32>::value);
    static_assert(!is_floating_point<bsl::uint32 const>::value);
    static_assert(!is_floating_point<bsl::uint64>::value);
    static_assert(!is_floating_point<bsl::uint64 const>::value);
    static_assert(!is_floating_point<bsl::uint_least8>::value);
    static_assert(!is_floating_point<bsl::uint_least8 const>::value);
    static_assert(!is_floating_point<bsl::uint_least16>::value);
    static_assert(!is_floating_point<bsl::uint_least16 const>::value);
    static_assert(!is_floating_point<bsl::uint_least32>::value);
    static_assert(!is_floating_point<bsl::uint_least32 const>::value);
    static_assert(!is_floating_point<bsl::uint_least64>::value);
    static_assert(!is_floating_point<bsl::uint_least64 const>::value);
    static_assert(!is_floating_point<bsl::uint_fast8>::value);
    static_assert(!is_floating_point<bsl::uint_fast8 const>::value);
    static_assert(!is_floating_point<bsl::uint_fast16>::value);
    static_assert(!is_floating_point<bsl::uint_fast16 const>::value);
    static_assert(!is_floating_point<bsl::uint_fast32>::value);
    static_assert(!is_floating_point<bsl::uint_fast32 const>::value);
    static_assert(!is_floating_point<bsl::uint_fast64>::value);
    static_assert(!is_floating_point<bsl::uint_fast64 const>::value);
    static_assert(!is_floating_point<bsl::uintptr>::value);
    static_assert(!is_floating_point<bsl::uintptr const>::value);
    static_assert(!is_floating_point<bsl::uintmax>::value);
    static_assert(!is_floating_point<bsl::uintmax const>::value);
    static_assert(!is_floating_point<myclass>::value);
    static_assert(!is_floating_point<myclass const>::value);
    static_assert(!is_floating_point<mystruct>::value);
    static_assert(!is_floating_point<mystruct const>::value);
    static_assert(!is_floating_point<myunion>::value);
    static_assert(!is_floating_point<myunion const>::value);
    static_assert(!is_floating_point<myenum>::value);
    static_assert(!is_floating_point<myenum const>::value);
    static_assert(!is_floating_point<myclass_abstract>::value);
    static_assert(!is_floating_point<myclass_abstract const>::value);
    static_assert(!is_floating_point<myclass_base>::value);
    static_assert(!is_floating_point<myclass_base const>::value);
    static_assert(!is_floating_point<myclass_subclass>::value);
    static_assert(!is_floating_point<myclass_subclass const>::value);
    static_assert(!is_floating_point<bool[]>::value);              // NOLINT
    static_assert(!is_floating_point<bool[1]>::value);             // NOLINT
    static_assert(!is_floating_point<bool[][1]>::value);           // NOLINT
    static_assert(!is_floating_point<bool[1][1]>::value);          // NOLINT
    static_assert(!is_floating_point<bool const[]>::value);        // NOLINT
    static_assert(!is_floating_point<bool const[1]>::value);       // NOLINT
    static_assert(!is_floating_point<bool const[][1]>::value);     // NOLINT
    static_assert(!is_floating_point<bool const[1][1]>::value);    // NOLINT
    static_assert(!is_floating_point<void>::value);
    static_assert(!is_floating_point<void const>::value);
    static_assert(!is_floating_point<void *>::value);
    static_assert(!is_floating_point<void const *>::value);
    static_assert(!is_floating_point<void *const>::value);
    static_assert(!is_floating_point<void const *const>::value);
    static_assert(!is_floating_point<bool &>::value);
    static_assert(!is_floating_point<bool &&>::value);
    static_assert(!is_floating_point<bool const &>::value);
    static_assert(!is_floating_point<bool const &&>::value);
    static_assert(!is_floating_point<bool(bool)>::value);
    static_assert(!is_floating_point<bool (*)(bool)>::value);

    // static_assert(is_floating_point<float>::value);                // <-- Not supported
    // static_assert(is_floating_point<float const>::value);          // <-- Not supported
    // static_assert(is_floating_point<double>::value);               // <-- Not supported
    // static_assert(is_floating_point<double const>::value);         // <-- Not supported
    // static_assert(is_floating_point<long double>::value);          // <-- Not supported
    // static_assert(is_floating_point<long double const>::value);    // <-- Not supported

    return bsl::ut_success();
}
