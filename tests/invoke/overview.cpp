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

#include <bsl/invoke.hpp>
#include <bsl/is_same.hpp>
#include <bsl/reference_wrapper.hpp>

#include <bsl/ut.hpp>

namespace
{
    [[nodiscard]] constexpr bool
    test_func(bool val)
    {
        return val;
    }

    class test_base
    {
    public:
        constexpr test_base() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val)
        {
            return val;
        }
    };

    class test_const final
    {
    public:
        constexpr test_const() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const
        {
            return val;
        }
    };

    class test_noexcept final
    {
    public:
        constexpr test_noexcept() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const noexcept
        {
            return val;
        }
    };

    class test_final final : public test_base
    {
    public:
        constexpr test_final() noexcept = default;

        [[nodiscard]] constexpr bool
        operator()(bool val) const
        {
            return val;
        }
    };

    constexpr test_const g_test_const{};
    constexpr test_noexcept g_test_noexcept{};
    constexpr test_final g_test_final{};

    constexpr bsl::reference_wrapper<test_const const> g_rw_test_const{g_test_const};
    constexpr bsl::reference_wrapper<test_noexcept const> g_rw_test_noexcept{g_test_noexcept};
    constexpr bsl::reference_wrapper<test_final const> g_rw_test_final{g_test_final};
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

    static_assert(bsl::invoke(&test_func, true));
    static_assert(bsl::invoke(&test_const::operator(), g_test_const, true));
    static_assert(bsl::invoke(&test_noexcept::operator(), g_test_noexcept, true));
    static_assert(bsl::invoke(&test_final::operator(), g_test_final, true));


// void bullet_one_two_tests() {
//     {
//         TestClass cl(42);
//         test_b12<int&(NonCopyable&&) &, int&>(cl);
//         test_b12<int const&(NonCopyable&&) const &, int const&>(cl);
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(cl);
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(cl);

//         test_b12<int&&(NonCopyable&&) &&, int&&>(std::move(cl));
//         test_b12<int const&&(NonCopyable&&) const &&, int const&&>(std::move(cl));
//         test_b12<int volatile&&(NonCopyable&&) volatile &&, int volatile&&>(std::move(cl));
//         test_b12<int const volatile&&(NonCopyable&&) const volatile &&, int const volatile&&>(std::move(cl));
//     }
//     {
//         DerivedFromTestClass cl(42);
//         test_b12<int&(NonCopyable&&) &, int&>(cl);
//         test_b12<int const&(NonCopyable&&) const &, int const&>(cl);
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(cl);
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(cl);

//         test_b12<int&&(NonCopyable&&) &&, int&&>(std::move(cl));
//         test_b12<int const&&(NonCopyable&&) const &&, int const&&>(std::move(cl));
//         test_b12<int volatile&&(NonCopyable&&) volatile &&, int volatile&&>(std::move(cl));
//         test_b12<int const volatile&&(NonCopyable&&) const volatile &&, int const volatile&&>(std::move(cl));
//     }
//     {
//         TestClass cl_obj(42);
//         std::reference_wrapper<TestClass> cl(cl_obj);
//         test_b12<int&(NonCopyable&&) &, int&>(cl);
//         test_b12<int const&(NonCopyable&&) const &, int const&>(cl);
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(cl);
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(cl);

//         test_b12<int&(NonCopyable&&) &, int&>(std::move(cl));
//         test_b12<int const&(NonCopyable&&) const &, int const&>(std::move(cl));
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(std::move(cl));
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(std::move(cl));
//     }
//     {
//         DerivedFromTestClass cl_obj(42);
//         std::reference_wrapper<DerivedFromTestClass> cl(cl_obj);
//         test_b12<int&(NonCopyable&&) &, int&>(cl);
//         test_b12<int const&(NonCopyable&&) const &, int const&>(cl);
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(cl);
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(cl);

//         test_b12<int&(NonCopyable&&) &, int&>(std::move(cl));
//         test_b12<int const&(NonCopyable&&) const &, int const&>(std::move(cl));
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(std::move(cl));
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(std::move(cl));
//     }
//     {
//         TestClass cl_obj(42);
//         TestClass *cl = &cl_obj;
//         test_b12<int&(NonCopyable&&) &, int&>(cl);
//         test_b12<int const&(NonCopyable&&) const &, int const&>(cl);
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(cl);
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(cl);
//     }
//     {
//         DerivedFromTestClass cl_obj(42);
//         DerivedFromTestClass *cl = &cl_obj;
//         test_b12<int&(NonCopyable&&) &, int&>(cl);
//         test_b12<int const&(NonCopyable&&) const &, int const&>(cl);
//         test_b12<int volatile&(NonCopyable&&) volatile &, int volatile&>(cl);
//         test_b12<int const volatile&(NonCopyable&&) const volatile &, int const volatile&>(cl);
//     }
// }

// void bullet_three_four_tests() {
//     {
//         typedef TestClass Fn;
//         Fn cl(42);
//         test_b34<int&>(cl);
//         test_b34<int const&>(static_cast<Fn const&>(cl));
//         test_b34<int volatile&>(static_cast<Fn volatile&>(cl));
//         test_b34<int const volatile&>(static_cast<Fn const volatile &>(cl));

//         test_b34<int&&>(static_cast<Fn &&>(cl));
//         test_b34<int const&&>(static_cast<Fn const&&>(cl));
//         test_b34<int volatile&&>(static_cast<Fn volatile&&>(cl));
//         test_b34<int const volatile&&>(static_cast<Fn const volatile&&>(cl));
//     }
//     {
//         typedef DerivedFromTestClass Fn;
//         Fn cl(42);
//         test_b34<int&>(cl);
//         test_b34<int const&>(static_cast<Fn const&>(cl));
//         test_b34<int volatile&>(static_cast<Fn volatile&>(cl));
//         test_b34<int const volatile&>(static_cast<Fn const volatile &>(cl));

//         test_b34<int&&>(static_cast<Fn &&>(cl));
//         test_b34<int const&&>(static_cast<Fn const&&>(cl));
//         test_b34<int volatile&&>(static_cast<Fn volatile&&>(cl));
//         test_b34<int const volatile&&>(static_cast<Fn const volatile&&>(cl));
//     }
//     {
//         typedef TestClass Fn;
//         Fn cl(42);
//         test_b34<int&>(std::reference_wrapper<Fn>(cl));
//         test_b34<int const&>(std::reference_wrapper<Fn const>(cl));
//         test_b34<int volatile&>(std::reference_wrapper<Fn volatile>(cl));
//         test_b34<int const volatile&>(std::reference_wrapper<Fn const volatile>(cl));
//     }
//     {
//         typedef DerivedFromTestClass Fn;
//         Fn cl(42);
//         test_b34<int&>(std::reference_wrapper<Fn>(cl));
//         test_b34<int const&>(std::reference_wrapper<Fn const>(cl));
//         test_b34<int volatile&>(std::reference_wrapper<Fn volatile>(cl));
//         test_b34<int const volatile&>(std::reference_wrapper<Fn const volatile>(cl));
//     }
//     {
//         typedef TestClass Fn;
//         Fn cl_obj(42);
//         Fn* cl = &cl_obj;
//         test_b34<int&>(cl);
//         test_b34<int const&>(static_cast<Fn const*>(cl));
//         test_b34<int volatile&>(static_cast<Fn volatile*>(cl));
//         test_b34<int const volatile&>(static_cast<Fn const volatile *>(cl));
//     }
//     {
//         typedef DerivedFromTestClass Fn;
//         Fn cl_obj(42);
//         Fn* cl = &cl_obj;
//         test_b34<int&>(cl);
//         test_b34<int const&>(static_cast<Fn const*>(cl));
//         test_b34<int volatile&>(static_cast<Fn volatile*>(cl));
//         test_b34<int const volatile&>(static_cast<Fn const volatile *>(cl));
//     }
// }

// void bullet_five_tests() {
//     using FooType = int&(NonCopyable&&);
//     {
//         FooType& fn = foo;
//         test_b5<int &>(fn);
//     }
//     {
//         FooType* fn = foo;
//         test_b5<int &>(fn);
//     }
//     {
//         typedef TestClass Fn;
//         Fn cl(42);
//         test_b5<int&>(cl);
//         test_b5<int const&>(static_cast<Fn const&>(cl));
//         test_b5<int volatile&>(static_cast<Fn volatile&>(cl));
//         test_b5<int const volatile&>(static_cast<Fn const volatile &>(cl));

//         test_b5<int&&>(static_cast<Fn &&>(cl));
//         test_b5<int const&&>(static_cast<Fn const&&>(cl));
//         test_b5<int volatile&&>(static_cast<Fn volatile&&>(cl));
//         test_b5<int const volatile&&>(static_cast<Fn const volatile&&>(cl));
//     }
// }

// struct CopyThrows {
//   CopyThrows() {}
//   CopyThrows(CopyThrows const&) {}
//   CopyThrows(CopyThrows&&) noexcept {}
// };

// struct NoThrowCallable {
//   void operator()() noexcept {}
//   void operator()(CopyThrows) noexcept {}
// };

// struct ThrowsCallable {
//   void operator()() {}
// };

// struct MemberObj {
//   int x;
// };

// void noexcept_test() {
//     {
//         NoThrowCallable obj; ((void)obj); // suppress unused warning
//         CopyThrows arg; ((void)arg); // suppress unused warning
//         static_assert(noexcept(std::invoke(obj)), "");
//         static_assert(!noexcept(std::invoke(obj, arg)), "");
//         static_assert(noexcept(std::invoke(obj, std::move(arg))), "");
//     }
//     {
//         ThrowsCallable obj; ((void)obj); // suppress unused warning
//         static_assert(!noexcept(std::invoke(obj)), "");
//     }
//     {
//         MemberObj obj{42}; ((void)obj); // suppress unused warning.
//         static_assert(noexcept(std::invoke(&MemberObj::x, obj)), "");
//     }
// }

    return bsl::ut_success();
}
