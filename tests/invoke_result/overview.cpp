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
#include <bsl/ut.hpp>

namespace
{
    // void print_num(int i)
    // {
    //     bsl::print("yourmom: %d\n", i);
    // }

    // class Foo final
    // {
    // public:
    //     void print_num(int i) const // NOLINT
    //     {
    //         bsl::print("yourmom from Foo: %d\n", i);
    //     }
    // };
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

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to (t1.*f)(t2, ..., tN) when f is a
    // // pointer to a member function of a class T and is_base_of_v<T, decay_ty<decltype(t1)>> is true
    // // (i.e. bullet 1.1 of [func.require] in N4659 - the C++17 final working draft).
    // {
    //     // Non-constexpr context.
    //     auto b = base(42);
    //     auto d = derived(42);

    //     // Via base class.
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) & noexcept -> int&,
    //         int&>(b));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(b));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile & noexcept -> int volatile&,
    //         int volatile&>(b));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile & noexcept -> int const volatile&,
    //         int const volatile&>(b));

    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) && noexcept -> int&&, int&&>(bml::move(b)));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const && noexcept -> int const&&,
    //         int const&&>(bml::move(b)));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile && noexcept -> int volatile&&,
    //         int volatile&&>(bml::move(b)));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile && noexcept -> int const volatile&&,
    //         int const volatile&&>(bml::move(b)));

    //     // Via derived class.
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) & noexcept -> int&,
    //         int&>(d));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(d));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile & noexcept -> int volatile&,
    //         int volatile&>(d));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile & noexcept -> int const volatile&,
    //         int const volatile&>(d));

    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) && noexcept -> int&&,
    //         int&&>(bml::move(d)));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const && noexcept -> int const&&,
    //         int const&&>(bml::move(d)));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile && noexcept -> int volatile&&,
    //         int volatile&&>(bml::move(d)));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile && noexcept -> int const volatile&&,
    //         int const volatile&&>(bml::move(d)));

    //     // Constexpr context.
    //     constexpr auto cb = base(42);
    //     constexpr auto cd = derived(42);

    //     // Via base class.
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(cb));
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const && noexcept -> int const&&,
    //         int const&&>(bml::move(cb)));

    //     // Via derived class.
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(cd));
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const && noexcept -> int const&&,
    //         int const&&>(bml::move(cd)));
    // }

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to (t1.get().*f)(t2, ..., tN) when f is a
    // // pointer to a member function of a class T and decay_ty<decltype(t1)> is a specialization of
    // // reference_wrapper (i.e. bullet 1.2 of [func.require] in N4659 - the C++17 final working
    // // draft).
    // {
    //     // Non-constexpr context.
    //     auto b = base(42);
    //     auto d = derived(42);

    //     auto b_ref = bml::reference_wrapper(b);
    //     auto d_ref = bml::reference_wrapper(d);

    //     // Via reference_wrapper to base class.
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) & noexcept -> int&,
    //         int&>(b_ref));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(b_ref));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile & noexcept -> int volatile&,
    //         int volatile&>(b_ref));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile & noexcept -> int const volatile&,
    //         int const volatile&>(b_ref));

    //     // Via reference_wrapper to derived class.
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) & noexcept -> int&,
    //         int&>(d_ref));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(d_ref));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile & noexcept -> int volatile&,
    //         int volatile&>(d_ref));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile & noexcept -> int const volatile&,
    //         int const volatile&>(d_ref));

    //     // Constexpr context.
    //     constexpr auto cb_ref = bml::reference_wrapper(global_base);
    //     constexpr auto cd_ref = bml::reference_wrapper(global_derived);

    //     // Via reference_wrapper to base class.
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(cb_ref));

    //     // Via reference_wrapper to derived class.
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(cd_ref));
    // }

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to ((*t1).*f)(t2, ..., tN) when f is a
    // // pointer to a member function of a class T and t1 does not satisfy the previous two items
    // // (i.e. bullet 1.3 of [func.require] in N4659 - the C++17 final working draft).
    // {
    //     // Non-constexpr context.
    //     auto b = base(42);
    //     auto d = derived(42);

    //     // Via pointer to base class.
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) & noexcept -> int&,
    //         int&>(&b));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(&b));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile & noexcept -> int volatile&,
    //         int volatile&>(&b));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile & noexcept -> int const volatile&,
    //         int const volatile&>(&b));

    //     // Via pointer to derived class.
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) & noexcept -> int&,
    //         int&>(&d));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(&d));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) volatile & noexcept -> int volatile&,
    //         int volatile&>(&d));
    //     bmltb_assert(mem_fun_invoked<
    //         auto (no_copy&&) const volatile & noexcept -> int const volatile&,
    //         int const volatile&>(&d));

    //     // Constexpr context.
    //     constexpr auto cb = base(42);
    //     constexpr auto cd = derived(42);

    //     // Via pointer to base class.
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(&cb));

    //     // Via pointer to derived class.
    //     static_assert(mem_fun_invoked<
    //         auto (no_copy&&) const & noexcept -> int const&,
    //         int const&>(&cd));
    // }

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to t1.*f when N == 1 and f is a pointer
    // // to data member of a class T and is_base_of_v<T, decay_ty<decltype(t1)>> is true (i.e. bullet
    // // 1.4 of [func.require] in N4659 - the C++17 final working draft).
    // {
    //     // Non-constexpr context.
    //     auto b = base(42);
    //     auto d = derived(42);

    //     // Via base class.
    //     bmltb_assert(mem_var_invoked<int&>(b));
    //     bmltb_assert(mem_var_invoked<int const&>(static_cast<base const&>(b)));
    //     bmltb_assert(mem_var_invoked<int volatile&>(static_cast<base volatile&>(b)));
    //     bmltb_assert(mem_var_invoked<int const volatile&>(static_cast<base const volatile&>(b)));

    //     // Via derived class.
    //     bmltb_assert(mem_var_invoked<int&>(d));
    //     bmltb_assert(mem_var_invoked<int const&>(static_cast<derived const&>(d)));
    //     bmltb_assert(mem_var_invoked<int volatile&>(static_cast<derived volatile&>(d)));
    //     bmltb_assert(mem_var_invoked<int const volatile&>(static_cast<derived const volatile&>(d)));

    //     // Constexpr context.
    //     constexpr auto cb = base(42);
    //     constexpr auto cd = derived(42);

    //     // Via base class.
    //     static_assert(mem_var_invoked<int const&>(cb));

    //     // Via derived class.
    //     static_assert(mem_var_invoked<int const&>(cd));
    // }

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to t1.get().*f when N == 1 and f is a
    // // pointer to data member of a class T and decay_ty<decltype(t1)> is a specialization of
    // // reference_wrapper (i.e. bullet 1.5 of [func.require] in N4659 - the C++17 final working
    // // draft).
    // {
    //     // Non-constexpr context.
    //     auto b = base(42);
    //     auto d = derived(42);

    //     auto b_ref    = bml::reference_wrapper(b);
    //     auto b_ref_c  = bml::reference_wrapper<base const>(b);
    //     auto b_ref_v  = bml::reference_wrapper<base volatile>(b);
    //     auto b_ref_cv = bml::reference_wrapper<base const volatile>(b);

    //     auto d_ref    = bml::reference_wrapper(d);
    //     auto d_ref_c  = bml::reference_wrapper<derived const>(d);
    //     auto d_ref_v  = bml::reference_wrapper<derived volatile>(d);
    //     auto d_ref_cv = bml::reference_wrapper<derived const volatile>(d);

    //     // Via reference_wrapper to base class.
    //     bmltb_assert(mem_var_invoked<int&>(b_ref));
    //     bmltb_assert(mem_var_invoked<int const&>(b_ref_c));
    //     bmltb_assert(mem_var_invoked<int volatile&>(b_ref_v));
    //     bmltb_assert(mem_var_invoked<int const volatile&>(b_ref_cv));

    //     // Via reference_wrapper to derived class.
    //     bmltb_assert(mem_var_invoked<int&>(d_ref));
    //     bmltb_assert(mem_var_invoked<int const&>(d_ref_c));
    //     bmltb_assert(mem_var_invoked<int volatile&>(d_ref_v));
    //     bmltb_assert(mem_var_invoked<int const volatile&>(d_ref_cv));

    //     // Constexpr context.
    //     constexpr auto cb_ref = bml::reference_wrapper(global_base);
    //     constexpr auto cd_ref = bml::reference_wrapper(global_derived);

    //     // Via reference_wrapper to base class.
    //     static_assert(mem_var_invoked<int const&>(cb_ref));

    //     // Via reference_wrapper to derived class.
    //     static_assert(mem_var_invoked<int const&>(cd_ref));
    // }

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to (*t1).*f when N == 1 and f is a
    // // pointer to data member of a class T and t1 does not satisfy the previous two items (i.e.
    // // bullet 1.6 of [func.require] in N4659 - the C++17 final working draft).
    // {
    //     // Non-constexpr context.
    //     auto b = base(42);
    //     auto d = derived(42);

    //     // Via pointer to base class.
    //     bmltb_assert(mem_var_invoked<int&>(&b));
    //     bmltb_assert(mem_var_invoked<int const&>(static_cast<base const*>(&b)));
    //     bmltb_assert(mem_var_invoked<int volatile&>(static_cast<base volatile*>(&b)));
    //     bmltb_assert(mem_var_invoked<int const volatile&>(static_cast<base const volatile*>(&b)));

    //     // Via pointer to derived class.
    //     bmltb_assert(mem_var_invoked<int&>(&d));
    //     bmltb_assert(mem_var_invoked<int const&>(static_cast<derived const*>(&d)));
    //     bmltb_assert(mem_var_invoked<int volatile&>(static_cast<derived volatile*>(&d)));
    //     bmltb_assert(mem_var_invoked<int const volatile&>(
    //         static_cast<derived const volatile*>(&d)));

    //     // Constexpr context.
    //     constexpr auto cb = base(42);
    //     constexpr auto cd = derived(42);

    //     // Via pointer to base class.
    //     static_assert(mem_var_invoked<int const&>(static_cast<base const*>(&cb)));

    //     // Via pointer to derived class.
    //     static_assert(mem_var_invoked<int const&>(static_cast<derived const*>(&cd)));
    // }

    // // Check that INVOKE(f, t1, t2, ..., tN) is equivalent to f(t1, t2, ..., tN) in all other cases
    // // (i.e. bullet 1.7 of [func.require] in N4659 - the C++17 final working draft).
    // {
    //     // Invoke reference to free function.
    //     auto& ref = foo;
    //     constexpr auto& cref = constexpr_foo;

    //     bmltb_assert(other_invoked<int&>(ref));
    //     static_assert(other_invoked<int const&>(cref));

    //     // Invoke pointer to free function.
    //     auto ptr = foo;
    //     constexpr auto cptr = constexpr_foo;

    //     bmltb_assert(other_invoked<int&>(ptr));
    //     static_assert(other_invoked<int const&>(cptr));

    //     // Invoke function object.
    //     auto b = base(42);
    //     constexpr auto cb = base(42);

    //     bmltb_assert(other_invoked<int&>(b));
    //     bmltb_assert(other_invoked<int const&>(static_cast<base const&>(b)));
    //     bmltb_assert(other_invoked<int volatile&>(static_cast<base volatile&>(b)));
    //     bmltb_assert(other_invoked<int const volatile&>(static_cast<base const volatile&>(b)));

    //     bmltb_assert(other_invoked<int&&>(static_cast<base&&>(b)));
    //     bmltb_assert(other_invoked<int const&&>(static_cast<base const&&>(b)));
    //     bmltb_assert(other_invoked<int volatile&&>(static_cast<base volatile&&>(b)));
    //     bmltb_assert(other_invoked<int const volatile&&>(static_cast<base const volatile&&>(b)));

    //     static_assert(other_invoked<int const&>(cb));
    //     static_assert(other_invoked<int const&&>(bml::move(cb)));
    // }

    // // Check that INVOKE yields the invoke_failed tag type when its arguments do not form an
    // // invocable expression.
    // {
    //     auto b = base(42);
    //     auto b_ref = bml::reference_wrapper(b);
    //     auto b_fn = static_cast<auto (base::*)(no_copy&&) & noexcept -> int&>(&base::operator());

    //     auto& f_ref = foo;
    //     auto f_ptr = foo;

    //     auto not_func_obj = bmltb::class_type();

    //     check_invoke_failed(b_fn);
    //     check_invoke_failed(b_fn, b);
    //     check_invoke_failed(b_fn, b_ref);
    //     check_invoke_failed(b_fn, b, no_copy(), 2);
    //     check_invoke_failed(b_fn, b, 1, 2, 3.0);

    //     check_invoke_failed(b);
    //     check_invoke_failed(b, b_fn);
    //     check_invoke_failed(b, b_fn, 5, 4, b);
    //     check_invoke_failed(b, b);
    //     check_invoke_failed(b, b_ref);

    //     check_invoke_failed(b_ref);
    //     check_invoke_failed(b_ref, b_fn);
    //     check_invoke_failed(b_ref, b_fn, 5, 4, b);
    //     check_invoke_failed(b_ref, b);

    //     check_invoke_failed(f_ref);
    //     check_invoke_failed(f_ref, f_ref);
    //     check_invoke_failed(f_ref, no_copy(), 2);
    //     check_invoke_failed(f_ref, 1.3f, 2, 3);

    //     check_invoke_failed(f_ptr);
    //     check_invoke_failed(f_ptr, no_copy(), no_copy());
    //     check_invoke_failed(f_ptr, 1.3f, 2, 3);

    //     check_invoke_failed(not_func_obj);
    // }

    return bsl::ut_success();
}
