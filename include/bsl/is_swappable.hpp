namespace __detail
{
    // ALL generic swap overloads MUST already have a declaration available at this point.

    template<class _Tp, class _Up = _Tp, bool _NotVoid = !is_void<_Tp>::value && !is_void<_Up>::value>
    struct __swappable_with
    {
        template<class _LHS, class _RHS>
        static decltype(swap(_VSTD::declval<_LHS>(), _VSTD::declval<_RHS>())) __test_swap(int);
        template<class, class>
        static __nat __test_swap(long);

        // Extra parens are needed for the C++03 definition of decltype.
        typedef decltype((__test_swap<_Tp, _Up>(0))) __swap1;
        typedef decltype((__test_swap<_Up, _Tp>(0))) __swap2;

        static const bool value = _IsNotSame<__swap1, __nat>::value && _IsNotSame<__swap2, __nat>::value;
    };

    template<class _Tp, class _Up>
    struct __swappable_with<_Tp, _Up, false> : false_type
    {};

    template<class _Tp, class _Up = _Tp, bool _Swappable = __swappable_with<_Tp, _Up>::value>
    struct __nothrow_swappable_with
    {
        static const bool value =
#ifndef _LIBCPP_HAS_NO_NOEXCEPT
            noexcept(swap(_VSTD::declval<_Tp>(), _VSTD::declval<_Up>())) &&
            noexcept(swap(_VSTD::declval<_Up>(), _VSTD::declval<_Tp>()));
#else
            false;
#endif
    };

    template<class _Tp, class _Up>
    struct __nothrow_swappable_with<_Tp, _Up, false> : false_type
    {};

}    // __detail

template<class _Tp>
struct __is_swappable : public integral_constant<bool, __detail::__swappable_with<_Tp &>::value>
{};

template<class _Tp>
struct __is_nothrow_swappable : public integral_constant<bool, __detail::__nothrow_swappable_with<_Tp &>::value>
{};
