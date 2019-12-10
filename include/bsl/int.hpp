//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef BSL_INT_HPP
#define BSL_INT_HPP

#include "contracts.hpp"

#include <cstdint>
#include <type_traits>

/// Integer
///
/// Provides a bounded integer type. Unlike the built-in integer types,
/// this integer type has added checks to make sure the integer type
/// never overruns, underruns, wraps, loses data, divides by zero,
/// shifts bits away, or converts integers to pointers and back of the
/// wrong type.
///
/// These are all required by AUTOSAR, and other specs, and a great
/// description of how to perform this math can be found in the following
/// SEI CERT rules (we used these to implement this integer header):
/// https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap
/// https://wiki.sei.cmu.edu/confluence/display/c/INT31-C.+Ensure+that+integer+conversions+do+not+result+in+lost+or+misinterpreted+data
/// https://wiki.sei.cmu.edu/confluence/display/c/INT32-C.+Ensure+that+operations+on+signed+integers+do+not+result+in+overflow
/// https://wiki.sei.cmu.edu/confluence/display/c/INT33-C.+Ensure+that+division+and+remainder+operations+do+not+result+in+divide-by-zero+errors
/// https://wiki.sei.cmu.edu/confluence/display/c/INT34-C.+Do+not+shift+an+expression+by+a+negative+number+of+bits+or+by+greater+than+or+equal+to+the+number+of+bits+that+exist+in+the+operand
/// https://wiki.sei.cmu.edu/confluence/display/c/INT36-C.+Converting+a+pointer+to+integer+or+integer+to+pointer
///
/// If contracts are disabled, this class reverts to a standard integer
/// type so there is likely no (or minimal) performance hit for using this
/// class (with optimizations on of course... only tested with GCC). If you
/// do have contracts on, signed integer types should be avoided whenever
/// possible as they are far more expensive than unsigned. In addition,
/// operations like *, / and % should also be avoided as these are also
/// expensive, and instead, the >> and << operators should be used when
/// possible. In general, when contracts are enabled, integer manipulation
/// is expensive. Note that the BSL is intended for kernel, hypervisor, and
/// embedded use-cases where correctness is critically important. Depending
/// on your usecase, you might still benefit from the BSL, even if your use
/// case does not require this specific integer class as the BSL is designed
/// as a larger alternative to the GSL (not a replacement).
///
/// Certain functionally is also disabled based on the type by design. For
/// example, the intptr_t type is not supported as this type is not allowed
/// to be used in any scenario by most coding standards. If you wish to
/// use ptr -> int -> ptr conversions, it must be a uintptr_t. We also do not
/// support mixed types. If you want to add two integers, both integers must
/// be of the same type. If they are not, you can explicitly make them the
/// same type by using the convert() function. This also applies to
/// construction. We explicitly require that during construction, types are
/// the same. This means that you cannot create, for example, uint64_t from
/// a int literal, or even an unsigned literal. It must be the same type
/// (i.e., in most cases, UL or ULL). Another change to a typical integer type
/// is the bitwise operators like <<, >>, |, &, ^, and ~ are only supported
/// on unsigned types (as they make far less sense on signed types). This
/// specific limitation could be removed in the future if enough people using
/// the library complain. For now, the main use case is critical systems,
/// which will likely prefer this limitation in place.
///
/// This rule does have some
/// exceptions. For example, the rational operators, which are capable of
/// performing comparisons without the risk of overflow, underrun or wrapping,
/// and return a boolean, and not an integer type, support mixing types, and
/// the code handles all of these conversions for you, safely. The idea here,
/// is where a type change is needed, it is explicit, which is required by
/// AUTOSAR. This also ensures the order of operands in our operators doesn't
/// matter which is also required by AUTOSAR. If a convert is not needed,
/// and the order can remain interchangable, we perform the conversion to
/// provide the maximum possible flexibility without breaking AUTOSAR rules.
///
/// Another thing you will notice in this code is our approach to some of
/// these functions is inline with SEI CERT and AUTOSAR, and not, in some
/// cases, with what other projects have done. A good example of this
/// is how the convert function was implemented. Our goal is to ensure the
/// implementation is consistent with the specifications.
///

namespace bsl
{
#ifndef BSL_PAGE_SHIFT
    constexpr const std::uint32_t page_size = 0x1000;
    constexpr const std::uint32_t page_shift = 12;
#else
    constexpr const std::uint32_t page_size = (1 << BSL_PAGE_SHIFT);
    constexpr const std::uint32_t page_shift = BSL_PAGE_SHIFT;
#endif

    template<typename T>
    class integer;

    template<typename T>
    struct is_integer : std::false_type
    {};

    template<typename T>
    struct is_integer<integer<T>> : std::true_type
    {};

    template<typename T>
    inline constexpr bool is_integer_v = is_integer<T>::value;

    /// Unsigned
    ///
    /// Converts an unsigned value, stored in a signed type as an unsigned
    /// type. The resulting value is returned as a std::uintmax_t. If you
    /// need a value smaller than this, use the convert function. This is
    /// really just a helper for the convert class, which should be used in
    /// most scenarios instead.
    ///
    /// expects: val is unsigned
    /// ensures: none
    ///
    /// @param val the value to unsign
    /// @return val as a std::uintmax_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    [[nodiscard]] constexpr auto
    unsign(const std::intmax_t &val) -> std::uintmax_t
    {
        bsl::expects_audit(val >= 0);
        return static_cast<std::uintmax_t>(val);
    }

    /// Convert
    ///
    /// Given an integer value, and an integer type you wish to convert the
    /// integer value to, this function will perform the conversion. For
    /// example, this function will safely convert a std::uint64_t to a
    /// std::int8_t. If an overrun, underrun or wrap occurs in the process
    /// of the conversion, bsl::expects_audit will trigger (with the resulting
    /// error being determined by the contracts handler and AUTOSAR policy).
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param f the integer value to convert "from"
    /// @param loc the location of the convert call for debugging.
    /// @return f converted "from" type F "to" type T
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename F,
        typename T,
        std::enable_if_t<std::is_integral_v<F>> * = nullptr,
        std::enable_if_t<std::is_integral_v<T>> * = nullptr>
    [[nodiscard]] constexpr auto
    convert(const F &f, const source_location &loc = here()) -> T
    {
        using f_limits = std::numeric_limits<F>;
        using t_limits = std::numeric_limits<T>;

        if constexpr (std::is_same_v<F, T>) {
            return f;
        }

        if constexpr (std::is_signed_v<F>) {
            if constexpr (std::is_signed_v<T>) {
                if constexpr (f_limits::max() <= t_limits::max()) {
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(f <= t_limits::max(), loc);
                    bsl::expects_audit(f >= t_limits::min(), loc);
                    return static_cast<T>(f);
                }
            }
            else {
                if constexpr (unsign(f_limits::max()) <= t_limits::max()) {
                    bsl::expects_audit(f >= 0, loc);
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(unsign(f) <= t_limits::max(), loc);
                    return static_cast<T>(f);
                }
            }
        }
        else {
            if constexpr (std::is_signed_v<T>) {
                if constexpr (f_limits::max() <= unsign(t_limits::max())) {
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(f <= unsign(t_limits::max()), loc);
                    return static_cast<T>(f);
                }
            }
            else {
                if constexpr (f_limits::max() <= t_limits::max()) {
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(f <= t_limits::max(), loc);
                    return static_cast<T>(f);
                }
            }
        }
    }

    /// Integer
    ///
    /// Please see the above "file" level description
    ///
    template<typename T>
    class integer
    {
        static_assert(std::is_integral_v<T>);

    public:
        using value_type = T;
        using reference = T &;
        using const_reference = const T &;
        using pointer = T *;
        using const_pointer = const T *;

        constexpr integer() noexcept = default;

        template<typename U, std::enable_if_t<std::is_same_v<T, U>> * = nullptr>
        explicit constexpr integer(const U &val) noexcept : m_val{val}
        {}

        template<typename U>
        explicit integer(const U *ptr) noexcept
        {
            bsl::discard(ptr);

            static_assert(
                sizeof(U) == 0, "uintptr_t required for pointer types");
        }

        template<typename U, std::enable_if_t<std::is_same_v<T, U>> * = nullptr>
        constexpr auto
        operator=(const U &val) noexcept -> integer<T> &
        {
            m_val = val;
            return *this;
        }

        template<typename U>
        auto
        operator=(const U *ptr) noexcept -> integer<T> &
        {
            bsl::discard(ptr);

            static_assert(
                sizeof(U) == 0, "uintptr_t required for pointer types");
        }

        [[nodiscard]] constexpr auto
        get() noexcept -> reference
        {
            return m_val;
        }

        [[nodiscard]] constexpr auto
        get() const noexcept -> const_reference
        {
            return m_val;
        }

        template<typename U>
        [[nodiscard]] auto
        to_ptr() const noexcept -> U *
        {
            static_assert(
                sizeof(U) == 0, "uintptr_t required for pointer types");
        }

        [[nodiscard]] static constexpr auto
        is_signed() noexcept -> bool
        {
            return std::is_signed_v<T>;
        }

        [[nodiscard]] static constexpr auto
        is_unsigned() noexcept -> bool
        {
            return std::is_unsigned_v<T>;
        }

        [[nodiscard]] static constexpr auto
        digits() noexcept -> std::int32_t
        {
            return std::numeric_limits<T>::digits;
        }

        [[nodiscard]] static constexpr auto
        digits10() noexcept -> std::int32_t
        {
            return std::numeric_limits<T>::digits10;
        }

        [[nodiscard]] static constexpr auto
        min() noexcept -> value_type
        {
            return std::numeric_limits<T>::min();
        }

        [[nodiscard]] static constexpr auto
        max() noexcept -> value_type
        {
            return std::numeric_limits<T>::max();
        }

        template<typename U, std::enable_if_t<is_integer_v<U>> * = nullptr>
        [[nodiscard]] constexpr auto
        convert(const source_location &loc = here()) const -> U
        {
            return U{bsl::convert<T, typename U::value_type>(m_val, loc)};
        }

        [[nodiscard]] constexpr auto
        operator+=(const integer<T> &rhs) -> integer<T> &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    ((rhs.get() > 0) &&
                     (m_val > static_cast<T>(max() - rhs.get()))) ||
                    ((rhs.get() < 0) &&
                     (m_val < static_cast<T>(min() - rhs.get()))));
            }
            else {
                bsl::expects_audit_false(
                    static_cast<T>(max() - m_val) < rhs.get());
            }

            m_val += rhs.get();
            return *this;
        }

        [[nodiscard]] constexpr auto
        operator-=(const integer<T> &rhs) -> integer<T> &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (rhs.get() > 0 &&
                     m_val < static_cast<T>(min() + rhs.get())) ||
                    (rhs.get() < 0 &&
                     m_val > static_cast<T>(max() + rhs.get())));
            }
            else {
                bsl::expects_audit_false(m_val < rhs.get());
            }

            m_val -= rhs.get();
            return *this;
        }

        [[nodiscard]] constexpr auto
        operator*=(const integer<T> &rhs) -> integer<T> &
        {
            if (m_val == 0) {
                return *this;
            }

            if (rhs.get() == 0) {
                m_val = 0;
                return *this;
            }

            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (m_val > 0 && rhs.get() > 0 &&
                     m_val > static_cast<T>(max() / rhs.get())) ||
                    (m_val > 0 && rhs.get() < 0 &&
                     rhs.get() < static_cast<T>(min() / m_val)) ||
                    (m_val < 0 && rhs.get() > 0 &&
                     m_val < static_cast<T>(min() / rhs.get())) ||
                    (m_val < 0 && rhs.get() < 0 &&
                     rhs.get() < static_cast<T>(max() / m_val)));
            }
            else {
                bsl::expects_audit_false(
                    m_val > static_cast<T>(max() / rhs.get()));
            }

            m_val *= rhs.get();
            return *this;
        }

        [[nodiscard]] constexpr auto
        operator/=(const integer<T> &rhs) -> integer<T> &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (rhs.get() == 0) ||
                    ((m_val == min()) && (rhs.get() == -1)));
            }
            else {
                bsl::expects_audit_false(rhs.get() == 0);
            }

            m_val /= rhs.get();
            return *this;
        }

        [[nodiscard]] constexpr auto
        operator%=(const integer<T> &rhs) -> integer<T> &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (rhs.get() == 0) ||
                    ((m_val == min()) && (rhs.get() == -1)));
            }
            else {
                bsl::expects_audit_false(rhs.get() == 0);
            }

            m_val %= rhs.get();
            return *this;
        }

        [[nodiscard]] constexpr auto
        operator++() -> integer<T> &
        {
            return *this += 1;
        }

        [[nodiscard]] constexpr auto
        operator++(int) -> integer<T>
        {
            auto old = *this;
            ++(*this);
            return old;
        }

        [[nodiscard]] constexpr auto
        operator--() -> integer<T> &
        {
            return *this -= 1;
        }

        [[nodiscard]] constexpr auto
        operator--(int) -> integer<T>
        {
            auto old = *this;
            --(*this);
            return old;
        }

    private:
        value_type m_val{};
    };

    // -------------------------------------------------------------------------
    // specializations
    // -------------------------------------------------------------------------

    /// Pointer Constructor (uintptr_t)
    ///
    /// The use of reinterpret_cast is not allowed by pretty much every C++
    /// coding standard out there. In some situations however, it is required.
    /// For example, there really is no way to implement a hypervisor, kernel,
    /// or some embedded systems without having to convert a pointer to and
    /// from an integer, as they may be required by a specification. Our goal
    /// is to adhere to "do not use reinterpret_cast" rule as much as possible.
    /// When reinterpret_cast is needed, we have a second issue we must handle.
    /// AUTOSAR (and others) state that the only valid integer type that can
    /// be used is a uintptr_t. The pointer to integer and back functions are
    /// provided to ensure this second rule is enforced.
    ///
    /// It should, however, be noted that the use of these conversion
    /// functions should be treated as a reinterpret_cast. If these functions
    /// are used, an exception should be documented the same way any other
    /// exception would be documented.
    ///
    /// NOLINT:
    /// - To perform the conversion, we need to use a reinterpret_cast.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param ptr the pointer to convert to a uintptr_t
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<>
    template<typename U>
    inline integer<std::uintptr_t>::integer(const U *ptr) noexcept :
        m_val{reinterpret_cast<std::uintptr_t>(ptr)}    // NOLINT
    {}

    /// Pointer Assignment (uintptr_t)
    ///
    /// The use of reinterpret_cast is not allowed by pretty much every C++
    /// coding standard out there. In some situations however, it is required.
    /// For example, there really is no way to implement a hypervisor, kernel,
    /// or some embedded systems without having to convert a pointer to and
    /// from an integer, as they may be required by a specification. Our goal
    /// is to adhere to "do not use reinterpret_cast" rule as much as possible.
    /// When reinterpret_cast is needed, we have a second issue we must handle.
    /// AUTOSAR (and others) state that the only valid integer type that can
    /// be used is a uintptr_t. The pointer to integer and back functions are
    /// provided to ensure this second rule is enforced.
    ///
    /// It should, however, be noted that the use of these conversion
    /// functions should be treated as a reinterpret_cast. If these functions
    /// are used, an exception should be documented the same way any other
    /// exception would be documented.
    ///
    /// NOLINT:
    /// - To perform the conversion, we need to use a reinterpret_cast.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param ptr the pointer to convert to a uintptr_t
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<>
    template<typename U>
    inline auto
    integer<std::uintptr_t>::operator=(const U *ptr) noexcept -> integer &
    {
        m_val = reinterpret_cast<std::uintptr_t>(ptr);    // NOLINT
        return *this;
    }

    /// To Pointer (uintptr_t)
    ///
    /// The use of reinterpret_cast is not allowed by pretty much every C++
    /// coding standard out there. In some situations however, it is required.
    /// For example, there really is no way to implement a hypervisor, kernel,
    /// or some embedded systems without having to convert a pointer to and
    /// from an integer, as they may be required by a specification. Our goal
    /// is to adhere to "do not use reinterpret_cast" rule as much as possible.
    /// When reinterpret_cast is needed, we have a second issue we must handle.
    /// AUTOSAR (and others) state that the only valid integer type that can
    /// be used is a uintptr_t. The pointer to integer and back functions are
    /// provided to ensure this second rule is enforced.
    ///
    /// It should, however, be noted that the use of these conversion
    /// functions should be treated as a reinterpret_cast. If these functions
    /// are used, an exception should be documented the same way any other
    /// exception would be documented.
    ///
    /// NOLINT:
    /// - To perform the conversion, we need to use a reinterpret_cast.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @return a pointer to the requested type using the uintptr_t as the
    ///     address.
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<>
    template<typename U>
    [[nodiscard]] inline auto
    integer<std::uintptr_t>::to_ptr() const noexcept -> U *
    {
        return reinterpret_cast<U *>(m_val);    // NOLINT
    }

    // -------------------------------------------------------------------------
    // upper/lower
    // -------------------------------------------------------------------------

    template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
    [[nodiscard]] constexpr auto
    lower(
        const bsl::integer<T> &val,
        const unsigned &bits = bsl::page_shift) noexcept -> integer<T>
    {
        return integer<T>{val.get() & ((static_cast<T>(1) << bits) - 1)};
    }

    template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
    [[nodiscard]] constexpr auto
    upper(
        const bsl::integer<T> &val,
        const unsigned &bits = bsl::page_shift) noexcept -> integer<T>
    {
        return integer<T>{val.get() & ~((static_cast<T>(1) << bits) - 1)};
    }
}    // namespace bsl

// -------------------------------------------------------------------------
// integer rational operators
// -------------------------------------------------------------------------

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator==(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1>) {
        if constexpr (std::is_unsigned_v<T2>) {
            if (lhs.get() < 0) {
                return false;
            }

            return static_cast<std::uintmax_t>(lhs.get()) == rhs.get();
        }
        else {
            return lhs.get() == rhs.get();
        }
    }
    else {
        if constexpr (std::is_unsigned_v<T2>) {
            return lhs.get() == rhs.get();
        }
        else {
            if (rhs.get() < 0) {
                return false;
            }

            return lhs.get() == static_cast<std::uintmax_t>(rhs.get());
        }
    }
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator==(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs == bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator==(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} == rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator!=(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    return !(lhs == rhs);
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator!=(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} != rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator!=(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs != bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator>(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1>) {
        if constexpr (std::is_unsigned_v<T2>) {
            if (lhs.get() < 0) {
                return false;
            }

            return static_cast<std::uintmax_t>(lhs.get()) > rhs.get();
        }
        else {
            return lhs.get() > rhs.get();
        }
    }
    else {
        if constexpr (std::is_unsigned_v<T2>) {
            return lhs.get() > rhs.get();
        }
        else {
            if (rhs.get() < 0) {
                return true;
            }

            return lhs.get() > static_cast<std::uintmax_t>(rhs.get());
        }
    }
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator>(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs > bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator>(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} > rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator>=(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1>) {
        if constexpr (std::is_unsigned_v<T2>) {
            if (lhs.get() < 0) {
                return false;
            }

            return static_cast<std::uintmax_t>(lhs.get()) >= rhs.get();
        }
        else {
            return lhs.get() >= rhs.get();
        }
    }
    else {
        if constexpr (std::is_unsigned_v<T2>) {
            return lhs.get() >= rhs.get();
        }
        else {
            if (rhs.get() < 0) {
                return true;
            }

            return lhs.get() >= static_cast<std::uintmax_t>(rhs.get());
        }
    }
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator>=(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs >= bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator>=(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} >= rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator<(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1>) {
        if constexpr (std::is_unsigned_v<T2>) {
            if (lhs.get() < 0) {
                return true;
            }

            return static_cast<std::uintmax_t>(lhs.get()) < rhs.get();
        }
        else {
            return lhs.get() < rhs.get();
        }
    }
    else {
        if constexpr (std::is_unsigned_v<T2>) {
            return lhs.get() < rhs.get();
        }
        else {
            if (rhs.get() < 0) {
                return false;
            }

            return lhs.get() < static_cast<std::uintmax_t>(rhs.get());
        }
    }
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator<(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs < bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator<(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} < rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator<=(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1>) {
        if constexpr (std::is_unsigned_v<T2>) {
            if (lhs.get() < 0) {
                return true;
            }

            return static_cast<std::uintmax_t>(lhs.get()) <= rhs.get();
        }
        else {
            return lhs.get() <= rhs.get();
        }
    }
    else {
        if constexpr (std::is_unsigned_v<T2>) {
            return lhs.get() <= rhs.get();
        }
        else {
            if (rhs.get() < 0) {
                return false;
            }

            return lhs.get() <= static_cast<std::uintmax_t>(rhs.get());
        }
    }
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator<=(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs <= bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
[[nodiscard]] constexpr auto
operator<=(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} <= rhs;
}

// -------------------------------------------------------------------------
// integer arithmetic operators
// -------------------------------------------------------------------------

template<typename T>
[[nodiscard]] constexpr auto
operator+(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs)
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp += rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator+(const bsl::integer<T> &lhs, const T &rhs) -> bsl::integer<T>
{
    return lhs + bsl::integer<T>{rhs};
}

template<typename T>
[[nodiscard]] constexpr auto
operator+(const T &lhs, const bsl::integer<T> &rhs) -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} + rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator-(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs)
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp -= rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator-(const bsl::integer<T> &lhs, const T &rhs) -> bsl::integer<T>
{
    return lhs - bsl::integer<T>{rhs};
}

template<typename T>
[[nodiscard]] constexpr auto
operator-(const T &lhs, const bsl::integer<T> &rhs) -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} - rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator*(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs)
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp *= rhs;
}

template<typename T>
[[nodiscard]] constexpr auto operator*(const bsl::integer<T> &lhs, const T &rhs)
    -> bsl::integer<T>
{
    return lhs * bsl::integer<T>{rhs};
}

template<typename T>
[[nodiscard]] constexpr auto operator*(const T &lhs, const bsl::integer<T> &rhs)
    -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} * rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator/(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs)
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp /= rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator/(const bsl::integer<T> &lhs, const T &rhs) -> bsl::integer<T>
{
    return lhs / bsl::integer<T>{rhs};
}

template<typename T>
[[nodiscard]] constexpr auto
operator/(const T &lhs, const bsl::integer<T> &rhs) -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} / rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator%(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs)
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp %= rhs;
}

template<typename T>
[[nodiscard]] constexpr auto
operator%(const bsl::integer<T> &lhs, const T &rhs) -> bsl::integer<T>
{
    return lhs % bsl::integer<T>{rhs};
}

template<typename T>
[[nodiscard]] constexpr auto
operator%(const T &lhs, const bsl::integer<T> &rhs) -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} % rhs;
}

// -------------------------------------------------------------------------
// shirt operators
// -------------------------------------------------------------------------

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator<<=(bsl::integer<T> &lhs, const unsigned &bits) -> bsl::integer<T> &
{
    bsl::expects_audit(
        bsl::upper(lhs, bsl::integer<T>::digits() - bits).get() == 0);

    lhs.get() <<= bits;
    return lhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator<<(const bsl::integer<T> &lhs, const unsigned &bits) -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp <<= bits;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator>>=(bsl::integer<T> &lhs, const unsigned &bits) noexcept
    -> bsl::integer<T> &
{
    lhs.get() >>= bits;
    return lhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator>>(const bsl::integer<T> &lhs, const unsigned &bits) noexcept
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp >>= bits;
}

// -------------------------------------------------------------------------
// bitwise operators
// -------------------------------------------------------------------------

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator&=(bsl::integer<T> &lhs, const bsl::integer<T> &rhs) noexcept
    -> bsl::integer<T> &
{
    lhs.get() &= rhs.get();
    return lhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator&(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs) noexcept
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp &= rhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator&(const bsl::integer<T> &lhs, const T &rhs) noexcept -> bsl::integer<T>
{
    return lhs & bsl::integer<T>{rhs};
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator&(const T &lhs, const bsl::integer<T> &rhs) noexcept -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} & rhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator|=(bsl::integer<T> &lhs, const bsl::integer<T> &rhs) noexcept
    -> bsl::integer<T> &
{
    lhs.get() |= rhs.get();
    return lhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator|(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs) noexcept
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp |= rhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator|(const bsl::integer<T> &lhs, const T &rhs) noexcept -> bsl::integer<T>
{
    return lhs | bsl::integer<T>{rhs};
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator|(const T &lhs, const bsl::integer<T> &rhs) noexcept -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} | rhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator^=(bsl::integer<T> &lhs, const bsl::integer<T> &rhs) noexcept
    -> bsl::integer<T> &
{
    lhs.get() ^= rhs.get();
    return lhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator^(const bsl::integer<T> &lhs, const bsl::integer<T> &rhs) noexcept
    -> bsl::integer<T>
{
    bsl::integer<T> tmp = lhs;
    return tmp ^= rhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator^(const bsl::integer<T> &lhs, const T &rhs) noexcept -> bsl::integer<T>
{
    return lhs ^ bsl::integer<T>{rhs};
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator^(const T &lhs, const bsl::integer<T> &rhs) noexcept -> bsl::integer<T>
{
    return bsl::integer<T>{lhs} ^ rhs;
}

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator~(const bsl::integer<T> &rhs) noexcept -> bsl::integer<T>
{
    return bsl::integer<T>(~rhs.get());
}

// -------------------------------------------------------------------------
// unary operators
// -------------------------------------------------------------------------

template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator+(const bsl::integer<T> &rhs) noexcept -> bsl::integer<std::uintmax_t>
{
    return bsl::integer<std::uintmax_t>(static_cast<std::uintmax_t>(rhs.get()));
}

template<typename T, std::enable_if_t<std::is_signed_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator+(const bsl::integer<T> &rhs) noexcept -> bsl::integer<std::intmax_t>
{
    return bsl::integer<std::intmax_t>(static_cast<std::intmax_t>(rhs.get()));
}

template<typename T, std::enable_if_t<std::is_signed_v<T>> * = nullptr>
[[nodiscard]] constexpr auto
operator-(const bsl::integer<T> &rhs) -> bsl::integer<T>
{
    bsl::expects_audit_false(rhs.get() == bsl::integer<T>::min());
    return bsl::integer<T>(-rhs.get());
}

// -------------------------------------------------------------------------
// i/o
// -------------------------------------------------------------------------

template<typename T>
struct fmt::formatter<bsl::integer<T>>
{
    static auto
    parse(format_parse_context &ctx)
    {
        return ctx.begin();
    }

    template<typename FormatContext>
    auto
    format(const bsl::integer<T> &i, FormatContext &ctx)
    {
        return format_to(ctx.out(), "{}", i.get());
    }
};

template<typename T>
auto
operator<<(std::ostream &os, const bsl::integer<T> &i) -> std::ostream &
{
    os << i.get();
    return os;
}

template<typename T>
auto
operator>>(std::istream &is, const bsl::integer<T> &i) -> std::istream &
{
    is >> i.get();
    return is;
}

// -------------------------------------------------------------------------
// supported integer types
// -------------------------------------------------------------------------

namespace bsl
{
    using int8_t = integer<std::int8_t>;
    using int16_t = integer<std::int16_t>;
    using int32_t = integer<std::int32_t>;
    using int64_t = integer<std::int64_t>;
    using int_fast8_t = integer<std::int_fast8_t>;
    using int_fast16_t = integer<std::int_fast16_t>;
    using int_fast32_t = integer<std::int_fast32_t>;
    using int_fast64_t = integer<std::int_fast64_t>;
    using int_least8_t = integer<std::int_least8_t>;
    using int_least16_t = integer<std::int_least16_t>;
    using int_least32_t = integer<std::int_least32_t>;
    using int_least64_t = integer<std::int_least64_t>;
    using intmax_t = integer<std::intmax_t>;
    // using intptr_t = integer<std::intptr_t>; not allowed

    using uint8_t = integer<std::uint8_t>;
    using uint16_t = integer<std::uint16_t>;
    using uint32_t = integer<std::uint32_t>;
    using uint64_t = integer<std::uint64_t>;
    using uint_fast8_t = integer<std::uint_fast8_t>;
    using uint_fast16_t = integer<std::uint_fast16_t>;
    using uint_fast32_t = integer<std::uint_fast32_t>;
    using uint_fast64_t = integer<std::uint_fast64_t>;
    using uint_least8_t = integer<std::uint_least8_t>;
    using uint_least16_t = integer<std::uint_least16_t>;
    using uint_least32_t = integer<std::uint_least32_t>;
    using uint_least64_t = integer<std::uint_least64_t>;
    using uintmax_t = integer<std::uintmax_t>;
    using uintptr_t = integer<std::uintptr_t>;

    static_assert(sizeof(bsl::int8_t) == sizeof(std::int8_t));
    static_assert(sizeof(bsl::int16_t) == sizeof(std::int16_t));
    static_assert(sizeof(bsl::int32_t) == sizeof(std::int32_t));
    static_assert(sizeof(bsl::int64_t) == sizeof(std::int64_t));
    static_assert(sizeof(bsl::int_fast8_t) == sizeof(std::int_fast8_t));
    static_assert(sizeof(bsl::int_fast16_t) == sizeof(std::int_fast16_t));
    static_assert(sizeof(bsl::int_fast32_t) == sizeof(std::int_fast32_t));
    static_assert(sizeof(bsl::int_fast64_t) == sizeof(std::int_fast64_t));
    static_assert(sizeof(bsl::int_least8_t) == sizeof(std::int_least8_t));
    static_assert(sizeof(bsl::int_least16_t) == sizeof(std::int_least16_t));
    static_assert(sizeof(bsl::int_least32_t) == sizeof(std::int_least32_t));
    static_assert(sizeof(bsl::int_least64_t) == sizeof(std::int_least64_t));
    static_assert(sizeof(bsl::intmax_t) == sizeof(std::intmax_t));
    // static_assert(sizeof(bsl::intptr_t) == sizeof(std::intptr_t));

    static_assert(sizeof(bsl::uint8_t) == sizeof(std::uint8_t));
    static_assert(sizeof(bsl::uint16_t) == sizeof(std::uint16_t));
    static_assert(sizeof(bsl::uint32_t) == sizeof(std::uint32_t));
    static_assert(sizeof(bsl::uint64_t) == sizeof(std::uint64_t));
    static_assert(sizeof(bsl::uint_fast8_t) == sizeof(std::uint_fast8_t));
    static_assert(sizeof(bsl::uint_fast16_t) == sizeof(std::uint_fast16_t));
    static_assert(sizeof(bsl::uint_fast32_t) == sizeof(std::uint_fast32_t));
    static_assert(sizeof(bsl::uint_fast64_t) == sizeof(std::uint_fast64_t));
    static_assert(sizeof(bsl::uint_least8_t) == sizeof(std::uint_least8_t));
    static_assert(sizeof(bsl::uint_least16_t) == sizeof(std::uint_least16_t));
    static_assert(sizeof(bsl::uint_least32_t) == sizeof(std::uint_least32_t));
    static_assert(sizeof(bsl::uint_least64_t) == sizeof(std::uint_least64_t));
    static_assert(sizeof(bsl::uintmax_t) == sizeof(std::uintmax_t));
    static_assert(sizeof(bsl::uintptr_t) == sizeof(std::uintptr_t));
}    // namespace bsl

// -------------------------------------------------------------------------
// unit testing facilities
// -------------------------------------------------------------------------

namespace bsl
{
    // #ifndef NDEBUG
    constexpr const std::int32_t magic_4 = 4;
    constexpr const std::int32_t magic_8 = 8;
    constexpr const std::int32_t magic_15 = 15;
    constexpr const std::int32_t magic_16 = 16;
    constexpr const std::int32_t magic_23 = 23;
    constexpr const std::int32_t magic_42 = 42;

    constexpr const std::int8_t magic_8b_4 = 4;
    constexpr const std::int8_t magic_8b_8 = 8;
    constexpr const std::int8_t magic_8b_15 = 15;
    constexpr const std::int8_t magic_8b_16 = 16;
    constexpr const std::int8_t magic_8b_23 = 23;
    constexpr const std::int8_t magic_8b_42 = 42;

    constexpr const std::int16_t magic_16b_4 = 4;
    constexpr const std::int16_t magic_16b_8 = 8;
    constexpr const std::int16_t magic_16b_15 = 15;
    constexpr const std::int16_t magic_16b_16 = 16;
    constexpr const std::int16_t magic_16b_23 = 23;
    constexpr const std::int16_t magic_16b_42 = 42;

    constexpr const std::int32_t magic_32b_4 = 4;
    constexpr const std::int32_t magic_32b_8 = 8;
    constexpr const std::int32_t magic_32b_15 = 15;
    constexpr const std::int32_t magic_32b_16 = 16;
    constexpr const std::int32_t magic_32b_23 = 23;
    constexpr const std::int32_t magic_32b_42 = 42;

    constexpr const std::int64_t magic_64b_4 = 4;
    constexpr const std::int64_t magic_64b_8 = 8;
    constexpr const std::int64_t magic_64b_15 = 15;
    constexpr const std::int64_t magic_64b_16 = 16;
    constexpr const std::int64_t magic_64b_23 = 23;
    constexpr const std::int64_t magic_64b_42 = 42;

    constexpr const std::uint32_t magic_4u = 4;
    constexpr const std::uint32_t magic_8u = 8;
    constexpr const std::uint32_t magic_15u = 15;
    constexpr const std::uint32_t magic_16u = 16;
    constexpr const std::uint32_t magic_23u = 23;
    constexpr const std::uint32_t magic_42u = 42;

    constexpr const std::uint8_t magic_8b_4u = 4;
    constexpr const std::uint8_t magic_8b_8u = 8;
    constexpr const std::uint8_t magic_8b_15u = 15;
    constexpr const std::uint8_t magic_8b_16u = 16;
    constexpr const std::uint8_t magic_8b_23u = 23;
    constexpr const std::uint8_t magic_8b_42u = 42;

    constexpr const std::uint16_t magic_16b_4u = 4;
    constexpr const std::uint16_t magic_16b_8u = 8;
    constexpr const std::uint16_t magic_16b_15u = 15;
    constexpr const std::uint16_t magic_16b_16u = 16;
    constexpr const std::uint16_t magic_16b_23u = 23;
    constexpr const std::uint16_t magic_16b_42u = 42;

    constexpr const std::uint32_t magic_32b_4u = 4;
    constexpr const std::uint32_t magic_32b_8u = 8;
    constexpr const std::uint32_t magic_32b_15u = 15;
    constexpr const std::uint32_t magic_32b_16u = 16;
    constexpr const std::uint32_t magic_32b_23u = 23;
    constexpr const std::uint32_t magic_32b_42u = 42;

    constexpr const std::uint64_t magic_64b_4u = 4;
    constexpr const std::uint64_t magic_64b_8u = 8;
    constexpr const std::uint64_t magic_64b_15u = 15;
    constexpr const std::uint64_t magic_64b_16u = 16;
    constexpr const std::uint64_t magic_64b_23u = 23;
    constexpr const std::uint64_t magic_64b_42u = 42;
    // #endif
}    // namespace bsl

#endif
