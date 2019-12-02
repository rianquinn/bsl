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

namespace bsl
{
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

    /// Absolute Value (signed)
    ///
    /// Returns the absolute value of a signed number as an unsigned
    /// integer. Note that the Standard Library version of this function
    /// returns the same type that it is given. We want everything
    /// returned as an unsigned type.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param t the integer to get the absolute value of
    /// @return the absolute value of t
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename T, std::enable_if_t<std::is_signed_v<T>> * = nullptr>
    [[nodiscard]] constexpr auto
    abs(const T &t) noexcept -> std::uintmax_t
    {
        if (t < 0) {
            return static_cast<std::uintmax_t>(-t);
        }

        return static_cast<std::uintmax_t>(t);
    }

    /// Absolute Value (unsigned)
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param t the number to return
    /// @return always returns t
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<typename T, std::enable_if_t<std::is_unsigned_v<T>> * = nullptr>
    [[nodiscard]] constexpr auto
    abs(const T &t) noexcept -> std::uintmax_t
    {
        return t;
    }

    /// Narrow
    ///
    /// Given an integer value, and an integer type you wish to narrow the
    /// integer value to, this function will perform the conversion. For
    /// example, this function will safely convert a std::uint64_t to a
    /// std::int8_t. If an overrun, underrun or wrap occurs in the process
    /// of the conversion, bsl::ensures will trigger (with the resulting
    /// error being determined by the contracts handler and AUTOSAR policy).
    ///
    /// expects: none
    /// ensures: no overruns underruns or wrapping
    ///
    /// @param t the integer value to narrow
    /// @return the narrowed version of t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename T,
        typename U,
        std::enable_if_t<std::is_integral_v<T>> * = nullptr,
        std::enable_if_t<std::is_integral_v<U>> * = nullptr>
    [[nodiscard]] auto
    narrow(const T &t, const source_location &loc = here()) -> U
    {
        using limits = std::numeric_limits<U>;

        if constexpr (std::is_signed_v<T>) {
            if constexpr (std::is_signed_v<U>) {
                bsl::ensures(t <= limits::max(), loc);
                bsl::ensures(t >= limits::min(), loc);
            }
            else {
                bsl::ensures(t >= 0, loc);
                bsl::ensures(abs(t) <= limits::max(), loc);
            }
        }
        else {
            if constexpr (std::is_signed_v<U>) {
                bsl::ensures(t <= abs(limits::max()), loc);
            }
            else {
                bsl::ensures(t <= limits::max(), loc);
                bsl::ensures(t >= limits::min(), loc);
            }
        }

        return static_cast<U>(t);
    }

    /// Expand
    ///
    /// Given an integer value, and an integer type you wish to expand the
    /// integer value to, this function will perform the conversion. For
    /// example, this function will safely convert a std::uint8_t to a
    /// std::int64_t. If an overrun, underrun or wrap occurs in the process
    /// of the conversion, bsl::ensures will trigger (with the resulting
    /// error being determined by the contracts handler and AUTOSAR policy).
    ///
    /// expects: none
    /// ensures: no overruns underruns or wrapping
    ///
    /// @param t the integer value to expand
    /// @return the expanded version of t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename T,
        typename U,
        std::enable_if_t<std::is_integral_v<T>> * = nullptr,
        std::enable_if_t<std::is_integral_v<U>> * = nullptr>
    [[nodiscard]] auto
    expand(const T &t, const source_location &loc = here()) -> U
    {
        return narrow<T, U>(t, loc);
    }

    /// Integer
    ///
    /// Provides a bounded integer type. Unlike the built-in integer types,
    /// this integer type has added checks to make sure the integer type
    /// never overruns, underruns or wraps. If contracts are disabled, this
    /// class reverts to a standard integer type so there is no performance
    /// hit for using this class if contracts are disabled in release mode.
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

        explicit constexpr integer(const value_type &val) noexcept : m_val{val}
        {}

        template<
            typename U,
            std::enable_if_t<std::is_integral_v<U>> * = nullptr,
            std::enable_if_t<!std::is_same_v<T, U>> * = nullptr>
        explicit constexpr integer(const U &val) noexcept :
            m_val{bsl::narrow<U, T>(val)}
        {}

        template<
            typename U,
            std::enable_if_t<!std::is_same_v<T, U>> * = nullptr>
        explicit integer(const integer<U> &val) :
            m_val{bsl::narrow<U, T>(val.get())}
        {}

        explicit integer(const void *ptr) noexcept = delete;

        constexpr auto
        operator=(const value_type &val) noexcept -> integer &
        {
            m_val = val;
            return *this;
        }

        template<
            typename U,
            std::enable_if_t<std::is_integral_v<U>> * = nullptr,
            std::enable_if_t<!std::is_same_v<T, U>> * = nullptr>
        constexpr auto
        operator=(const U &val) noexcept -> integer &
        {
            m_val = bsl::narrow<U, T>(val);
            return *this;
        }

        template<
            typename U,
            std::enable_if_t<!std::is_same_v<T, U>> * = nullptr>
        auto
        operator=(const integer<U> &val) noexcept -> integer &
        {
            m_val = bsl::narrow<U, T>(val.get());
            return *this;
        }

        [[nodiscard]] constexpr auto
        get() const noexcept -> value_type
        {
            return m_val;
        }

        template<typename U>
        [[nodiscard]] auto to_ptr() const noexcept -> U * = delete;

        [[nodiscard]] static constexpr auto
        is_signed() noexcept -> bool
        {
            return std::is_signed_v<T>;
        }

        [[nodiscard]] static constexpr auto
        digits() noexcept -> std::int32_t
        {
            return std::numeric_limits<T>::digits();
        }

        [[nodiscard]] static constexpr auto
        digits10() noexcept -> std::int32_t
        {
            return std::numeric_limits<T>::digits10();
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
        [[nodiscard]] auto
        narrow(const source_location &loc = here()) const -> U
        {
            if constexpr (std::is_same_v<T, U>) {
                return *this;
            }

            return U{bsl::narrow<T, typename U::value_type>(m_val, loc)};
        }

        // + - * ^ & | ~ += -= *= ^= &= |= << >> >>= <<= ++ --
        // / % /= %=

    private:
        value_type m_val{};
    };

    /// Pointer Constructor (uintptr_t)
    ///
    /// The use of reinterpret_cast is not allowed by pretty much every C++
    /// coding standard out there. In some situations however, it is required.
    /// When this happens, AUTOSAR states that the only valid type that can
    /// be used is a uintptr_t. This function provides support for this in a
    /// sane way, by requring that the only valid type that pointer arithmetic
    /// can be performed on is a uintptr_t.
    ///
    /// NOLINT:
    /// - To perform the conversion, we need to use a reinterpret_cast. This
    ///   is ok as we are only allowing this to be performed on uintptr_t
    ///   types. It should be noted, however, that this function's use should
    ///   be limited.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param ptr the pointer to convert to a uintptr_t
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<>
    inline integer<std::uintptr_t>::integer(const void *ptr) noexcept :
        m_val{reinterpret_cast<std::uintptr_t>(ptr)}    // NOLINT
    {}

    /// To Pointer (uintptr_t)
    ///
    /// The use of reinterpret_cast is not allowed by pretty much every C++
    /// coding standard out there. In some situations however, it is required.
    /// When this happens, AUTOSAR states that the only valid type that can
    /// be used is a uintptr_t. This function provides support for this in a
    /// sane way, by requring that the only valid type that pointer arithmetic
    /// can be performed on is a uintptr_t.
    ///
    /// NOLINT:
    /// - To perform the conversion, we need to use a reinterpret_cast. This
    ///   is ok as we are only allowing this to be performed on uintptr_t
    ///   types. It should be noted, however, that this function's use should
    ///   be limited.
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
    using intptr_t = integer<std::intptr_t>;

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
}    // namespace bsl

// -------------------------------------------------------------------------
// integer rational operators
// -------------------------------------------------------------------------

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator==(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1> && std::is_unsigned_v<T2>) {
        if (lhs.get() < 0) {
            return false;
        }

        return static_cast<std::uintmax_t>(lhs.get()) == rhs.get();
    }

    if constexpr (std::is_unsigned_v<T1> && std::is_signed_v<T2>) {
        if (rhs.get() < 0) {
            return false;
        }

        return lhs.get() == static_cast<std::uintmax_t>(rhs.get());
    }

    return lhs.get() == rhs.get();
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
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
constexpr auto
operator>(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1> && std::is_unsigned_v<T2>) {
        if (lhs.get() < 0) {
            return false;
        }

        return static_cast<std::uintmax_t>(lhs.get()) > rhs.get();
    }

    if constexpr (std::is_unsigned_v<T1> && std::is_signed_v<T2>) {
        if (rhs.get() < 0) {
            return true;
        }

        return lhs.get() > static_cast<std::uintmax_t>(rhs.get());
    }

    return lhs.get() > rhs.get();
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator>=(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1> && std::is_unsigned_v<T2>) {
        if (lhs.get() < 0) {
            return false;
        }

        return static_cast<std::uintmax_t>(lhs.get()) >= rhs.get();
    }

    if constexpr (std::is_unsigned_v<T1> && std::is_signed_v<T2>) {
        if (rhs.get() < 0) {
            return true;
        }

        return lhs.get() >= static_cast<std::uintmax_t>(rhs.get());
    }

    return lhs.get() >= rhs.get();
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator<(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1> && std::is_unsigned_v<T2>) {
        if (lhs.get() < 0) {
            return true;
        }

        return static_cast<std::uintmax_t>(lhs.get()) < rhs.get();
    }

    if constexpr (std::is_unsigned_v<T1> && std::is_signed_v<T2>) {
        if (rhs.get() < 0) {
            return false;
        }

        return lhs.get() < static_cast<std::uintmax_t>(rhs.get());
    }

    return lhs.get() < rhs.get();
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator<=(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs) noexcept
    -> bool
{
    if constexpr (std::is_signed_v<T1> && std::is_unsigned_v<T2>) {
        if (lhs.get() < 0) {
            return true;
        }

        return static_cast<std::uintmax_t>(lhs.get()) <= rhs.get();
    }

    if constexpr (std::is_unsigned_v<T1> && std::is_signed_v<T2>) {
        if (rhs.get() < 0) {
            return false;
        }

        return lhs.get() <= static_cast<std::uintmax_t>(rhs.get());
    }

    return lhs.get() <= rhs.get();
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator==(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs == bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator!=(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs != bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator>(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs > bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator>=(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs >= bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator<(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs < bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator<=(const bsl::integer<T1> &lhs, const T2 &rhs) noexcept -> bool
{
    return lhs <= bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator==(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} == rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator!=(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} != rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator>(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} > rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator>=(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} >= rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator<(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} < rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_integral_v<T1>> * = nullptr,
    std::enable_if_t<std::is_integral_v<T2>> * = nullptr>
constexpr auto
operator<=(const T1 &lhs, const bsl::integer<T2> &rhs) noexcept -> bool
{
    return bsl::integer<T1>{lhs} <= rhs;
}

// -------------------------------------------------------------------------
// integer arithmetic operators
// -------------------------------------------------------------------------

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_signed_v<T1>> * = nullptr,
    std::enable_if_t<std::is_signed_v<T2>> * = nullptr>
[[nodiscard]] auto
operator+(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs)
    -> bsl::integer<T1>
{
    auto tmp = rhs.template narrow<bsl::integer<T1>>();

    bsl::ensures_false(
        ((tmp.get() > 0) && (lhs.get() > (lhs.max() - tmp.get()))) ||
        ((tmp.get() < 0) && (lhs.get() < (lhs.min() - tmp.get()))));
    return bsl::integer<T1>{lhs.get() + tmp.get()};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_signed_v<T1>> * = nullptr,
    std::enable_if_t<std::is_signed_v<T2>> * = nullptr>
[[nodiscard]] auto
operator+(const bsl::integer<T1> &lhs, const T2 &rhs)
    -> bsl::integer<T1>
{
    return lhs + bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_signed_v<T1>> * = nullptr,
    std::enable_if_t<std::is_signed_v<T2>> * = nullptr>
[[nodiscard]] auto
operator+(const T1 &lhs, const bsl::integer<T2> &rhs)
    -> bsl::integer<T1>
{
    return bsl::integer<T1>{lhs} + rhs;
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_unsigned_v<T1>> * = nullptr,
    std::enable_if_t<std::is_unsigned_v<T2>> * = nullptr>
[[nodiscard]] auto
operator+(const bsl::integer<T1> &lhs, const bsl::integer<T2> &rhs)
    -> bsl::integer<T1>
{
    auto tmp = rhs.template narrow<bsl::integer<T1>>();

    bsl::ensures_false(tmp.max() - lhs.get() < rhs.get());
    return bsl::integer<T1>{lhs.get() + tmp.get()};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_unsigned_v<T1>> * = nullptr,
    std::enable_if_t<std::is_unsigned_v<T2>> * = nullptr>
[[nodiscard]] auto
operator+(const bsl::integer<T1> &lhs, const T2 &rhs)
    -> bsl::integer<T1>
{
    return lhs + bsl::integer<T2>{rhs};
}

template<
    typename T1,
    typename T2,
    std::enable_if_t<std::is_unsigned_v<T1>> * = nullptr,
    std::enable_if_t<std::is_unsigned_v<T2>> * = nullptr>
[[nodiscard]] auto
operator+(const T2 &lhs, const bsl::integer<T1> &rhs)
    -> bsl::integer<T1>
{
    return bsl::integer<T1>{lhs} + rhs;
}


// NOTES FOR ME
//
// unary is only allowed on signed types
// no division allowed
// subtraction from unsigned is allowed... need to think about this
//
//

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
static_assert(sizeof(bsl::intptr_t) == sizeof(std::intptr_t));

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

namespace bsl
{
#ifndef NDEBUG
    constexpr const std::int32_t magic_4 = 4;
    constexpr const std::int32_t magic_8 = 8;
    constexpr const std::int32_t magic_15 = 15;
    constexpr const std::int32_t magic_16 = 16;
    constexpr const std::int32_t magic_23 = 23;
    constexpr const std::int32_t magic_42 = 42;
    constexpr const std::uint32_t magic_4u = 4;
    constexpr const std::uint32_t magic_8u = 8;
    constexpr const std::uint32_t magic_15u = 15;
    constexpr const std::uint32_t magic_16u = 16;
    constexpr const std::uint32_t magic_23u = 23;
    constexpr const std::uint32_t magic_42u = 42;
#endif
}    // namespace bsl

#endif
