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

#ifndef BSL_INTEGER_HPP
#define BSL_INTEGER_HPP

#include "contracts.hpp"

#include <cstdint>
#include <type_traits>

namespace bsl
{
    /// @brief provides a prototype for the integer type
    template<typename T>
    class integer;

    /// @brief returns false if the provided type is not a bsl::integer
    template<typename T>
    struct is_integer : std::false_type
    {};

    /// @brief returns true if the provided type is not a bsl::integer
    template<typename T>
    struct is_integer<integer<T>> : std::true_type
    {};

    /// @class integer
    ///
    /// Provides a bounded integer type. Unlike the built-in integer types,
    /// this integer type has added checks to make sure the integer type
    /// never overruns, underruns, wraps, loses data, divides by zero,
    /// shifts bits away, etc...
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
    /// embedded use-cases where correctness is critically important.
    ///
    /// Certain functionally is also disabled based on the type by design. For
    /// example, the intptr_t type is not supported as this type is not allowed
    /// to be used in any scenario by most coding standards. We also do not
    /// support mixed types. If you want to add two integers, both integers must
    /// be of the same type. If they are not, you can explicitly make them the
    /// same type by using the convert() function. This also applies to
    /// construction. We explicitly require that during construction, types are
    /// the same. This means that you cannot create, for example, uint64_t from
    /// a int literal, or even an unsigned literal. It must be the same type.
    /// To support this, all magic number should be created using a constexpr
    /// version of a bsl::integer, intialized using direct list initialization
    /// without the use of L or U literals. The compiler will perform the
    /// conversion / errors as needed. Another change to a typical integer type
    /// is the bitwise operators like <<, >>, |, &, ^, and ~ are only supported
    /// on unsigned types (as they make far less sense on signed types). This
    /// specific limitation could be removed in the future if enough people
    /// using the library complain. For now, the main use case is critical
    /// systems, which will likely prefer this limitation in place.
    ///
    template<typename T>
    class integer final
    {
        static_assert(std::is_integral<T>::value, "only integer types are supported");

    public:
        /// @brief the type T that the integer class stores
        using value_type = T;
        /// @brief a reference to the type T that the integer class stores
        using reference = T &;
        /// @brief a const reference to the type T that the integer class stores
        using const_reference = T const &;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr integer() noexcept : m_val{}
        {}

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr integer(integer const &o) noexcept = default;

        /// @brief constructor
        ///
        /// Creates an integer given an initial value. Normally, you would
        /// do so using "value_type const &val". The problem with this approach
        /// is the compiler is allowed to use implicit conversions, even when
        /// we use "explicit". To overcome this, we implement this function
        /// using a template U and is_same as this forces the compiler to
        /// ensure the types are the same.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param val the value to set the integer to
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename U, std::enable_if_t<std::is_same<T, U>::value> * = nullptr>
        explicit constexpr integer(U const &val) noexcept : m_val{val}
        {}

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be moved
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr integer(integer &&o) noexcept = default;

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @return a reference to the newly copied object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr integer &operator=(integer const &o) &noexcept = default;

        // clang-format off

        /// @brief operator =
        ///
        /// Creates an integer given an initial value. Normally, you would
        /// do so using "value_type const &val". The problem with this approach
        /// is the compiler is allowed to use implicit conversions, even when
        /// we use "explicit". To overcome this, we implement this function
        /// using a template U and is_same as this forces the compiler to
        /// ensure the types are the same.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param val the value to set the integer to
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename U, std::enable_if_t<std::is_same<T, U>::value> * = nullptr>
        [[maybe_unused]] constexpr integer<T> &
        operator=(U const &val) &noexcept
        {
            m_val = val;
            return *this;
        }

        // clang-format on

        /// @brief operator =
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be moved
        /// @return a reference to the newly moved object
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr integer &operator=(integer &&o) &noexcept = default;

        /// @brief destructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~integer() noexcept = default;

        /// @brief get
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns a reference to the value stored
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr reference
        get() noexcept
        {
            return m_val;
        }

        /// @brief get
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns a const reference to the value stored
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] constexpr const_reference
        get() const noexcept
        {
            return m_val;
        }

        /// @brief is_signed
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns true if the integer is signed, false otherwise
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr bool
        is_signed() noexcept
        {
            return std::is_signed_v<T>;
        }

        /// @brief is_unsigned
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns true if the integer is unsigned, false otherwise
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr bool
        is_unsigned() noexcept
        {
            return std::is_unsigned_v<T>;
        }

        /// @brief digits
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns std::numeric_limits<T>::digits;
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr std::int32_t
        digits() noexcept
        {
            return std::numeric_limits<T>::digits;
        }

        /// @brief digits10
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns std::numeric_limits<T>::digits10;
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr std::int32_t
        digits10() noexcept
        {
            return std::numeric_limits<T>::digits10;
        }

        /// @brief min
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns std::numeric_limits<T>::min();
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr value_type
        min() noexcept
        {
            return std::numeric_limits<T>::min();
        }

        /// @brief max
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns std::numeric_limits<T>::max();
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        [[nodiscard]] static constexpr value_type
        max() noexcept
        {
            return std::numeric_limits<T>::max();
        }

        /// @brief convert
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param sloc the location of the convert_to call used for debugging.
        /// @return returns a coverted version of the stored value
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        template<typename U, std::enable_if_t<is_integer<U>::value> * = nullptr>
        [[nodiscard]] constexpr U
        convert_to(sloc_type const &sloc = here()) const
        {
            return U{bsl::convert<U::value_type>(m_val, sloc)};
        }

        /// @brief operator +=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator+=(integer<T> const &rhs) &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    ((rhs.get() > 0) && (m_val > static_cast<T>(max() - rhs.get()))) ||
                    ((rhs.get() < 0) && (m_val < static_cast<T>(min() - rhs.get()))));
            }
            else {
                bsl::expects_audit_false(static_cast<T>(max() - m_val) < rhs.get());
            }

            m_val += rhs.get();
            return *this;
        }

        /// @brief operator +=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator+=(T const &rhs) &
        {
            return *this += integer<T>{rhs};
        }

        /// @brief operator -=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator-=(integer<T> const &rhs) &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (rhs.get() > 0 && m_val < static_cast<T>(min() + rhs.get())) ||
                    (rhs.get() < 0 && m_val > static_cast<T>(max() + rhs.get())));
            }
            else {
                bsl::expects_audit_false(m_val < rhs.get());
            }

            m_val -= rhs.get();
            return *this;
        }

        /// @brief operator -=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator-=(T const &rhs) &
        {
            return *this -= integer<T>{rhs};
        }

        /// @brief operator *=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator*=(integer<T> const &rhs) &
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
                    (m_val > 0 && rhs.get() > 0 && m_val > static_cast<T>(max() / rhs.get())) ||
                    (m_val > 0 && rhs.get() < 0 && rhs.get() < static_cast<T>(min() / m_val)) ||
                    (m_val < 0 && rhs.get() > 0 && m_val < static_cast<T>(min() / rhs.get())) ||
                    (m_val < 0 && rhs.get() < 0 && rhs.get() < static_cast<T>(max() / m_val)));
            }
            else {
                bsl::expects_audit_false(m_val > static_cast<T>(max() / rhs.get()));
            }

            m_val *= rhs.get();
            return *this;
        }

        /// @brief operator *=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator*=(T const &rhs) &
        {
            return *this *= integer<T>{rhs};
        }

        /// @brief operator /=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator/=(integer<T> const &rhs) &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (rhs.get() == 0) || ((m_val == min()) && (rhs.get() == -1)));
            }
            else {
                bsl::expects_audit_false(rhs.get() == 0);
            }

            m_val /= rhs.get();
            return *this;
        }

        /// @brief operator /=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator/=(T const &rhs) &
        {
            return *this /= integer<T>{rhs};
        }

        /// @brief operator %=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator%=(integer<T> const &rhs) &
        {
            if constexpr (std::is_signed_v<T>) {
                bsl::expects_audit_false(
                    (rhs.get() == 0) || ((m_val == min()) && (rhs.get() == -1)));
            }
            else {
                bsl::expects_audit_false(rhs.get() == 0);
            }

            m_val %= rhs.get();
            return *this;
        }

        /// @brief operator %=
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param rhs the right hand side of the operator
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator%=(T const &rhs) &
        {
            return *this %= integer<T>{rhs};
        }

        /// @brief operator ++
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator++()
        {
            return *this += static_cast<T>(1);
        }

        /// @brief operator ++
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param i ignored
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T>
        operator++(int i)
        {
            static_cast<void>(i);

            const auto old = *this;
            ++(*this);
            return old;
        }

        /// @brief operator --
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T> &
        operator--()
        {
            return *this -= static_cast<T>(1);
        }

        /// @brief operator --
        ///
        /// expects: no overruns underruns or wrapping
        /// ensures: none
        ///
        /// @param i ignored
        /// @return returns a reference to this bsl::integer
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[maybe_unused]] constexpr integer<T>
        operator--(int i)
        {
            static_cast<void>(i);

            const auto old = *this;
            --(*this);
            return old;
        }

        /// @brief to_string
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the string version of the stored value in dec
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[nodiscard]] std::string
        to_string() const
        {
            return fmt::format("{0:d}", m_val);
        }

        /// @brief to_hex_string
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns the string version of the stored value in hex
        /// @throw [checked]: none
        /// @throw [unchecked]: possible
        ///
        [[nodiscard]] std::string
        to_hex_string() const
        {
            return fmt::format("{:#018x}", m_val);
        }

    private:
        /// @brief the value stored by this integer
        value_type m_val;
    };

    /// @brief operator <<
    ///
    /// Provides support for outputing a bsl::integer.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param os the stream to output the source location to
    /// @param val the integer to output
    /// @return a reference to the output stream provided
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T>
    std::ostream &
    operator<<(std::ostream &os, integer<T> const &val)
    {
        return os << val.get();
    }
}    // namespace bsl

// -------------------------------------------------------------------------
// integer rational operators
// -------------------------------------------------------------------------

namespace bsl
{
    /// @brief operator ==
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs == rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator==(bsl::integer<T1> const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        if constexpr (std::is_signed<T1>::value) {
            if constexpr (std::is_unsigned<T2>::value) {
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
            if constexpr (std::is_unsigned<T2>::value) {
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

    /// @brief operator ==
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs == rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator==(bsl::integer<T1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs == bsl::integer<T2>{rhs};
    }

    /// @brief operator ==
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs == rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator==(T1 const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return bsl::integer<T1>{lhs} == rhs;
    }

    /// @brief operator !=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs != rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator!=(bsl::integer<T1> const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return !(lhs == rhs);
    }

    /// @brief operator !=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs != rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator!=(T1 const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return bsl::integer<T1>{lhs} != rhs;
    }

    /// @brief operator !=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs != rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator!=(bsl::integer<T1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs != bsl::integer<T2>{rhs};
    }

    /// @brief operator >
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs > rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator>(bsl::integer<T1> const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        if constexpr (std::is_signed<T1>::value) {
            if constexpr (std::is_unsigned<T2>::value) {
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
            if constexpr (std::is_unsigned<T2>::value) {
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

    /// @brief operator >
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs > rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator>(bsl::integer<T1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs > bsl::integer<T2>{rhs};
    }

    /// @brief operator >
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs > rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator>(T1 const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return bsl::integer<T1>{lhs} > rhs;
    }

    /// @brief operator >=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs >= rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator>=(bsl::integer<T1> const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        if constexpr (std::is_signed<T1>::value) {
            if constexpr (std::is_unsigned<T2>::value) {
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
            if constexpr (std::is_unsigned<T2>::value) {
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

    /// @brief operator >=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs >= rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator>=(bsl::integer<T1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs >= bsl::integer<T2>{rhs};
    }

    /// @brief operator >=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs >= rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator>=(T1 const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return bsl::integer<T1>{lhs} >= rhs;
    }

    /// @brief operator <
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs < rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator<(bsl::integer<T1> const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        if constexpr (std::is_signed<T1>::value) {
            if constexpr (std::is_unsigned<T2>::value) {
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
            if constexpr (std::is_unsigned<T2>::value) {
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

    /// @brief operator <
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs < rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator<(bsl::integer<T1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs < bsl::integer<T2>{rhs};
    }

    /// @brief operator <
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs < rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator<(T1 const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return bsl::integer<T1>{lhs} < rhs;
    }

    /// @brief operator <=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs <= rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator<=(bsl::integer<T1> const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        if constexpr (std::is_signed<T1>::value) {
            if constexpr (std::is_unsigned<T2>::value) {
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
            if constexpr (std::is_unsigned<T2>::value) {
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

    /// @brief operator <=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs <= rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator<=(bsl::integer<T1> const &lhs, T2 const &rhs) noexcept
    {
        return lhs <= bsl::integer<T2>{rhs};
    }

    /// @brief operator <=
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param lhs the left hand side of the operator
    /// @param rhs the right hand side of the operator
    /// @return true if lhs <= rhs, false otherwise
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<
        typename T1,
        typename T2,
        std::enable_if_t<std::is_integral<T1>::value> * = nullptr,
        std::enable_if_t<std::is_integral<T2>::value> * = nullptr>
    [[nodiscard]] constexpr bool
    operator<=(T1 const &lhs, bsl::integer<T2> const &rhs) noexcept
    {
        return bsl::integer<T1>{lhs} <= rhs;
    }
}    // namespace bsl
// -------------------------------------------------------------------------
// supported integer types
// -------------------------------------------------------------------------

namespace bsl
{
    /// @brief provides the bsl::integer version of std::int8_t
    using int8_t = integer<std::int8_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int16_t
    using int16_t = integer<std::int16_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int32_t
    using int32_t = integer<std::int32_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int64_t
    using int64_t = integer<std::int64_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_fast8_t
    using int_fast8_t = integer<std::int_fast8_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_fast16_t
    using int_fast16_t = integer<std::int_fast16_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_fast32_t
    using int_fast32_t = integer<std::int_fast32_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_fast64_t
    using int_fast64_t = integer<std::int_fast64_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_least8_t
    using int_least8_t = integer<std::int_least8_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_least16_t
    using int_least16_t = integer<std::int_least16_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_least32_t
    using int_least32_t = integer<std::int_least32_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::int_least64_t
    using int_least64_t = integer<std::int_least64_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::intmax_t
    using intmax_t = integer<std::intmax_t>;    // PRQA S 2502

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

    /// @brief provides the bsl::integer version of std::uint8_t
    using uint8_t = integer<std::uint8_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint16_t
    using uint16_t = integer<std::uint16_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint32_t
    using uint32_t = integer<std::uint32_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint64_t
    using uint64_t = integer<std::uint64_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_fast8_t
    using uint_fast8_t = integer<std::uint_fast8_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_fast16_t
    using uint_fast16_t = integer<std::uint_fast16_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_fast32_t
    using uint_fast32_t = integer<std::uint_fast32_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_fast64_t
    using uint_fast64_t = integer<std::uint_fast64_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_least8_t
    using uint_least8_t = integer<std::uint_least8_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_least16_t
    using uint_least16_t = integer<std::uint_least16_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_least32_t
    using uint_least32_t = integer<std::uint_least32_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uint_least64_t
    using uint_least64_t = integer<std::uint_least64_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uintmax_t
    using uintmax_t = integer<std::uintmax_t>;    // PRQA S 2502
    /// @brief provides the bsl::integer version of std::uintptr_t
    using uintptr_t = integer<std::uintptr_t>;    // PRQA S 2502

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

#endif
