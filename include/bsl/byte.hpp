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
///
/// @file byte.hpp
///

#ifndef BSL_BYTE_HPP
#define BSL_BYTE_HPP

#include "cstdint.hpp"
#include "enable_if.hpp"
#include "is_integral.hpp"
#include "is_unsigned.hpp"
#include "move.hpp"

namespace bsl
{
    /// @enum bsl::byte
    ///
    /// <!-- description -->
    ///   @brief std::byte is a distinct type that implements the concept of
    ///     byte as specified in the C++ language definition. It is not a safe
    ///     integer type, meaning wrapping is possible, and is not checked.
    ///     Unlike a std::byte, the bsl::byte is implemented as a class since
    ///     the relaxed implicit conversions between an integer type and an
    ///     enum are not allowed by AUTOSAR. In addition, the shift operations
    ///     all require unsigned integer types, instead of any integer type.
    ///     A signed integer type, and an integer type of any size can be used
    ///     to create a byte, and is created using a static_cast() to an
    ///     8bit unsigned type, meaning if the integer type is signed, it will
    ///     be converted to an unsigned type, and if the intger type is larger
    ///     than 8 bits, only the first 8 bits wil be used and the remaining
    ///     portion of the integer will be dropped using whatever mechanism the
    ///     compiler sees fit. If a safe integer type is needed, please use
    ///     the safe integer types provided by the BSL instead.
    ///   @include byte/overview.cpp
    ///
    class byte final
    {
        /// @brief stores the byte itself
        bsl::uint8 m_data;

    public:
        /// <!-- description -->
        ///   @brief Default constructor. This ensures the byte type is a
        ///     POD type, allowing it to be constructed as a global resource.
        ///     This is needed as aligned storage uses a bsl::byte as its
        ///     base type, and aligned storage is needed as a global resource
        ///     to support the bsl::manager.
        ///   @include example_byte__overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        byte() noexcept = default;

        /// <!-- description -->
        ///   @brief Creates a bsl::byte from an integer type. The bsl::byte
        ///     is created by statically casting the provided integer to a
        ///     bsl::uint8. As such, if the integer type is signed, it will be
        ///     converted to an unsigned type, and if the integer type is
        ///     larger than a byte, data will be lost in the conversion.
        ///   @include example_byte__overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integer to create the bsl::byte from
        ///   @param t the value of the integer to create the bsl::byte from.
        ///
        template<typename T, enable_if_t<is_integral<T>::value> = true>
        explicit constexpr byte(T const t) noexcept    // --
            : m_data{static_cast<bsl::uint8>(t)}       // PRQA S 2906
        {}

        /// <!-- description -->
        ///   @brief Destroyes a previously created bsl::byte
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        ~byte() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr byte(byte const &o) noexcept = default;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr byte(byte &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr byte &    // --
        operator=(byte const &o) &noexcept = default;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr byte &    // --
        operator=(byte &&o) &noexcept = default;

        /// <!-- description -->
        ///   @brief Returns the bsl::byte as a given integer type using a
        ///     static_cast to perform the conversion.
        ///   @include example_byte__overview.hpp
        ///
        /// <!-- contracts -->
        ///   @pre none
        ///   @post none
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of integer to convert the bsl::byte to
        ///   @return Returns the bsl::byte as a given integer type using a
        ///     static_cast to perform the conversion.
        ///
        template<typename T = bsl::uint32, enable_if_t<is_integral<T>::value> = true>
        [[nodiscard]] constexpr T
        to_integer() const noexcept
        {
            return static_cast<T>(m_data);
        }
    };

    /// <!-- description -->
    ///   @brief The same as b = byte{b.to_integer() << shift}
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SHIFT_T the type used for the shift value
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns a reference to the provided "b"
    ///
    template<typename SHIFT_T, enable_if_t<is_unsigned<SHIFT_T>::value> = true>
    constexpr byte &
    operator<<=(byte &b, SHIFT_T const shift) noexcept
    {
        b = byte{b.to_integer() << shift};
        return b;
    }

    /// <!-- description -->
    ///   @brief The same as b = byte{b.to_integer() >> shift}
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SHIFT_T the type used for the shift value
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns a reference to the provided "b"
    ///
    template<typename SHIFT_T, enable_if_t<is_unsigned<SHIFT_T>::value> = true>
    constexpr byte &
    operator>>=(byte &b, SHIFT_T const shift) noexcept
    {
        b = byte{b.to_integer() >> shift};
        return b;
    }

    /// <!-- description -->
    ///   @brief The same as byte tmp{b}; tmp <<= shift;
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SHIFT_T the type used for the shift value
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns byte tmp{b}; tmp <<= shift;
    ///
    template<typename SHIFT_T, enable_if_t<is_unsigned<SHIFT_T>::value> = true>
    constexpr byte
    operator<<(byte const &b, SHIFT_T const shift) noexcept
    {
        byte tmp{b};
        tmp <<= shift;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as byte tmp{b}; tmp >>= shift;
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SHIFT_T the type used for the shift value
    ///   @param b the bsl::byte to shift
    ///   @param shift the number of bits to shift b
    ///   @return returns byte tmp{b}; tmp >>= shift;
    ///
    template<typename SHIFT_T, enable_if_t<is_unsigned<SHIFT_T>::value> = true>
    constexpr byte
    operator>>(byte const &b, SHIFT_T const shift) noexcept
    {
        byte tmp{b};
        tmp >>= shift;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as lhs = byte{lhs.to_integer() | rhs.to_integer()};
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns a reference to the provided "lhs"
    ///
    constexpr byte &
    operator|=(byte &lhs, byte const &rhs) noexcept
    {
        lhs = byte{lhs.to_integer() | rhs.to_integer()};
        return lhs;
    }

    /// <!-- description -->
    ///   @brief The same as lhs = byte{lhs.to_integer() & rhs.to_integer()};
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns a reference to the provided "lhs"
    ///
    constexpr byte &
    operator&=(byte &lhs, byte const &rhs) noexcept
    {
        lhs = byte{lhs.to_integer() & rhs.to_integer()};
        return lhs;
    }

    /// <!-- description -->
    ///   @brief The same as lhs = byte{lhs.to_integer() ^ rhs.to_integer()};
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns a reference to the provided "lhs"
    ///
    constexpr byte &
    operator^=(byte &lhs, byte const &rhs) noexcept
    {
        lhs = byte{lhs.to_integer() ^ rhs.to_integer()};
        return lhs;
    }

    /// <!-- description -->
    ///   @brief The same as tmp{lhs}; tmp |= rhs;
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns tmp{lhs}; tmp |= rhs;
    ///
    constexpr byte
    operator|(byte const &lhs, byte const &rhs) noexcept
    {
        byte tmp{lhs};
        tmp |= rhs;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as tmp{lhs}; tmp &= rhs;
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns tmp{lhs}; tmp &= rhs;
    ///
    constexpr byte operator&(byte const &lhs, byte const &rhs) noexcept
    {
        byte tmp{lhs};
        tmp &= rhs;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as tmp{lhs}; tmp ^= rhs;
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param lhs the left hand side of the binary operation
    ///   @param rhs the right hand side of the binary operation
    ///   @return returns tmp{lhs}; tmp ^= rhs;
    ///
    constexpr byte
    operator^(byte const &lhs, byte const &rhs) noexcept
    {
        byte tmp{lhs};
        tmp ^= rhs;
        return tmp;
    }

    /// <!-- description -->
    ///   @brief The same as byte{~b.to_integer()}
    ///   @include example_byte__overview.hpp
    ///
    /// <!-- contracts -->
    ///   @pre none
    ///   @post none
    ///
    /// <!-- inputs/outputs -->
    ///   @param b the bsl::byte to invert
    ///   @return returns byte{~b.to_integer()}
    ///
    constexpr byte
    operator~(byte const &b) noexcept
    {
        return byte{~b.to_integer()};
    }
}

#endif
