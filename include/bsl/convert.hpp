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

#ifndef BSL_CONFIRM_HPP
#define BSL_CONFIRM_HPP

#include "unsign.hpp"
#include "source_location.hpp"

namespace bsl
{
    /// @brief convert
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
    /// @param sloc the location of the call for debugging.
    /// @return f converted "from" type F "to" type T
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<
        typename T,
        typename F,
        std::enable_if_t<std::is_integral<T>::value> * = nullptr,
        std::enable_if_t<std::is_integral<F>::value> * = nullptr>
    [[nodiscard]] constexpr T
    convert(F const &f, sloc_type const &sloc = here())
    {
        using f_limits = std::numeric_limits<F>;
        using t_limits = std::numeric_limits<T>;

        if constexpr (std::is_same<F, T>::value) {
            return f;
        }

        if constexpr (std::is_signed<F>::value) {
            if constexpr (std::is_signed<T>::value) {
                if constexpr (f_limits::max() <= t_limits::max()) {
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(f <= t_limits::max(), sloc);
                    bsl::expects_audit(f >= t_limits::min(), sloc);
                    return static_cast<T>(f);
                }
            }
            else {
                if constexpr (unsign(f_limits::max()) <= t_limits::max()) {
                    bsl::expects_audit(f >= 0, sloc);
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(unsign(f) <= t_limits::max(), sloc);
                    return static_cast<T>(f);
                }
            }
        }
        else {
            if constexpr (std::is_signed<T>::value) {
                if constexpr (f_limits::max() <= unsign(t_limits::max())) {
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(f <= unsign(t_limits::max()), sloc);
                    return static_cast<T>(f);
                }
            }
            else {
                if constexpr (f_limits::max() <= t_limits::max()) {
                    return static_cast<T>(f);
                }
                else {
                    bsl::expects_audit(f <= t_limits::max(), sloc);
                    return static_cast<T>(f);
                }
            }
        }
    }

    /// @brief to_int8
    ///
    /// Converts an integral type T to a std::int8_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int8_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int8_t
    to_int8(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int8_t>(val, sloc);
    }

    /// @brief to_int16
    ///
    /// Converts an integral type T to a std::int16_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int16_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int16_t
    to_int16(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int16_t>(val, sloc);
    }

    /// @brief to_int32
    ///
    /// Converts an integral type T to a std::int32_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int32_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int32_t
    to_int32(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int32_t>(val, sloc);
    }

    /// @brief to_int64
    ///
    /// Converts an integral type T to a std::int64_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int64_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int64_t
    to_int64(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int64_t>(val, sloc);
    }

    /// @brief to_int_fast8
    ///
    /// Converts an integral type T to a std::int_fast8_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_fast8_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_fast8_t
    to_int_fast8(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_fast8_t>(val, sloc);
    }

    /// @brief to_int_fast16
    ///
    /// Converts an integral type T to a std::int_fast16_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_fast16_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_fast16_t
    to_int_fast16(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_fast16_t>(val, sloc);
    }

    /// @brief to_int_fast32
    ///
    /// Converts an integral type T to a std::int_fast32_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_fast32_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_fast32_t
    to_int_fast32(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_fast32_t>(val, sloc);
    }

    /// @brief to_int_fast64
    ///
    /// Converts an integral type T to a std::int_fast64_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_fast64_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_fast64_t
    to_int_fast64(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_fast64_t>(val, sloc);
    }

    /// @brief to_int_least8
    ///
    /// Converts an integral type T to a std::int_least8_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_least8_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_least8_t
    to_int_least8(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_least8_t>(val, sloc);
    }

    /// @brief to_int_least16
    ///
    /// Converts an integral type T to a std::int_least16_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_least16_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_least16_t
    to_int_least16(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_least16_t>(val, sloc);
    }

    /// @brief to_int_least32
    ///
    /// Converts an integral type T to a std::int_least32_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_least32_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_least32_t
    to_int_least32(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_least32_t>(val, sloc);
    }

    /// @brief to_int_least64
    ///
    /// Converts an integral type T to a std::int_least64_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::int_least64_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::int_least64_t
    to_int_least64(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::int_least64_t>(val, sloc);
    }

    /// @brief to_intmax
    ///
    /// Converts an integral type T to a std::intmax_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::intmax_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::intmax_t
    to_intmax(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::intmax_t>(val, sloc);
    }

    /// @brief to_uint8
    ///
    /// Converts an integral type T to a std::uint8_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint8_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint8_t
    to_uint8(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint8_t>(val, sloc);
    }

    /// @brief to_uint16
    ///
    /// Converts an integral type T to a std::uint16_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint16_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint16_t
    to_uint16(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint16_t>(val, sloc);
    }

    /// @brief to_uint32
    ///
    /// Converts an integral type T to a std::uint32_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint32_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint32_t
    to_uint32(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint32_t>(val, sloc);
    }

    /// @brief to_uint64
    ///
    /// Converts an integral type T to a std::uint64_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint64_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint64_t
    to_uint64(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint64_t>(val, sloc);
    }

    /// @brief to_uint_fast8
    ///
    /// Converts an integral type T to a std::uint_fast8_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_fast8_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_fast8_t
    to_uint_fast8(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_fast8_t>(val, sloc);
    }

    /// @brief to_uint_fast16
    ///
    /// Converts an integral type T to a std::uint_fast16_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_fast16_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_fast16_t
    to_uint_fast16(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_fast16_t>(val, sloc);
    }

    /// @brief to_uint_fast32
    ///
    /// Converts an integral type T to a std::uint_fast32_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_fast32_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_fast32_t
    to_uint_fast32(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_fast32_t>(val, sloc);
    }

    /// @brief to_uint_fast64
    ///
    /// Converts an integral type T to a std::uint_fast64_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_fast64_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_fast64_t
    to_uint_fast64(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_fast64_t>(val, sloc);
    }

    /// @brief to_uint_least8
    ///
    /// Converts an integral type T to a std::uint_least8_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_least8_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_least8_t
    to_uint_least8(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_least8_t>(val, sloc);
    }

    /// @brief to_uint_least16
    ///
    /// Converts an integral type T to a std::uint_least16_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_least16_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_least16_t
    to_uint_least16(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_least16_t>(val, sloc);
    }

    /// @brief to_uint_least32
    ///
    /// Converts an integral type T to a std::uint_least32_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_least32_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_least32_t
    to_uint_least32(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_least32_t>(val, sloc);
    }

    /// @brief to_uint_least64
    ///
    /// Converts an integral type T to a std::uint_least64_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uint_least64_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uint_least64_t
    to_uint_least64(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uint_least64_t>(val, sloc);
    }

    /// @brief to_uintmax
    ///
    /// Converts an integral type T to a std::uintmax_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uintmax_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uintmax_t
    to_uintmax(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uintmax_t>(val, sloc);
    }

    /// @brief to_uintptr
    ///
    /// Converts an integral type T to a std::uintptr_t using the convert
    /// function to ensure safety.
    ///
    /// expects: no overruns underruns or wrapping
    /// ensures: none
    ///
    /// @param val the value of type T to be converted
    /// @param sloc the location of the call for debugging.
    /// @return val as a std::uintptr_t
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
    [[nodiscard]] constexpr std::uintptr_t
    to_uintptr(T const &val, sloc_type const &sloc = here())
    {
        return bsl::convert<std::uintptr_t>(val, sloc);
    }
}    // namespace bsl

#endif
