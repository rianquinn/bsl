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

#ifndef BSL_DEBUG_HPP
#define BSL_DEBUG_HPP

#include "debug_resources.hpp"
#include "failure.hpp"

namespace bsl
{
    /// Print
    ///
    /// Prints using fmt::print. The only difference between this function
    /// can fmt::print is the addition of the debug level, which can be used
    /// to control verbosity, and the output is synchronized by a global mutex.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param args the arguments to pass to fmt::print
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::verbosity_level_0, typename... A>
    constexpr void
    print(A &&... args) noexcept
    {
        if constexpr (!BSL_DISABLE_DEBUGGING) {
            debug_resources::print<level>({}, nullptr, std::forward<A>(args)...);
        }
    }

    /// Debug
    ///
    /// Uses fmt to output a debug statement. Debug statements are synchronized
    /// with other debug statements using a global mutex and debug statements
    /// can be filtered using the level template parameter. If the provided
    /// level is <= to the global debug level, and NDEBUG is not defined,
    /// the debug statement is outputted.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param args the fmt arguments to output using fmt
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::verbosity_level_0, typename... A>
    constexpr void
    debug(A &&... args) noexcept
    {
        if constexpr (!BSL_DISABLE_DEBUGGING) {
            debug_resources::print<level>(green, "debug", std::forward<A>(args)...);
        }
    }

    /// Alert
    ///
    /// Uses fmt to output a alert statement. Alert statements are synchronized
    /// with other debug statements using a global mutex and alert statements
    /// can be filtered using the level template parameter. If the provided
    /// level is <= to the global debug level, and NDEBUG is not defined,
    /// the alert statement is outputted.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param args the fmt arguments to output using fmt
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::verbosity_level_0, typename... A>
    constexpr void
    alert(A &&... args) noexcept
    {
        if constexpr (!BSL_DISABLE_DEBUGGING) {
            debug_resources::print<level>(yellow, "alert", std::forward<A>(args)...);
        }
    }

    /// Error
    ///
    /// Uses fmt to output a error statement. Error statements are synchronized
    /// with other debug statements using a global mutex and error statements
    /// can be filtered using the level template parameter. If the provided
    /// level is <= to the global debug level, and NDEBUG is not defined,
    /// the error statement is outputted.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param args the fmt arguments to output using fmt
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::verbosity_level_0, typename... A>
    constexpr void
    error(A &&... args) noexcept
    {
        if constexpr (!BSL_DISABLE_DEBUGGING) {
            debug_resources::print<level>(red, "error", std::forward<A>(args)...);
        }
    }

    /// Fatal
    ///
    /// Uses fmt to output a fatal statement. Fatal statements are synchronized
    /// with other debug statements using a global mutex. Fatal statements do
    /// not have a debug level, and how a fatal statement is handled depends
    /// on whether or not AUTOSAR compliance is enabled. Note that unlike the
    /// other debug statements, you must provide a source location, and this
    /// debug statement will insert a newline for you.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param sloc the location of where the failure occurred
    /// @param args the fmt arguments to output using fmt
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename... A>
    [[noreturn]] constexpr void
    fatal(sloc_type const &sloc, A &&... args)
    {
        debug_resources::print(magenta, "\nfatal", std::forward<A>(args)...);
        debug_resources::print(magenta, "\nfatal", "{}\n", sloc);
        bsl::fail(sloc);
    }

    /// Unexpected Exception (unknown)
    ///
    /// The following can be used to output when an unexpected exception
    /// has been caught.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param sloc the location of where the unexpected exception occurred.
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::verbosity_level_0>
    constexpr void
    unexpected_exception(sloc_type const &sloc = here()) noexcept
    {
        bsl::error<level>("unexpected exception: unknown or ...\n{}\n", sloc);
    }

    /// Unexpected Exception (known)
    ///
    /// The following can be used to output when an unexpected exception
    /// has been caught.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param e the unexpected exception
    /// @param sloc the location of where the unexpected exception occurred.
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::verbosity_level_0>
    constexpr void
    unexpected_exception(std::exception const &e, sloc_type const &sloc = here()) noexcept
    {
        bsl::error<level>("unexpected exception: {}\n{}\n", e.what(), sloc);
    }
}    // namespace bsl

#endif
