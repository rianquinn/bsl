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

#include "source_location.hpp"
#include "autosar.hpp"

#include <mutex>

#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/color.h>

// extern "C" auto thread_id() noexcept -> std::uint64_t
// {

// }

namespace bsl
{
    struct fatal_error : bsl::unchecked_error
    {
        fatal_error() : bsl::unchecked_error{"fatal_error"}
        {}
    };

    enum class debug_level_t { all = 0, none = 0, v = 1, vv = 2, vvv = 3 };
    constexpr const auto V = bsl::debug_level_t::v;
    constexpr const auto VV = bsl::debug_level_t::vv;
    constexpr const auto VVV = bsl::debug_level_t::vvv;

    constexpr const auto black = fmt::fg(fmt::terminal_color::bright_black);
    constexpr const auto red = fmt::fg(fmt::terminal_color::bright_red);
    constexpr const auto green = fmt::fg(fmt::terminal_color::bright_green);
    constexpr const auto yellow = fmt::fg(fmt::terminal_color::bright_yellow);
    constexpr const auto blue = fmt::fg(fmt::terminal_color::bright_blue);
    constexpr const auto magenta = fmt::fg(fmt::terminal_color::bright_magenta);
    constexpr const auto cyan = fmt::fg(fmt::terminal_color::bright_cyan);
    constexpr const auto white = fmt::fg(fmt::terminal_color::bright_white);

    using color_t = decltype(black);
}    // namespace bsl

template<>
struct fmt::formatter<bsl::source_location>
{
    static auto
    parse(format_parse_context &ctx)
    {
        return ctx.begin();
    }

    template<typename FormatContext>
    auto
    format(const bsl::source_location &loc, FormatContext &ctx)
    {
        std::string str;

        str += fmt::format(bsl::magenta, "   here");
        str += fmt::format(" --> ");
        str += fmt::format(bsl::yellow, "{}", loc.file_name());
        str += fmt::format(": ");
        str += fmt::format(bsl::cyan, "{}", loc.line());

        return format_to(ctx.out(), "{}", str);
    }
};

namespace bsl
{
    namespace details::debug
    {
#ifndef NDEBUG
        constexpr const bool ndebug = false;
#else
        constexpr const bool ndebug = true;
#endif

#ifndef DEBUG_LEVEL
        constexpr const debug_level_t debug_level = debug_level_t::none;
#else
        constexpr const debug_level_t debug_level = DEBUG_LEVEL;
#endif

#ifndef OUTPUT_TID_WHEN_DEBUGGING
        constexpr const bool show_tid = false;
#else
        constexpr const bool show_tid = true;
#endif

        /// Debug Mutex
        ///
        /// Returns a mutex that is used to synchronize the output of
        /// debug statements.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return mutex used to synchronize the output of debug statements
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        inline auto
        mutex() noexcept -> std::mutex &
        {
            static std::mutex s_mutex{};
            return s_mutex;
        }

        /// Print
        ///
        /// This is the internal implementation of the print function that all
        /// of the other debug functions use to output debug statements.
        /// All debug statements are synchronized using a global mutex, and
        /// (other than fatal) all debug statement provide the ability to
        /// filter which debug statements are outputted using a global
        /// debug level. An optional thread ID can be added to the output, as
        /// well as optional information about which line and file the debug
        /// statement came from (other than print).
        ///
        /// AUTOSAR:
        /// - A15-3-4: the catch all is used for isolation.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param color the color of the optional label to output
        /// @param label an optional label to output for each debug statement
        /// @param args the fmt arguments to output
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<debug_level_t level, typename... ARGS>
        void
        print(
            const color_t &color, const cstr_t label, ARGS &&... args) noexcept

        {
            if constexpr (level <= debug_level) {
                try {
                    std::lock_guard<std::mutex> lock(mutex());

                    if (label != nullptr) {
                        if constexpr (show_tid) {
                            fmt::print(color, label);
                            // fmt::print(yellow, " [{}]", thread_id());
                            fmt::print(": ");
                        }
                        else {
                            fmt::print(color, label);
                            fmt::print(": ");
                        }
                    }

                    fmt::print(std::forward<ARGS>(args)...);
                }
                catch (const fmt::format_error &e) {
                    fputs("unexpected exception in bsl::debug::print", stderr);
                    fputs("  - what: ", stderr);
                    fputs(e.what(), stderr);
                    fputs("\n", stderr);
                }
                catch(...) {
                    fputs("unexpected exception in bsl::debug::print", stderr);
                    fputs("\n", stderr);
                }
            }
        }
    }    // namespace details::debug

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
    template<debug_level_t level = debug_level_t::none, typename... ARGS>
    constexpr auto
    print(ARGS &&... args) noexcept -> void
    {
        if constexpr (!details::debug::ndebug) {
            details::debug::print<level>(
                {}, nullptr, std::forward<ARGS>(args)...);
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
    template<debug_level_t level = debug_level_t::none, typename... ARGS>
    constexpr auto
    debug(ARGS &&... args) noexcept -> void
    {
        if constexpr (!details::debug::ndebug) {
            details::debug::print<level>(
                green, "DEBUG", std::forward<ARGS>(args)...);
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
    template<debug_level_t level = debug_level_t::none, typename... ARGS>
    constexpr auto
    alert(ARGS &&... args) noexcept -> void
    {
        if constexpr (!details::debug::ndebug) {
            details::debug::print<level>(
                yellow, "ALERT", std::forward<ARGS>(args)...);
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
    template<debug_level_t level = debug_level_t::none, typename... ARGS>
    constexpr auto
    error(ARGS &&... args) noexcept -> void
    {
        if constexpr (!details::debug::ndebug) {
            details::debug::print<level>(
                red, "ERROR", std::forward<ARGS>(args)...);
        }
    }

    /// Fatal
    ///
    /// Uses fmt to output a fatal statement. Fatal statements are synchronized
    /// with other debug statements using a global mutex. Fatal statements do
    /// not have a debug level, and how a fatal statement is handled depends
    /// on whether or not AUTOSAR compliance is enabled. When this is enabled,
    /// an exception is thrown, otherwise, std::abort() is called.
    ///
    /// expects: none
    /// ensures: none
    ///
    /// @param args the fmt arguments to output using fmt
    /// @throw [checked]: none
    /// @throw [unchecked]: possible
    ///
    template<typename ERROR = fatal_error, typename... ARGS>
    [[noreturn]] constexpr auto
    fatal(ARGS &&... args) -> void
    {
        details::debug::print<debug_level_t::all>(
            magenta, "\nFATAL", std::forward<ARGS>(args)...);

        bsl::details::autosar::failure<ERROR>();
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
    template<debug_level_t level = debug_level_t::none>
    constexpr auto
    unexpected_exception(const source_location &sloc) noexcept
        -> void
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
    /// @param sloc the location of where the unexpected exception occurred.
    /// @throw [checked]: none
    /// @throw [unchecked]: none
    ///
    template<debug_level_t level = debug_level_t::none>
    constexpr auto
    unexpected_exception(const std::exception &e, const source_location &sloc)
        noexcept -> void
    {
        bsl::error<level>("unexpected exception: {}\n{}\n", e.what(), sloc);
    }
}    // namespace bsl

#endif
