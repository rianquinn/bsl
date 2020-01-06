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
/// @file debug_resources.hpp
///

#ifndef BSL_DEBUG_RESOURCES_HPP
#define BSL_DEBUG_RESOURCES_HPP

#include "fmt.hpp"
#include "debug_level.hpp"

#include <mutex>

namespace bsl
{
    /// @brief a prototype for the debug_resources class
    class debug_resources;

    /// @brief defines the debug resource type used by these APIs
    using debug_resources_type = debug_resources *;

    namespace details
    {
        /// @brief g_debug_resources
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @return returns a reference to the global debug resource
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename T = void>
        [[nodiscard]] debug_resources_type &
        g_debug_resources() noexcept
        {
            static debug_resources_type s_debug_resources{};
            return s_debug_resources;
        }
    }    // namespace details

    /// @class debug_resources
    ///
    /// This class provides the global resource used by the debug statements.
    /// For the debug statements to work, this class must be created so that
    /// the debug statements have something to output to. If this class is
    /// not created, debug statements will be ignored.
    ///
    class debug_resources final
    {
    public:
        // ---------------------------------------------------------------------
        // Constructors/Destructors/Assignment

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr debug_resources() noexcept
        {
            if (nullptr == details::g_debug_resources()) {
                details::g_debug_resources() = this;
            }
        }

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be copied
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr debug_resources(debug_resources const &o) noexcept = delete;

        /// @brief constructor
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param o the object to be moved
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        constexpr debug_resources(debug_resources &&o) noexcept = delete;

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
        constexpr debug_resources &operator=(debug_resources const &o) &noexcept = delete;

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
        constexpr debug_resources &operator=(debug_resources &&o) &noexcept = delete;

        /// @brief destructor
        ///
        /// Destroys the resource owned by the owner by calling the Deleter
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~debug_resources() noexcept
        {
            details::g_debug_resources() = nullptr;
        }

        // ---------------------------------------------------------------------
        // Formatted Output

        /// @brief print
        ///
        /// This is the internal implementation of the print function that all
        /// of the other debug functions use to output debug statements.
        /// All debug statements are synchronized using a global mutex, and
        /// (other than fatal) all debug statement provide the ability to
        /// filter which debug statements are outputted using a global
        /// debug level. An optional thread ID can be added to the output by
        /// defining BSL_THREAD_ID as "foo();".
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param color an optional color
        /// @param label an optional label describing the debug statement
        /// @param args the fmt arguments to output
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<debug_level_t level = debug_level_t::verbosity_level_0, typename... A>
        static inline void
        print(cstr_type const &color, cstr_type const &label, A &&... args) noexcept
        {
            if constexpr (level <= BSL_DEBUG_LEVEL) {
                if (nullptr == details::g_debug_resources()) {
                    return;
                }

                try {
                    std::lock_guard<std::mutex> const lock{details::g_debug_resources()->m_mutex};

                    if (nullptr != label) {
                        if (nullptr != color) {
                            fmt::print("{}", color);
                        }

                        fmt::print("{}", label);
                        BSL_THREAD_ID
                        fmt::print("{}", reset_color);
                        fmt::print(": ");
                    }

                    fmt::print(std::forward<A>(args)...);
                    fmt::print("{}", reset_color);
                }
                catch (fmt::format_error const &e) {
                    print_exception(label, e.what());
                }
                catch (std::exception const &e) {
                    print_exception(label, e.what());
                }
                catch (...) {
                    print_exception(label, nullptr);
                }
            }
        }

        /// @brief print exception
        ///
        /// This function prints an exception that might come from the
        /// print function to stderr using fputs. Note that error codes from
        /// fputs are ignored so if this function fails to execute, you will
        /// not receive an error message.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param label an optional label describing the debug statement
        /// @param what an optional what from an exception to output
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        static inline void
        print_exception(cstr_type const label, cstr_type const &what) noexcept
        {
            static_cast<void>(fputs(reset_color, stderr));
            static_cast<void>(fputs("\n", stderr));
            static_cast<void>(fputs("exception thrown from bsl::\"", stderr));

            if (nullptr != label) {
                static_cast<void>(fputs(label, stderr));
            }
            else {
                static_cast<void>(fputs("print", stderr));
            }

            if (nullptr != what) {
                static_cast<void>(fputs("\n", stderr));
                static_cast<void>(fputs("  - what: ", stderr));
                static_cast<void>(fputs(what, stderr));
            }

            static_cast<void>(fputs("\n", stderr));
        }

    private:
        /// @brief the mutex used to synchronize debug statements
        mutable std::mutex m_mutex{};
    };
}    // namespace bsl

#endif
