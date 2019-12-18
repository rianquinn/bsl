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

#ifndef BSL_UNIQUE_OWNER_HPP
#define BSL_UNIQUE_OWNER_HPP

#include "int.hpp"
#include <tuple>

/// Owner
///
/// Unlike the gsl::owner, ths bsl::owner is not a decoration, but instead
/// provides the facilities for actually owning a resource. Specifically,
/// if you "own" a resource, you are responsible for releasing or freeing
/// the resource when you lose scope. The gsl::owner goes completely
/// against the C++ Core Guidelines as it encourages the use of an owner
/// whose lifetime is not tied to the lifetime of the owner. The BSL owner
/// address this issue. For a bsl::unique_owner, we use EBO, such that, we
/// are capable of re-creating the gsl use case with no impact on the size of
/// the code or its performance when no lifetime function is needed.
///
/// It should be noted, however, that to make this work, we mimic the
/// std::unique_ptr APIs, which means that the bsl::owner is not a drop in
/// replacement for a gsl::owner as you must execute get() to get access to
/// the resource(s) that it owns.
///
/// It should also be noted that we do not 100% mimic the std::unique_ptr, as
/// it has some functionality that is really never used, and just
/// overcomplicates things. For example, we require that the deleter is
/// default constructable, and we do not provide constructor overloads for
/// providing deleters with non-default construction. This feature is likely
/// never used, evidence by the fact that make_unique doesn't even support it
/// either. We also simplify some of the member functions as a lot of those
/// functions are also overly complicated.
///
/// Another big change (which is why we don't just rename a unique_ptr),
/// is we support multiple resources. One of the biggest issues with
/// std::unique_ptr is that it doesn't store the size of the ptr, which in
/// some ways make the class pointless. For example, all of the array
/// functions are meaningless as they cannot be used under most coding
/// standards are the std::unique_ptr has no idea what the bounds of the
/// array is.
///

namespace bsl
{
    /// No Delete
    ///
    /// Does nothing. As a result, the default bsl::owner should compile
    /// away when used, similar to a gsl::owner.
    ///
    struct nodelete
    {
        /// Functor
        ///
        /// Deletes memory allocated using new T[].
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @param args the resources owned by the bsl::owner
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        template<typename... ARGS>
        constexpr auto
        operator()(const std::tuple<ARGS...> &args) noexcept -> void
        {
            bsl::discard(args);
        }
    };

    /// Owner
    ///
    /// Please see the above "file" level description
    ///
    template<typename Deleter = nodelete, typename... ARGS>
    class unique_owner : public Deleter
    {
    public:

        using index_type = bsl::uintmax_t;

        /// Constructor
        ///
        /// Creates a unique_owner.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        explicit constexpr unique_owner(ARGS &&... args) noexcept :
            m_args{std::forward<ARGS>(args)...}
        {}

        /// Destructor
        ///
        /// Calls the function provided during construction.
        ///
        /// expects: none
        /// ensures: none
        ///
        /// @throw [checked]: none
        /// @throw [unchecked]: none
        ///
        ~unique_owner() noexcept
        {
            Deleter::operator()(m_args);
        }

        constexpr auto
        swap(unique_owner& other) noexcept -> void
        {
            m_args.swap(other.m_args);
        }

        template<index_type::value_type I = 0>
        constexpr auto
        get() const noexcept -> auto
        {
            return std::get<I>(m_args);
        }

        unique_owner(const unique_owner &) = delete;
        auto operator=(const unique_owner &) -> unique_owner & = delete;
        unique_owner(unique_owner &&) noexcept = default;
        auto operator=(unique_owner &&) noexcept -> unique_owner & = default;

    private:

        std::tuple<ARGS...> m_args;
    };
}    // namespace bsl




// template<class T1, class D1, class T2, class D2>
// bool operator==(const unique_ptr<T1, D1>& x, const unique_ptr<T2, D2>& y);
// 	(1) 	(since C++11)
// template<class T1, class D1, class T2, class D2>
// bool operator!=(const unique_ptr<T1, D1>& x, const unique_ptr<T2, D2>& y);
// 	(2) 	(since C++11)




// template <class CharT, class Traits, class Y, class D>

// std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
//                                               const std::unique_ptr<Y, D>& p);

#endif
