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

#ifndef BSL_DYNARRAY_HPP
#define BSL_DYNARRAY_HPP

#include "contracts.hpp"

// --------------------------------------------------------------------------
// Iterators
// --------------------------------------------------------------------------

#include <iterator>

namespace bsl
{
    // Random Access Iterator
    //
    // The following defines a random access iterator. For more
    // information, please see the following:
    // https://en.cppreference.com/w/cpp/named_req/RandomAccessIterator
    //
    // The legacy random access iterator has a lot of requirements. The
    // following are most of them:
    // - default constructable
    //   https://en.cppreference.com/w/cpp/named_req/DefaultConstructible
    // - destructable
    //   https://en.cppreference.com/w/cpp/named_req/Destructible
    // - copy constructable/assignable
    //   https://en.cppreference.com/w/cpp/named_req/CopyConstructible
    //   https://en.cppreference.com/w/cpp/named_req/CopyAssignable
    // - move constructable/assignable
    //   https://en.cppreference.com/w/cpp/named_req/MoveConstructible
    //   https://en.cppreference.com/w/cpp/named_req/MoveAssignable
    // - implements *iter, ++iter and iter++
    //   https://en.cppreference.com/w/cpp/named_req/Iterator
    // - equality operators
    //   https://en.cppreference.com/w/cpp/named_req/EqualityComparable
    // - iter != iter, iter->, (void)i++ == (void)++i, *i++
    //   https://en.cppreference.com/w/cpp/named_req/InputIterator
    // - iter-- and --iter, *iter--
    //   https://en.cppreference.com/w/cpp/named_req/BidirectionalIterator
    // - +, +=, -, -=, iter[n], <, <=, >, >=
    //   https://en.cppreference.com/w/cpp/named_req/RandomAccessIterator
    //
    template<typename Array, typename T>
    class random_access_iterator
    {
    public:
        using value_type = T;
        using difference_type = std::ptrdiff_t;
        using reference = T &;
        using pointer = T *;
        using iterator_category = std::random_access_iterator_tag;

        random_access_iterator() = default;

        random_access_iterator(const Array *a, difference_type i) noexcept :
            m_a{a}, m_i{i}
        {}

        constexpr auto operator*() const -> reference
        {
            bsl::expects(m_a != nullptr);
            bsl::expects(m_i >= 0 && m_i < m_a->ssize());

            return m_a->get()[static_cast<std::size_t>(m_i)];
        }

        constexpr auto operator-> () const -> pointer
        {
            bsl::expects(m_a != nullptr);
            bsl::expects(m_i >= 0 && m_i < m_a->ssize());

            return &m_a->get()[static_cast<std::size_t>(m_i)];
        }

        constexpr auto operator[](std::size_t n) const -> reference
        {
            bsl::expects(m_a != nullptr);
            bsl::expects(n < m_a->size());

            return m_a->get()[n];
        }

        constexpr auto
        operator++() noexcept -> random_access_iterator &
        {
            ++m_i;
            return *this;
        }

        constexpr auto
        operator++(int) noexcept -> random_access_iterator
        {
            auto ret = *this;
            ++(*this);
            return ret;
        }

        constexpr auto
        operator--() noexcept -> random_access_iterator &
        {
            --m_i;
            return *this;
        }

        constexpr auto
        operator--(int) noexcept -> random_access_iterator
        {
            auto ret = *this;
            --(*this);
            return ret;
        }

        constexpr auto
        operator+(difference_type n) const noexcept -> random_access_iterator
        {
            auto ret = *this;
            return ret += n;
        }

        constexpr auto
        operator-(difference_type n) const noexcept -> random_access_iterator
        {
            auto ret = *this;
            return ret -= n;
        }

        constexpr auto
        operator+=(difference_type n) noexcept -> random_access_iterator &
        {
            m_i += n;
            return *this;
        }

        constexpr auto
        operator-=(difference_type n) noexcept -> random_access_iterator &
        {
            m_i -= n;
            return *this;
        }

        constexpr auto
        operator-(const random_access_iterator &rhs) const noexcept
            -> difference_type
        {
            return m_i - rhs.m_i;
        }

        friend constexpr auto
        operator==(
            random_access_iterator lhs, random_access_iterator rhs) noexcept
            -> bool
        {
            return lhs.m_a == rhs.m_a && lhs.m_i == rhs.m_i;
        }

        friend constexpr auto
        operator!=(
            random_access_iterator lhs, random_access_iterator rhs) noexcept
            -> bool
        {
            return !(lhs == rhs);
        }

        friend constexpr auto
        operator<(
            random_access_iterator lhs, random_access_iterator rhs) noexcept
            -> bool
        {
            return lhs.m_i < rhs.m_i;
        }

        friend constexpr auto
        operator<=(
            random_access_iterator lhs, random_access_iterator rhs) noexcept
            -> bool
        {
            return lhs.m_i <= rhs.m_i;
        }

        friend constexpr auto
        operator>(
            random_access_iterator lhs, random_access_iterator rhs) noexcept
            -> bool
        {
            return lhs.m_i > rhs.m_i;
        }

        friend constexpr auto
        operator>=(
            random_access_iterator lhs, random_access_iterator rhs) noexcept
            -> bool
        {
            return lhs.m_i >= rhs.m_i;
        }

    private:
        const Array *m_a{};
        difference_type m_i{};
    };
}    // namespace bsl

/// @endcond

// --------------------------------------------------------------------------
// Dynamic Array
// --------------------------------------------------------------------------

// namespace bsl
// {
//     // ----------------------------------------------------------------------
//     // Deleters
//     // ----------------------------------------------------------------------

//     /// Default Deleter
//     ///
//     /// Deletes memory allocated using new T[]. This is the deleter that the
//     /// bsl::dynarray will use by default.
//     ///
//     template<typename T>
//     struct default_deleter
//     {
//         /// Functor
//         ///
//         /// Deletes memory allocated using new T[].
//         ///
//         /// @param ptr the pointer to pass to delete [].
//         /// @param size ignored
//         /// @return none
//         ///
//         auto
//         operator()(T *ptr, size_t size) -> void
//         {
//             bsl::unused(size);
//             delete[] ptr;
//         }
//     };

//     /// No Delete
//     ///
//     /// Do not delete the memory passed to the deleter. This turns a
//     /// bsl::dynarray into a non-owning container (similar to a gsl::span).
//     ///
//     struct nodelete
//     {
//         /// Functor
//         ///
//         /// Does nothing.
//         ///
//         /// @param ptr ignored
//         /// @param size ignored
//         /// @return none
//         ///
//         auto
//         operator()(const void *ptr, size_t size) -> void
//         {
//             bsl::unused(ptr);
//             bsl::unused(size);
//         }
//     };

//     // ----------------------------------------------------------------------
//     // dynarray
//     // ----------------------------------------------------------------------

//     /// Dynamic Array
//     ///
//     /// The dynamic array is designed to fill a whole in C++ that currently
//     /// exists as C++ currently does not have support for a GSL compliant,
//     /// owning, dynamic array type. std::array provides this support for
//     static
//     /// arrays, but nothing currently exists for dynamic arrays.
//     ///
//     /// THIS DYNAMIC ARRAY IS NOT MEANT TO COMPETE WITH THE FOLLOWING:
//     /// https:///en.cppreference.com/w/cpp/container/dynarray
//     ///
//     /// The Dynamic Array is modeled after std::unique_ptr and std::array,
//     and
//     /// shares the same interface with a couple of differences:
//     /// - there is no need to use the [] syntax as the dynamic array is
//     assumed
//     ///   to be an array, which simplifies the interface a bit as there are
//     no
//     ///   conflicts between [] and non-[]
//     /// - the dynamic array supports some of the APIs from std::array where
//     ///   they make sense. This includes iterator support. In this sense, the
//     ///   APIs are somewhat similar to what was proposed for std::dynarray,
//     but
//     ///   with the exception that this is intended to be a library
//     ///   implementation with no support for the stack-based optimizations
//     that
//     ///   std::dynarray was attempting to pursue. Instead, we decided to
//     model
//     ///   the bsl::dynarray after the std::unique_ptr as it comes really
//     close
//     ///   to a complete implementation (missing iterators, size and Core
//     ///   Guideline Compliance)
//     /// - the dynamic array is designed to be Core Guideline Compliant when
//     ///   enabled, with the same ability to define how contract violations
//     are
//     ///   handled. By default, to achieve this compliance, you must use .at()
//     as
//     ///   this is always bounds checked. If you would like the bsl::dynarray
//     to
//     ///   be fully compliant like a gsl::span, define
//     ///   BSL_CORE_GUIDELINE_COMPLIANT. Like the GSL, you can control
//     ///   whether exceptions are thrown or std::terminate is called. This
//     ///   changes some of the noexcept rules defined by std::unique_ptr. Also
//     ///   note that not all of the functions can throw on contract
//     violations.
//     ///   An example of this are move semantics and any functions that are
//     ///   used by these semantics.
//     ///
//     /// The implementation of this code, and it's documentation was inspired
//     /// by the following:
//     /// https:///en.cppreference.com/w/cpp/memory/unique_ptr
//     /// https:///en.cppreference.com/w/cpp/container/array
//     ///
//     /// TODO
//     /// - operators >, >=, <, and <=
//     /// - support for deleter pointer and reference types
//     ///
//     template<
//         typename T,
//         typename Deleter = default_deleter<T>,
//         BSL_IS_NOT_POINTER(Deleter),
//         BSL_IS_NOT_REFERENCE(Deleter)>
//     class dynarray : public Deleter
//     {
//         BSL_MOVE_ONLY(dynarray)

//     public:
//         /// @cond
//         using value_type = T;
//         using element_type = T;
//         using index_type = std::size_t;
//         using difference_type = std::ptrdiff_t;
//         using reference = T &;
//         using const_reference = const T &;
//         using pointer = T *;
//         using const_pointer = const T *;
//         using deleter_type = Deleter;
//         using const_deleter_type = const Deleter;
//         using iterator = random_access_iterator<dynarray, T>;
//         using const_iterator = random_access_iterator<dynarray, const T>;
//         using reverse_iterator = std::reverse_iterator<iterator>;
//         using const_reverse_iterator = std::reverse_iterator<const_iterator>;
//         /// @endcond

//     public:
//         /// Default Constructor
//         ///
//         /// Constructs a bsl::dynarray that owns nothing. Value-initializes
//         the
//         /// stored pointer, stored count and the stored deleter. Requires
//         that
//         /// Deleter is DefaultConstructible and that construction does not
//         throw
//         /// an exception.
//         ///
//         /// This overload only participate in overload resolution if
//         /// std::is_default_constructible<Deleter>::value is true and Deleter
//         is
//         /// not a pointer or reference type.
//         ///
//         /// @expects
//         /// @ensures empty() == true
//         ///
//         template<BSL_IS_DEFAULT_CONSTRUCTABLE(deleter_type)>
//         constexpr dynarray() noexcept
//         {
//             bsl_ensures_terminate(empty());
//         }

//         /// Pointer / Count Constructor
//         ///
//         /// Constructs a bsl::dynarray which owns p, initializing the stored
//         /// pointer with p, the stored count with count, and
//         value-initializing
//         /// the stored deleter. Requires that Deleter is DefaultConstructible
//         /// and that construction does not throw an exception.
//         ///
//         /// This overload only participates in overload resolution if
//         /// std::is_default_constructible<Deleter>::value is true and Deleter
//         /// is not a pointer or reference type.
//         ///
//         /// If BSL_THROW_ON_CONTRACT_VIOLATION is defined, this function
//         /// can throw on contract violations. Otherwise, this function is
//         marked
//         /// as noexcept.
//         ///
//         /// @expects ptr != nullptr
//         /// @expects count != 0
//         /// @ensures empty() == false
//         ///
//         /// @param ptr a pointer to an array
//         /// @param count the number of elements in the array
//         ///
//         template<BSL_IS_DEFAULT_CONSTRUCTABLE(deleter_type)>
//         explicit dynarray(pointer ptr, index_type count)
//         noexcept(!BSL_THROW_ON_CONTRACT_VIOLATION) :
//             deleter_type(deleter_type()),
//             m_ptr{ptr},
//             m_count{count}
//         {
//             bsl::expects(ptr != nullptr && count != 0);
//             bsl_ensures(!empty());
//         }

//         /// Pointer / Count Constructor (const Deleter &)
//         ///
//         /// Constructs a bsl::dynarray object which owns p, initializing the
//         /// stored pointer with p, the stored count with count and
//         initializing
//         /// d the deleter D as a const l-value reference using
//         /// std::forward<decltype(d)>(d).
//         ///
//         /// This overload only participates in overload resolution if
//         /// Deleter is not a pointer or reference type.
//         ///
//         /// If BSL_THROW_ON_CONTRACT_VIOLATION is defined, this function
//         /// can throw on contract violations. Otherwise, this function is
//         marked
//         /// as noexcept.
//         ///
//         /// @expects ptr != nullptr
//         /// @expects count != 0
//         /// @ensures empty() == false
//         ///
//         /// @param ptr a pointer to an array
//         /// @param count the number of elements in the array
//         /// @param d the deleter to use to destroy the array
//         ///
//         explicit dynarray(pointer ptr, index_type count, const deleter_type
//         &d)
//             noexcept(!BSL_THROW_ON_CONTRACT_VIOLATION) :

//             deleter_type(std::forward<decltype(d)>(d)),
//             m_ptr{ptr},
//             m_count{count}
//         {
//             bsl::expects(ptr != nullptr && count != 0);
//             bsl_ensures(!empty());
//         }

//         /// Pointer / Count Constructor (Deleter &&)
//         ///
//         /// Constructs a bsl::dynarray object which owns p, initializing the
//         /// stored pointer with p, the stored count with count and
//         initializing
//         /// d the deleter D as an r-value reference using
//         /// std::forward<decltype(d)>(d).
//         ///
//         /// This overload only participates in overload resolution if
//         /// Deleter is not a pointer or reference type.
//         ///
//         /// If BSL_THROW_ON_CONTRACT_VIOLATION is defined, this function
//         /// can throw on contract violations. Otherwise, this function is
//         marked
//         /// as noexcept.
//         ///
//         /// @expects ptr != nullptr
//         /// @expects count != 0
//         /// @ensures empty() == false
//         ///
//         /// @param ptr a pointer to an array
//         /// @param count the number of elements in the array
//         /// @param d the deleter to use to destroy the array
//         ///
//         explicit dynarray(pointer ptr, index_type count, deleter_type &&d)
//             noexcept(!BSL_THROW_ON_CONTRACT_VIOLATION) :

//             deleter_type(std::forward<decltype(d)>(d)),
//             m_ptr{ptr},
//             m_count{count}
//         {
//             bsl::expects(ptr != nullptr && count != 0);
//             bsl_ensures(!empty());
//         }

//         /// Move Constructor
//         ///
//         /// Constructs a bsl::dynarray by transferring ownership from u to
//         *this
//         /// and stores the null pointer and 0 count in u. This constructor
//         only
//         /// participates in overload resolution if
//         /// std::is_move_nothrow_constructible<Deleter>::value is true.
//         ///
//         /// This function always calls std::terminate on contract violations.
//         ///
//         /// @expects
//         /// @ensures u.empty()
//         ///
//         /// @param u another dynarray to acquire the array from
//         ///
//         template<BSL_IS_NOTHROW_MOVE_CONSTRUCTABLE(deleter_type)>
//         explicit dynarray(dynarray &&u) noexcept : deleter_type(std::move(u))
//         {
//             m_ptr = std::exchange(u.m_ptr, m_ptr);
//             m_count = std::exchange(u.m_count, m_count);

//             bsl_ensures_terminate(u.empty());
//         }

//         /// Destructor
//         ///
//         /// If get() == nullptr there are no effects. Otherwise, the array
//         /// is destroyed via get_deleter()(get(), size()). Requires that
//         /// get_deleter()(get(), size()) does not throw exceptions.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         ~dynarray()
//         {
//             if (get() != nullptr) {
//                 get_deleter()(get(), size());
//             }
//         }

//         /// Move Operator
//         ///
//         /// Transfers ownership from r to *this as if by calling
//         /// reset(r.release()) followed by an assignment of get_deleter()
//         from
//         /// std::move(r.get_deleter()). This requires that the deleter is
//         /// nothrow-MoveAssignable. If r == *this, the function has no
//         effect.
//         ///
//         /// This function always calls std::terminate on contract violations.
//         ///
//         /// @expects
//         /// @ensures u.empty()
//         ///
//         /// @param r another dynarray to acquire the array from
//         /// @return *this
//         ///
//         template<BSL_IS_NOTHROW_MOVE_ASSIGNABLE(deleter_type)>
//         auto
//         operator=(dynarray &&r) noexcept -> dynarray &
//         {
//             if (&r == this) {
//                 return *this;
//             }

//             reset(r.release());
//             get_deleter() = std::move(r.get_deleter());

//             bsl_ensures_terminate(r.empty());
//             return *this;
//         }

//         /// Release
//         ///
//         /// Releases the ownership of the array if any. get() returns
//         /// nullptr and size() returns 0 after the call
//         ///
//         /// This function always calls std::terminate on contract violations.
//         ///
//         /// @expects
//         /// @ensures get() == nullptr
//         /// @ensures size() == 0
//         ///
//         /// @return a std::pair containing a pointer to the array and
//         ///     the number of elements in the array or nullptr and 0
//         ///     if empty(), i.e. the value which would be
//         ///     returned by get() and size() before the call.
//         ///
//         [[nodiscard]] constexpr auto
//         release() noexcept -> std::pair<pointer, index_type>
//         {
//             auto old_ptr = get();
//             auto old_count = size();

//             m_ptr = pointer();
//             m_count = index_type();

//             bsl_ensures_terminate(get() == pointer());
//             bsl_ensures_terminate(size() == index_type());

//             bsl_ensures_if_terminate(old_ptr != nullptr, old_count >= 1);
//             bsl_ensures_if_terminate(old_ptr == nullptr, old_count == 0);

//             return {old_ptr, old_count};
//         }

//         /// Reset (pointer, count)
//         ///
//         /// Given current_ptr, the pointer to the array, and current_size,
//         the
//         /// number of elements in the array, performs the following actions,
//         /// in this order:
//         /// - Saves a copy of the current pointer old_ptr = m_ptr, and a copy
//         ///   of the current number of elements old_count = m_count.
//         /// - Overwrites the current pointer with the argument m_ptr = ptr
//         ///   and the current number of elements with the argument
//         ///   m_count = count.
//         /// - If the old pointer was non-empty, deletes the previous array
//         with
//         ///   if(old_ptr) get_deleter()(old_ptr, old_count).
//         ///
//         /// This function always calls std::terminate on contract violations.
//         ///
//         /// @expects ptr != nullptr || count == 0
//         /// @expects ptr == nullptr || count >= 1
//         /// @ensures if ptr == nullptr, empty()
//         /// @ensures if ptr != nullptr, !empty()
//         ///
//         /// @param ptr pointer to a new array
//         /// @param count the number of elements in the new array
//         /// @return none
//         ///
//         constexpr auto
//         reset(pointer ptr = pointer(), index_type count = index_type())
//         noexcept
//             -> void
//         {
//             bsl::expects_if_terminate(ptr != nullptr, count >= 1);
//             bsl::expects_if_terminate(ptr == nullptr, count == 0);

//             auto old_ptr = m_ptr;
//             auto old_count = m_count;

//             m_ptr = ptr;
//             m_count = count;

//             if (old_ptr) {
//                 get_deleter()(old_ptr, old_count);
//             }

//             bsl_ensures_if_terminate(ptr == nullptr, empty());
//             bsl_ensures_if_terminate(ptr != nullptr, !empty());
//         }

//         /// Reset (std::pair)
//         ///
//         /// Equivalent to reset(info.first, info.second)
//         ///
//         /// @param info a std::pair containing a pointer to an array for the
//         ///     bsl::dynarray to manage as well as the number of elements in
//         ///     the array
//         /// @return none
//         ///
//         constexpr auto
//         reset(const std::pair<pointer, index_type> &info) noexcept -> void
//         {
//             reset(info.first, info.second);
//         }

//         /// Swap
//         ///
//         /// Swaps the array, the number of elements in the array, and the
//         /// associated deleters of *this to another dynarray other.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @param other another dynarray to swap the array, the number of
//         ///     elements in the array, and the associated deleters with
//         /// @return none
//         ///
//         constexpr auto
//         swap(dynarray &other) noexcept -> void
//         {
//             dynarray tmp(std::move(*this));
//             *this = std::move(other);
//             other = std::move(tmp);
//         }

//         /// Get
//         ///
//         /// Returns a pointer to the array or nullptr if no array is
//         /// owned.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Pointer to the array or nullptr if no array is owned.
//         ///
//         [[nodiscard]] constexpr auto
//         get() const -> pointer
//         {
//             return m_ptr;
//         }

//         /// Get Deleter
//         ///
//         /// Returns the deleter object which would be used for destruction of
//         /// the array.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return The stored deleter object.
//         ///
//         [[nodiscard]] constexpr auto
//         get_deleter() noexcept -> deleter_type &
//         {
//             return *this;
//         }

//         /// Get Deleter (const)
//         ///
//         /// Returns the deleter object which would be used for destruction of
//         /// the array.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return The stored deleter object.
//         ///
//         [[nodiscard]] constexpr auto
//         get_deleter() const noexcept -> const_deleter_type &
//         {
//             return *this;
//         }

//         /// Valid
//         ///
//         /// Checks whether *this owns an array, i.e. whether get() != nullptr
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return true if *this owns an array, false otherwise.
//         ///
//         explicit operator bool() const noexcept
//         {
//             bsl_ensures_if_terminate(get() != nullptr, size() >= 1);
//             bsl_ensures_if_terminate(get() == nullptr, size() == 0);

//             return get() != nullptr;
//         }

//         /// Subscript Operator
//         ///
//         /// operator[] provides access to the elements in the array.
//         /// The parameter i shall be less than the number of elements in the
//         /// array; otherwise, the behavior is undefined by default, or
//         /// throws an exception when BSL_CORE_GUIDELINE_COMPLIANT is
//         /// defined.
//         ///
//         /// @expects i < size()
//         /// @ensures
//         ///
//         /// @param i the index of the element to be returned
//         /// @return Returns the element at index i, i.e. get()[i].
//         ///
//         [[nodiscard]] constexpr auto operator[](index_type i) -> reference
//         {
//             bsl::expects(i < size());
//             return get()[i];
//         }

//         /// Subscript Operator (const)
//         ///
//         /// operator[] provides access to the elements in the array.
//         /// The parameter i shall be less than the number of elements in the
//         /// array; otherwise, the behavior is undefined by default, or
//         /// throws an exception when BSL_CORE_GUIDELINE_COMPLIANT is
//         /// defined.
//         ///
//         /// @expects i < size()
//         /// @ensures
//         ///
//         /// @param i the index of the element to be returned
//         /// @return Returns the element at index i, i.e. get()[i].
//         ///
//         [[nodiscard]] constexpr auto operator[](index_type i) const
//             -> const_reference
//         {
//             bsl::expects(i < size());
//             return get()[i];
//         }

//         /// At
//         ///
//         /// Returns a reference to the element at specified location pos,
//         /// with bounds checking. If pos is not within the range of the
//         /// array, an exception of type std::out_of_range is thrown.
//         ///
//         /// @expects pos < size()
//         /// @ensures
//         ///
//         /// @param pos position of the element to return
//         /// @return reference to the requested element.
//         ///
//         [[nodiscard]] constexpr auto
//         at(index_type pos) -> reference
//         {
//             if (pos >= size()) {
//                 throw std::out_of_range("dynarray: pos >= size()");
//             }

//             return get()[pos];
//         }

//         /// At (const)
//         ///
//         /// Returns a reference to the element at specified location pos,
//         /// with bounds checking. If pos is not within the range of the
//         /// array, an exception of type std::out_of_range is thrown.
//         ///
//         /// @expects pos < size()
//         /// @ensures
//         ///
//         /// @param pos position of the element to return
//         /// @return reference to the requested element.
//         ///
//         [[nodiscard]] constexpr auto
//         at(index_type pos) const -> const_reference
//         {
//             if (pos >= size()) {
//                 throw std::out_of_range("dynarray: pos >= size()");
//             }

//             return get()[pos];
//         }

//         /// Front
//         ///
//         /// Returns a reference to the first element in the array. Calling
//         /// front on an empty array is undefined unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects !empty()
//         /// @ensures
//         ///
//         /// @return reference to the first element (i.e., get()[0])
//         ///
//         [[nodiscard]] constexpr auto
//         front() -> reference
//         {
//             bsl::expects(!empty());
//             return get()[0];
//         }

//         /// Front (const)
//         ///
//         /// Returns a reference to the first element in the array. Calling
//         /// front on an empty array is undefined unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects !empty()
//         /// @ensures
//         ///
//         /// @return reference to the first element (i.e., get()[0])
//         ///
//         [[nodiscard]] constexpr auto
//         front() const -> const_reference
//         {
//             bsl::expects(!empty());
//             return get()[0];
//         }

//         /// Back
//         ///
//         /// Returns a reference to the last element in the array. Calling
//         /// back on an empty array is undefined unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects !empty()
//         /// @ensures
//         ///
//         /// @return reference to the last element (i.e., get()[size() - 1])
//         ///
//         [[nodiscard]] constexpr auto
//         back() -> reference
//         {
//             bsl::expects(!empty());
//             return get()[size() - 1];
//         }

//         /// Back (const)
//         ///
//         /// Returns a reference to the last element in the array. Calling
//         /// back on an empty array is undefined unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects !empty()
//         /// @ensures
//         ///
//         /// @return reference to the last element (i.e., get()[size() - 1])
//         ///
//         [[nodiscard]] constexpr auto
//         back() const -> const_reference
//         {
//             bsl::expects(!empty());
//             return get()[size() - 1];
//         }

//         /// Data
//         ///
//         /// Returns a pointer to the underlying array serving as element
//         /// storage. The pointer is such that range [data(); data() + size())
//         is
//         /// always a valid range, even if the array is empty (data() is not
//         /// dereferenceable in that case).
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Pointer to the underlying element storage. For non-empty
//         ///     arrays, the returned pointer compares equal to the address
//         ///     of the first element.
//         ///
//         [[nodiscard]] constexpr auto
//         data() noexcept -> pointer
//         {
//             return m_ptr;
//         }

//         /// Data (const)
//         ///
//         /// Returns a pointer to the underlying array serving as element
//         /// storage. The pointer is such that range [data(); data() + size())
//         is
//         /// always a valid range, even if the array is empty (data() is not
//         /// dereferenceable in that case).
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Pointer to the underlying element storage. For non-empty
//         ///     arrays, the returned pointer compares equal to the address
//         ///     of the first element.
//         ///
//         [[nodiscard]] constexpr auto
//         data() const noexcept -> const_pointer
//         {
//             return m_ptr;
//         }

//         /// Begin
//         ///
//         /// Returns an iterator to the first element of the array. If the
//         /// array is empty, the returned iterator will be equal to end().
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Iterator to the first element
//         ///
//         [[nodiscard]] constexpr auto
//         begin() noexcept -> iterator
//         {
//             return {this, 0};
//         }

//         /// Begin
//         ///
//         /// Returns an iterator to the first element of the array. If the
//         /// array is empty, the returned iterator will be equal to end().
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Iterator to the first element
//         ///
//         [[nodiscard]] constexpr auto
//         begin() const noexcept -> const_iterator
//         {
//             return {this, 0};
//         }

//         /// Begin
//         ///
//         /// Returns an iterator to the first element of the array. If the
//         /// array is empty, the returned iterator will be equal to end().
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Iterator to the first element
//         ///
//         [[nodiscard]] constexpr auto
//         cbegin() const noexcept -> const_iterator
//         {
//             return {this, 0};
//         }

//         /// End
//         ///
//         /// Returns an iterator to the element following the last element of
//         /// the array. This element acts as a placeholder; attempting to
//         /// access it results in undefined behavior unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Iterator to the element following the last element.
//         ///
//         [[nodiscard]] constexpr auto
//         end() noexcept -> iterator
//         {
//             return {this, ssize()};
//         }

//         /// End
//         ///
//         /// Returns an iterator to the element following the last element of
//         /// the array. This element acts as a placeholder; attempting to
//         /// access it results in undefined behavior unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Iterator to the element following the last element.
//         ///
//         [[nodiscard]] constexpr auto
//         end() const noexcept -> const_iterator
//         {
//             return {this, ssize()};
//         }

//         /// End
//         ///
//         /// Returns an iterator to the element following the last element of
//         /// the array. This element acts as a placeholder; attempting to
//         /// access it results in undefined behavior unless
//         /// BSL_CORE_GUIDELINE_COMPLIANT is defined in which case an
//         /// exception is thrown.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Iterator to the element following the last element.
//         ///
//         [[nodiscard]] constexpr auto
//         cend() const noexcept -> const_iterator
//         {
//             return {this, ssize()};
//         }

//         /// Reverse Begin
//         ///
//         /// Returns a reverse iterator to the first element of the reversed
//         /// array. It corresponds to the last element of the non-reversed
//         array.
//         /// If the array is empty, the returned iterator is equal to rend().
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Reverse iterator to the first element.
//         ///
//         [[nodiscard]] constexpr auto
//         rbegin() noexcept -> reverse_iterator
//         {
//             return std::make_reverse_iterator(end());
//         }

//         /// Reverse Begin
//         ///
//         /// Returns a reverse iterator to the first element of the reversed
//         /// array. It corresponds to the last element of the non-reversed
//         array.
//         /// If the array is empty, the returned iterator is equal to rend().
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Reverse iterator to the first element.
//         ///
//         [[nodiscard]] constexpr auto
//         rbegin() const noexcept -> const_reverse_iterator
//         {
//             return std::make_reverse_iterator(end());
//         }

//         /// Reverse Begin
//         ///
//         /// Returns a reverse iterator to the first element of the reversed
//         /// array. It corresponds to the last element of the non-reversed
//         array.
//         /// If the array is empty, the returned iterator is equal to rend().
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Reverse iterator to the first element.
//         ///
//         [[nodiscard]] constexpr auto
//         crbegin() const noexcept -> const_reverse_iterator
//         {
//             return std::make_reverse_iterator(cend());
//         }

//         /// Reverse End
//         ///
//         /// Returns a reverse iterator to the element following the last
//         element
//         /// of the reversed container. It corresponds to the element
//         preceding
//         /// the first element of the non-reversed container. This element
//         acts
//         /// as a placeholder, attempting to access it results in undefined
//         /// behavior. unless BSL_CORE_GUIDELINE_COMPLIANT is defined in
//         /// which case an exception is thrown.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Reverse iterator to the element following the last
//         element.
//         ///
//         [[nodiscard]] constexpr auto
//         rend() noexcept -> reverse_iterator
//         {
//             return std::make_reverse_iterator(begin());
//         }

//         /// Reverse End
//         ///
//         /// Returns a reverse iterator to the element following the last
//         element
//         /// of the reversed container. It corresponds to the element
//         preceding
//         /// the first element of the non-reversed container. This element
//         acts
//         /// as a placeholder, attempting to access it results in undefined
//         /// behavior. unless BSL_CORE_GUIDELINE_COMPLIANT is defined in
//         /// which case an exception is thrown.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Reverse iterator to the element following the last
//         element.
//         ///
//         [[nodiscard]] constexpr auto
//         rend() const noexcept -> const_reverse_iterator
//         {
//             return std::make_reverse_iterator(begin());
//         }

//         /// Reverse End
//         ///
//         /// Returns a reverse iterator to the element following the last
//         element
//         /// of the reversed container. It corresponds to the element
//         preceding
//         /// the first element of the non-reversed container. This element
//         acts
//         /// as a placeholder, attempting to access it results in undefined
//         /// behavior. unless BSL_CORE_GUIDELINE_COMPLIANT is defined in
//         /// which case an exception is thrown.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Reverse iterator to the element following the last
//         element.
//         ///
//         [[nodiscard]] constexpr auto
//         crend() const noexcept -> const_reverse_iterator
//         {
//             return std::make_reverse_iterator(cbegin());
//         }

//         /// Empty
//         ///
//         /// Checks if the array has no elements, i.e. whether size() == 0;
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return true if the array is empty, false otherwise
//         ///
//         [[nodiscard]] constexpr auto
//         empty() const noexcept -> bool
//         {
//             bsl_ensures_if_terminate(get() != nullptr, size() >= 1);
//             bsl_ensures_if_terminate(get() == nullptr, size() == 0);

//             return size() == 0;
//         }

//         /// Size
//         ///
//         /// Returns the number of elements in the array
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return The number of elements in the array
//         ///
//         [[nodiscard]] constexpr auto
//         size() const noexcept -> index_type
//         {
//             return m_count;
//         }

//         /// Signed Size
//         ///
//         /// Returns the number of elements in the array
//         ///
//         /// Notes:
//         /// - This is a likely a controversial addition. The total size of
//         ///   dynarray is maxed out on the difference_type as this class
//         ///   uses iterators. The problem is, when you are working with
//         ///   size information, you might need access to a signed version.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return The number of elements in the array
//         ///
//         [[nodiscard]] constexpr auto
//         ssize() const noexcept -> difference_type
//         {
//             return static_cast<difference_type>(m_count);
//         }

//         /// Size in Bytes
//         ///
//         /// Returns the size of the array in bytes.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return The size of the array in bytes, i.e.,
//         ///     size() * sizeof(element_type)
//         ///
//         [[nodiscard]] constexpr auto
//         size_bytes() const noexcept -> index_type
//         {
//             return size() * sizeof(T);
//         }

//         /// Max Size
//         ///
//         /// Returns the maximum number of elements the array is able to
//         /// hold due to system or library implementation limitations, i.e.
//         /// size() for the largest array.
//         ///
//         /// Notes:
//         /// - Since this class uses iterators, the max size must be based
//         ///   on the difference_type as iterators only work with signed
//         types.
//         /// - This is asking for the maximum number of elements, so we must
//         ///   divide my the size of T.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @return Maximum number of elements.
//         ///
//         [[nodiscard]] constexpr auto
//         max_size() const noexcept -> index_type
//         {
//             return std::numeric_limits<difference_type>::max() / sizeof(T);
//         }

//         /// Fill (const T &)
//         ///
//         /// Assigns the given value value to all elements in the array.
//         ///
//         /// @expects
//         /// @ensures
//         ///
//         /// @param value the value to assign to the elements
//         /// @return none
//         ///
//         constexpr auto
//         fill(const T &value) -> void
//         {
//             for (index_type i = 0; i < size(); ++i) {
//                 get()[i] = value;
//             }
//         }

//     private:
//         pointer m_ptr{};
//         index_type m_count{};
//     };

//     // ----------------------------------------------------------------------

//     /// Make Dynarray
//     ///
//     /// Constructs an array of T with size count. The function is equivalent
//     to:
//     /// dynarray<T>(new T[count](), count).
//     ///
//     /// If BSL_THROW_ON_CONTRACT_VIOLATION is defined, this function
//     /// can throw on contract violations.
//     ///
//     /// @expects count > 0
//     /// @ensures
//     ///
//     /// @param count the size of the array to construct
//     /// @return a dynarray containing a newly allocated array with count
//     ///     number of elements value-initialized.
//     ///
//     template<typename T>
//     constexpr auto
//     make_dynarray(size_t count) -> dynarray<T>
//     {
//         bsl::expects(count > 0);
//         return dynarray<T>(new T[count](), count);
//     }

//     /// Make Dynarray
//     ///
//     /// Constructs an array of T with size count. The function is equivalent
//     to:
//     /// dynarray<T>(new T[count], count).
//     ///
//     /// If BSL_THROW_ON_CONTRACT_VIOLATION is defined, this function
//     /// can throw on contract violations.
//     ///
//     /// @expects count > 0
//     /// @ensures
//     ///
//     /// @param count the size of the array to construct
//     /// @return a dynarray containing a newly allocated array with count
//     ///     number of elements default-initialized.
//     ///
//     template<typename T>
//     constexpr auto
//     make_dynarray_default_init(size_t count) -> dynarray<T>
//     {
//         bsl::expects(count > 0);
//         return dynarray<T>(new T[count], count);
//     }
// }    // namespace bsl

// --------------------------------------------------------------------------
// Operator Overloads
// --------------------------------------------------------------------------

// /// Equality Operator (==)
// ///
// /// Checks if the contents of lhs and rhs are equal, that is, whether each
// /// element in lhs compares equal with the element in rhs at the same
// position.
// ///
// /// @expects
// /// @ensures
// ///
// /// @param lhs container whose contents to compare
// /// @param rhs container whose contents to compare
// ///
// /// @return true if the contents of the containers are equal, false otherwise
// ///
// template<typename T1, typename D1, typename T2, typename D2>
// constexpr auto
// operator==(const bsl::dynarray<T1, D1> &lhs, const bsl::dynarray<T2, D2>
// &rhs)
//     -> bool
// {
//     if (lhs.size() != rhs.size()) {
//         return false;
//     }

//     for (size_t i = 0; i < lhs.size(); --i) {
//         if (lhs.get()[i] != rhs.get()[i]) {
//             return false;
//         }
//     }

//     return true;
// }

// /// Equality Operator (!=)
// ///
// /// Checks if the contents of lhs and rhs are equal, that is, whether each
// /// element in lhs compares equal with the element in rhs at the same
// position.
// ///
// /// @expects
// /// @ensures
// ///
// /// @param lhs container whose contents to compare
// /// @param rhs container whose contents to compare
// ///
// /// @return true if the contents of the containers are not equal, false
// /// otherwise
// ///
// template<typename T1, typename D1, typename T2, typename D2>
// constexpr auto
// operator!=(const bsl::dynarray<T1, D1> &lhs, const bsl::dynarray<T2, D2>
// &rhs)
//     -> bool
// {
//     return !operator==(lhs, rhs);
// }

// /// Output Stream
// ///
// /// Inserts the value of the array's pointer into the output stream os.
// /// Equivalent to os << static_cast<const void *>(da.get())
// ///
// /// @expects
// /// @ensures
// ///
// /// @param os a std::basic_ostream to insert the pointer into
// /// @param da the array to insert into the stream
// ///
// template<typename Ch, typename Tr, typename T, typename D>
// auto
// operator<<(std::basic_ostream<Ch, Tr> &os, const bsl::dynarray<T, D> &da)
//     -> std::basic_ostream<Ch, Tr> &
// {
//     return os << static_cast<const void *>(da.get());
// }

#endif
