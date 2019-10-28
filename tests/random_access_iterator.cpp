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

#define BAREFLANK_THROW_ON_CONTRACT_VIOLATION
#define BAREFLANK_CORE_GUIDELINE_COMPLIANT
#include "../include/bsl.h"

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

TEST_CASE("iterator concept checks")
{
    using it_t = bsl::dynarray<int>::iterator;

    static_assert(std::is_default_constructible_v<it_t>);
    static_assert(std::is_destructible_v<it_t>);
    static_assert(std::is_copy_constructible_v<it_t>);
    static_assert(std::is_copy_assignable_v<it_t>);
    static_assert(std::is_move_constructible_v<it_t>);
    static_assert(std::is_move_assignable_v<it_t>);
    static_assert(std::is_swappable_v<it_t>);
}

TEST_CASE("constructors")
{
    {
        bsl::dynarray<int>::iterator it;
        CHECK_THROWS(*it);
    }

    {
        auto da = bsl::make_dynarray<int>(1);
        auto it = da.begin();
        CHECK_NOTHROW(*it);
    }
}

TEST_CASE("operator*")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS((*it1).m_data = 42);
            CHECK_THROWS((*it1).m_data == 42);

            CHECK_NOTHROW((*it2).m_data = 42);
            CHECK_NOTHROW((*it2).m_data == 42);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS((*it1).m_data == 42);
            CHECK_NOTHROW((*it2).m_data == 42);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator->")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS(it1->m_data = 42);
            CHECK_THROWS(it1->m_data == 42);

            CHECK_NOTHROW(it2->m_data = 42);
            CHECK_NOTHROW(it2->m_data == 42);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS(it1->m_data == 42);
            CHECK_NOTHROW(it2->m_data == 42);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator[]")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS(it1[0].m_data = 42);
            CHECK_THROWS(it1[0].m_data == 42);

            CHECK_NOTHROW(it2[0].m_data = 42);
            CHECK_NOTHROW(it2[0].m_data == 42);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS(it1[0].m_data == 42);
            CHECK_NOTHROW(it2[0].m_data == 42);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator++")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() :
            da1{bsl::make_dynarray<Foo>(1)},
            da2{bsl::make_dynarray<Foo>(2)}
        {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            ++it1;
            ++it2;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            ++it1;
            ++it2;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[2].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[2].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            ++it1;
            ++it2;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            ++it1;
            ++it2;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[2].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[2].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator++(int)")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() :
            da1{bsl::make_dynarray<Foo>(1)},
            da2{bsl::make_dynarray<Foo>(2)}
        {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            it1++;
            it2++;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            it1++;
            it2++;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[2].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[2].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            it1++;
            it2++;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            it1++;
            it2++;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[2].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[2].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator--")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() :
            da1{bsl::make_dynarray<Foo>(1)},
            da2{bsl::make_dynarray<Foo>(2)}
        {}

        auto
        test1() -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            --it1;
            --it2;

            CHECK_NOTHROW((*it1).m_data);
            CHECK_NOTHROW(it1->m_data);
            CHECK_NOTHROW(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            --it1;
            --it2;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[-1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            --it1;
            --it2;

            CHECK_NOTHROW((*it1).m_data);
            CHECK_NOTHROW(it1->m_data);
            CHECK_NOTHROW(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            --it1;
            --it2;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[-1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator--(int)")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() :
            da1{bsl::make_dynarray<Foo>(1)},
            da2{bsl::make_dynarray<Foo>(2)}
        {}

        auto
        test1() -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            it1--;
            it2--;

            CHECK_NOTHROW((*it1).m_data);
            CHECK_NOTHROW(it1->m_data);
            CHECK_NOTHROW(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            it1--;
            it2--;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[-1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            it1--;
            it2--;

            CHECK_NOTHROW((*it1).m_data);
            CHECK_NOTHROW(it1->m_data);
            CHECK_NOTHROW(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[1].m_data);

            it1--;
            it2--;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[-1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator+ n")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            auto it3 = it1 + 1;
            auto it4 = it2 + 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);

            CHECK_THROWS((*it3).m_data);
            CHECK_THROWS(it3->m_data);
            CHECK_THROWS(it3[1].m_data);

            CHECK_THROWS((*it4).m_data);
            CHECK_THROWS(it4->m_data);
            CHECK_THROWS(it4[1].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            auto it3 = it1 + 1;
            auto it4 = it2 + 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);

            CHECK_THROWS((*it3).m_data);
            CHECK_THROWS(it3->m_data);
            CHECK_THROWS(it3[1].m_data);

            CHECK_THROWS((*it4).m_data);
            CHECK_THROWS(it4->m_data);
            CHECK_THROWS(it4[1].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator- n")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            auto it3 = it1 - 1;
            auto it4 = it2 - 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[1].m_data);

            CHECK_THROWS((*it3).m_data);
            CHECK_THROWS(it3->m_data);
            CHECK_THROWS(it3[-1].m_data);

            CHECK_NOTHROW((*it4).m_data);
            CHECK_NOTHROW(it4->m_data);
            CHECK_NOTHROW(it4[0].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            auto it3 = it1 - 1;
            auto it4 = it2 - 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[1].m_data);

            CHECK_THROWS((*it3).m_data);
            CHECK_THROWS(it3->m_data);
            CHECK_THROWS(it3[-1].m_data);

            CHECK_NOTHROW((*it4).m_data);
            CHECK_NOTHROW(it4->m_data);
            CHECK_NOTHROW(it4[0].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator+= n")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);

            it1 += 1;
            it2 += 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[1].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[1].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.begin();
            auto it2 = da2.begin();

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);

            it1 += 1;
            it2 += 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[1].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[1].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator-= n")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[1].m_data);

            it1 -= 1;
            it2 -= 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[-1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[0].m_data);

            CHECK_THROWS((*it2).m_data);
            CHECK_THROWS(it2->m_data);
            CHECK_THROWS(it2[1].m_data);

            it1 -= 1;
            it2 -= 1;

            CHECK_THROWS((*it1).m_data);
            CHECK_THROWS(it1->m_data);
            CHECK_THROWS(it1[-1].m_data);

            CHECK_NOTHROW((*it2).m_data);
            CHECK_NOTHROW(it2->m_data);
            CHECK_NOTHROW(it2[0].m_data);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("operator- rhs")
{
    struct Foo
    {
        int m_data;
    };

    class test
    {
        bsl::dynarray<Foo> da1;
        bsl::dynarray<Foo> da2;

    public:
        test() : da2{bsl::make_dynarray<Foo>(1)} {}

        auto
        test1() -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            auto it3 = it1 - 1;
            auto it4 = it2 - 1;

            CHECK(it3 - it1 == -1);
            CHECK(it4 - it2 == -1);
        }

        auto
        test2() const -> void
        {
            auto it1 = da1.end();
            auto it2 = da2.end();

            auto it3 = it1 - 1;
            auto it4 = it2 - 1;

            CHECK(it3 - it1 == -1);
            CHECK(it4 - it2 == -1);
        }
    };

    test t;
    t.test1();
    t.test2();
}

TEST_CASE("comparison operators")
{
    auto da1 = bsl::dynarray<int>();
    auto da2 = bsl::make_dynarray<int>(42);

    CHECK(da1.begin() == da1.begin());
    CHECK(da1.end() == da1.end());
    CHECK(da1.begin() == da1.end());
    CHECK(da1.end() == da1.begin());

    CHECK(da2.begin() == da2.begin());
    CHECK(da2.end() == da2.end());
    CHECK(da2.begin() != da2.end());
    CHECK(da2.end() != da2.begin());

    CHECK(da1.begin() != da2.begin());
    CHECK(da1.end() != da2.end());
    CHECK(da1.begin() != da2.end());
    CHECK(da1.end() != da2.begin());

    CHECK(da2.begin() != da1.begin());
    CHECK(da2.end() != da1.end());
    CHECK(da2.begin() != da1.end());
    CHECK(da2.end() != da1.begin());

    CHECK(da2.end() > da1.end());
    CHECK(da1.end() < da2.end());
    CHECK(da1.end() >= da1.end());
    CHECK(da1.end() <= da1.end());
    CHECK(da2.end() >= da2.end());
    CHECK(da2.end() <= da2.end());
}