#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    auto ret = [&] {
        return val;
    }();

    bsl::ensures(ret == 42);
    return ret;
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: contract violation [[ensures default]] [10]: ...
// Aborted (core dumped)
