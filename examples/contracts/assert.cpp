#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    bsl::assert(1 + 1 == 3);
    return val;
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: contract violation [[assert default]] [6]: ...
// Aborted (core dumped)
