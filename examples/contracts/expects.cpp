#define BSL_BUILD_LEVEL 0
#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    bsl::expects(val == 42);
    std::cout << val << '\n';
    return val;
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: contract violation [[expects default]] [6]: ...
// Aborted (core dumped)
