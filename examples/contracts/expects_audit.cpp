#define BSL_BUILD_LEVEL BSL_BUILD_LEVEL_AUDIT    // i.e., 2
#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    bsl::expects_audit(val == 42);
    return val;
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: contract violation [[expects audit]] [7]: ...
// Aborted (core dumped)
