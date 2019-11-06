#define BSL_BUILD_LEVEL 2
#include <bsl/contracts.h>

static constexpr auto
the_answer(int val) noexcept -> void
{
    bsl::ensures_audit(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: audit postcondition violation [7]: ...
// Aborted (core dumped)
