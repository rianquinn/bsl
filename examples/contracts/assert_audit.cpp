#define BSL_BUILD_LEVEL 2
#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> void
{
    bsl::assert_audit(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: audit assertion violation [7]: ...
// Aborted (core dumped)
