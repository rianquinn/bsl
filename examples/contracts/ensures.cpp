#include <bsl/contracts.h>

static constexpr auto
the_answer(int val) noexcept -> void
{
    bsl::ensures(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: default postcondition violation [6]: ...
// Aborted (core dumped)
