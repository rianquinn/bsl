#include <bsl/contracts.h>

static constexpr auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::expects(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: default precondition violation [6]: ...
// Aborted (core dumped)
