#include <bsl/contracts.hpp>

static constexpr auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::assert(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: default assertion violation [6]: ...
// Aborted (core dumped)
