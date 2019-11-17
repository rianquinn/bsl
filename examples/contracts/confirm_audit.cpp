#define BSL_BUILD_LEVEL 2
#include <bsl/contracts.hpp>

static auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::confirm_audit(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: audit assertion violation [7]: ...
// Aborted (core dumped)
