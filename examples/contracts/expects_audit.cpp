#define BSL_BUILD_LEVEL 2
#include <bsl/contracts.h>

static constexpr auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::expects_audit(val == 42);
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: audit precondition violation [7]: ...
// Aborted (core dumped)
