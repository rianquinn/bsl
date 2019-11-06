#include <bsl/contracts.h>

static constexpr auto
the_answer(int val) noexcept -> void
{
    bsl::assert_axiom(val == 42);    // <--- ignored
}

auto
main() -> int
{
    the_answer(23);
}
