#include <bsl/contracts.h>

static constexpr auto
the_answer(int val) noexcept -> void
{
    bsl::ensures_axiom(val == 42);    // <--- ignored
}

auto
main() -> int
{
    the_answer(23);
}
