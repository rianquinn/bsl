#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    bsl::assert_axiom(1 + 1 == 3);    // <--- Ignored
    return val;
}

auto
main() -> int
{
    the_answer(23);
}
