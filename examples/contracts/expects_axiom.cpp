#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    bsl::expects_axiom(val == 42);    // <--- Ignored
    return val;
}

auto
main() -> int
{
    the_answer(23);
}
