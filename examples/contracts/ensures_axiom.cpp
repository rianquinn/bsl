#include <bsl/contracts.h>

static constexpr auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::ensures_axiom(val == 42);    // <--- ignored
}

auto
main() -> int
{
    the_answer(23);
}
