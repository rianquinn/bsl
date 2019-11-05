#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    auto ret = [&] {
        return val;
    }();

    bsl::ensures_axiom(ret == 42);    // <--- Ignored
    return ret;
}

auto
main() -> int
{
    the_answer(23);
}
