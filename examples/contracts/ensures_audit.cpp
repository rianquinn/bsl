#define BSL_BUILD_LEVEL BSL_BUILD_LEVEL_AUDIT    // i.e., 2
#include <bsl/contracts.h>

static auto
the_answer(int val) noexcept -> auto
{
    auto ret = [&] {
        return val;
    }();

    bsl::ensures_audit(ret == 42);
    return ret;
}

auto
main() -> int
{
    the_answer(23);
}

// FATAL ERROR: contract violation [[ensures audit]] [11]: ...
// Aborted (core dumped)
