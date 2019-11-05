#define BUILD_LEVEL BSL_BUILD_LEVEL_DEFAULT
#include <bsl/contracts.h>

#include <memory>
#include <iostream>

static auto
the_answer(int val) -> auto
{
    bsl::expects(val == 42);    // <--- Trips on bad input

    auto ret = [&] {
        bsl::assert(1 + 1 != 3);    // <--- Could trip, but always true
        return std::make_unique<int>(val);
    }();

    bsl::ensures_audit(!!ret);    // <--- Ignored at current BUILD_LEVEL

    return ret;
}

auto
main() -> int
{
    the_answer(42);
}
