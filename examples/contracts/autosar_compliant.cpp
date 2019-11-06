#define BSL_AUTOSAR_COMPLIANT 1
#include <bsl/contracts.h>

static constexpr auto
the_answer(int val) -> void
{
    bsl::expects(val == 42);
}

auto
main() -> int
{
    try {
        the_answer(23);
    }
    catch (const std::logic_error &e) {
        std::cerr << "unchecked exception: " << e.what() << '\n';
    }
}

// unchecked exception: FATAL ERROR: default precondition violation [7]: ...
