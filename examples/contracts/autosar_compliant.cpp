
/// [example]
#define BSL_AUTOSAR_COMPLIANT 1
#include <bsl/contracts.hpp>

static constexpr auto
the_answer(std::int32_t val) -> void
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
/// [example]
