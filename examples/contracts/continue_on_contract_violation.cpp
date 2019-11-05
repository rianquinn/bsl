#define BSL_CONTINUE_ON_CONTRACT_VIOLATION 1
#include <bsl/contracts.h>

static auto
violation_handler(const bsl::violation_info &info) -> void
{
    std::cerr << "contract violation detected\n";
    std::cerr << "  - type: " + std::string(info.comment) + '\n';
    std::cerr << "  - file: " + std::string(info.location.file()) + '\n';
    std::cerr << "  - line: " + std::to_string(info.location.line()) + '\n';
}

static auto
the_answer(int val) noexcept -> auto
{
    bsl::expects(val == 42);
    return val;
}

auto
main() -> int
{
    bsl::set_violation_handler(violation_handler);

    the_answer(23);
    std::cout << "program state undefined from this point\n";
}

// contract violation detected
//   - type: [[expects default]]
//   - file: ...
//   - line: 16
// program state undefined from this point
