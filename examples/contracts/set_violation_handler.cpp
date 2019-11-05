#include <bsl/contracts.h>

[[noreturn]] static auto
violation_handler(const bsl::violation_info &info) -> void
{
    std::cerr << "contract violation detected\n";
    std::cerr << "  - type: " + std::string(info.comment) + '\n';
    std::cerr << "  - file: " + std::string(info.location.file()) + '\n';
    std::cerr << "  - line: " + std::to_string(info.location.line()) + '\n';

    std::terminate();
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
}

// contract violation detected
//   - type: [[expects default]]
//   - file: ...
//   - line: 17
// terminate called without an active exception
// Aborted (core dumped)
