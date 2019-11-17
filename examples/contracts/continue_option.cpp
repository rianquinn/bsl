#define BSL_CONTINUE_OPTION 1
#include <bsl/contracts.hpp>

#include <string>
#include <iostream>

static auto
violation_handler(const bsl::violation_info &info) noexcept -> void
{
    std::string what;
    what += "contract violation detected\n";
    what += "  - type: " + std::string(info.comment) + '\n';
    what += "  - file: " + std::string(info.location.file_name()) + '\n';
    what += "  - func: " + std::string(info.location.function_name()) + '\n';
    what += "  - line: " + std::to_string(info.location.line()) + '\n';

    std::cerr << what << '\n';
}

static auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::expects(val == 42);
    std::cout << "the violation was logged and ignored\n";
}

auto
main() -> int
{
    bsl::set_violation_handler(violation_handler);
    the_answer(23);
}

// contract violation detected
//   - type: default precondition
//   - file: ...
//   - func: the_answer
//   - line: 23

// the violation was logged and ignored
