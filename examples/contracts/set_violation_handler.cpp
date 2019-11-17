#include <bsl/contracts.hpp>

#include <string>
#include <stdexcept>

[[noreturn]] static auto
violation_handler(const bsl::violation_info &info) -> void
{
    std::string what;
    what += "contract violation detected\n";
    what += "  - type: " + std::string(info.comment) + '\n';
    what += "  - file: " + std::string(info.location.file_name()) + '\n';
    what += "  - func: " + std::string(info.location.function_name()) + '\n';
    what += "  - line: " + std::to_string(info.location.line()) + '\n';

    throw std::logic_error(what);
}

static constexpr auto
the_answer(std::int32_t val) noexcept -> void
{
    bsl::expects(val == 42);
}

auto
main() -> int
{
    bsl::set_violation_handler(violation_handler);
    the_answer(23);
}

// terminate called after throwing an instance of 'std::logic_error'
//   what():  contract violation detected
//   - type: default precondition
//   - file: ...
//   - func: the_answer
//   - line: 19
//
// Aborted (core dumped)
