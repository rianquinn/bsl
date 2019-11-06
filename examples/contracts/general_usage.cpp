#define BSL_BUILD_LEVEL 2
#include <bsl/contracts.h>

#include <memory>
#include <string>
#include <iostream>
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

static auto
the_answer(int val) -> std::unique_ptr<int>
{
    bsl::expects(val == 42);
    bsl::assert_axiom(1 + 1 != 3);

    auto ret = std::make_unique<int>(val);
    bsl::ensures_audit(!!ret);

    return ret;
}

auto
main() -> int
{
    bsl::set_violation_handler(violation_handler);

    auto val = the_answer(42);
    std::cout << "The answer is: " << *val << '\n';

    try {
        the_answer(0);
    }
    catch (const std::exception &e) {
        std::cerr << e.what();
    }
}

// The answer is: 42
// contract violation detected
//   - type: default precondition
//   - file: ...
//   - func: the_answer
//   - line: 23
