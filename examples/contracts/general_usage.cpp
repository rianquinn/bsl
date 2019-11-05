#define BSL_BUILD_LEVEL BSL_BUILD_LEVEL_AUDIT
#include <bsl/contracts.h>

#include <memory>
#include <iostream>

[[noreturn]] static auto
violation_handler(const bsl::violation_info &info) -> void
{
    std::string what;
    what += "contract violation detected\n";
    what += "  - type: " + std::string(info.comment) + '\n';
    what += "  - file: " + std::string(info.location.file()) + '\n';
    what += "  - line: " + std::to_string(info.location.line()) + '\n';

    throw std::runtime_error(what);
}

static auto
the_answer(int val) -> auto
{
    bsl::expects(val == 42);

    auto ret = [&] {
        bsl::assert(1 + 1 != 3);
        return std::make_unique<int>(val);
    }();

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
//   - type: [[expects default]]
//   - file: ...
//   - line: 21
