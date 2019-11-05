#include <bsl/utility.h>
#include <iostream>

auto
main(int argc, const char *argv[]) -> int
{
    bsl::discard(argv);
    std::cout << sizeof(bsl::narrow_cast<short>(argc)) << '\n';
}

// 2
