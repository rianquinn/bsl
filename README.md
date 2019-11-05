# **Bareflank Support Library**

## **Description**

The Bareflank Support Library (BSL) is a simple, header-only library that provides support for the C++ Core Guideline compliance. Similar to the goals of the Guideline Support Library (GSL) by Microsoft, the BSL aims to provide the facilities needed to ensure guideline compliance, while minimizing the need for verbosity.

[![Material for MkDocs](https://github.com/Bareflank/bsl/raw/master/docs/images/example.png)](https://github.com/Bareflank/bsl/raw/master/docs/images/example.png)

## **Quick start**

![GitHub release (latest by date)](https://img.shields.io/github/v/release/bareflank/bsl?color=brightgreen)

Get the latest version of the BSL from GitHub:

``` bash
wget https://raw.githubusercontent.com/Bareflank/bsl/master/include/bsl.h
```

Enjoy:

``` c++
#include "bsl.h"

auto
main() -> int
{
    auto da = bsl::make_dynarray<int>(42);
}
```

## **Resources**

[![Board Status](https://dev.azure.com/bareflank/0e2ee159-02d3-456c-908e-b6684055bb6c/183e6af6-db8f-4e28-910e-33ffd32d94a9/_apis/work/boardbadge/2e44e3c9-beea-457e-9786-4af440d91aa8)](https://dev.azure.com/bareflank/0e2ee159-02d3-456c-908e-b6684055bb6c/_boards/board/t/183e6af6-db8f-4e28-910e-33ffd32d94a9/Microsoft.RequirementCategory/)
[![Join the chat](https://img.shields.io/badge/chat-on%20Slack-brightgreen.svg)](https://app.slack.com/client/TPN7LQKRP/CPJLF1RV1)

The Bareflank Support Library provides a ton of useful resources to learn how to use the library including:

-   **Documentation**: <https://bareflank.github.io/bsl/>
-   **Examples**: <https://github.com/Bareflank/bsl/tree/master/examples>
-   **Unit Tests**: <https://github.com/Bareflank/bsl/tree/master/tests>

If you have any questions, bugs, or feature requests, please feel free to ask on any of the following:

-   **Issue Tracker**: <https://github.com/Bareflank/bsl/issues>
-   **Slack**: <https://app.slack.com/client/TPN7LQKRP/CPJLF1RV1>

And as always, we are always looking for more help:

-   **Pull Requests**: <https://github.com/Bareflank/bsl/pulls>
-   **Contributing Guidelines**: <https://github.com/Bareflank/bsl/blob/master/contributing.md>

## **Testing**
[![Build Status](https://dev.azure.com/bareflank/bsl/_apis/build/status/Bareflank.bsl?branchName=master)](https://dev.azure.com/bareflank/bsl/_build/latest?definitionId=2&branchName=master)
[![codecov](https://codecov.io/gh/Bareflank/bsl/branch/master/graph/badge.svg)](https://codecov.io/gh/Bareflank/bsl)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/Bareflank/bsl.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Bareflank/bsl/context:cpp)
![Codacy grade](https://img.shields.io/codacy/grade/9e55fc17a08d4e2abe51d82f09f4449f)
[![CodeFactor](https://www.codefactor.io/repository/github/bareflank/bsl/badge)](https://www.codefactor.io/repository/github/bareflank/bsl)

The Bareflank Support Library leverages the following tools to ensure the highest possible code quality. Each pull request undergoes the follwoing rigurous testing and review:

-   **Static Analysis:** Clang Tidy, CppCheck, Codacy, CodeFactor, and LGTM
-   **Dynamic Analysis:** Google's ASAN and UBSAN, Valgrind
-   **Code Coverage:** LCOV Code Coverage with CodeCov
-   **Coding Standards**: [AUTOSAR C++14](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf)
-   **Style**: Clang Format and Git Check
-   **Documentation**: MkDocs and Doxygen
