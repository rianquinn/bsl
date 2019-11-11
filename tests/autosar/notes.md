## Manual review notes
-   if you need to use stdint types, use std::xxx instead of xxx
-   One way to avoid issues with arithmetic is to store the result in a variable that is larger that the source. For example, int16_t = int8_t + int8_t.
-   prefer ++x or x++;
-   prefer x{} initialization over any other form.
-   When comparing constants, the constant should go first to prevent accidental assignments

## Failed rules
-   Unused final result in a loop is not detected
-   m0-1-8 is not detected (pointless functions)
-   m0-1-9 is not detected (dead code)


