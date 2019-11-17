## Manual review notes
-   One way to avoid issues with arithmetic is to store the result in a
    variable that is larger that the source. For example,
    int16_t = int8_t +int8_t.
-   prefer ++x or x++;
-   prefer x{} initialization over any other form.
-   When comparing constants, the constant should go first to prevent               accidental assignments
-   All error codes from functions must be checked.
-   Sections of code cannot be commented out
-   Variable and type names should be unique, even in different scopes
-   Cannot reuse the same function/variables names, even if they are marked
    as static. This should not be an issue for us with such a large amount of
    templates
-   variable names should not be the same as type names. Even if the
    type name includes a namespace

## Failed rules
-   a0-1-1: unused final result in a loop
-   m0-1-8: pointless functions
-   m0-1-9: dead code
-   m2-10-3: ambiguity local types vs names
-   a2-11-4: ambiguity static functions/variables
-   a2-11-5: ambiguity static functions/variables
-   m2-10-6: ambiguity type name == variable name

## TODO
-   We need code metrics like function size, max number params, etc...
