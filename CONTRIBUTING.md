# Contributing to Binscope

Thanks for helping. Binscope is a small, defensive, read-only triage tool; contributions
that keep it that way are very welcome.

## Development setup

```bash
python3 -m venv .tools
. .tools/bin/activate                 # Windows: .tools\Scripts\activate
pip install -r tools/requirements.txt # pinned CMake, clang-format, clang-tidy
cmake --preset dev                    # needs Ninja and a C++20 compiler
cmake --build --preset dev
ctest --preset dev
```

Before sending a change, also run the sanitizer build and the fuzz smoke driver:

```bash
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
./build/asan/fuzz_smoke --iterations 50000 samples
```

## Lint

```bash
clang-format --dry-run --Werror include/binscope/*.hpp src/lib/*.cpp src/lib/*.hpp \
  src/cli/*.cpp src/cli/*.hpp tests/*.cpp tests/*.hpp fuzz/*.cpp fuzz/*.hpp
clang-tidy -p build/dev src/lib/*.cpp
# macOS with the pip clang-tidy: add --extra-arg=-isysroot$(xcrun --show-sdk-path)
```

CI runs the same commands on Ubuntu and macOS, plus libFuzzer for 60 seconds on Linux.

## Rules for parser code

- Every read of file data goes through `ByteView` / `StructReader`. No pointer
  arithmetic or `reinterpret_cast` over the input buffer.
- Offsets and sizes from the file are combined with `checked_add` / `checked_mul` or
  `range_ok`, never with raw `+` or `*` before a bounds check.
- Every loop driven by a count from the file is capped by a field of `Limits`.
- A malformed structure becomes a `ParseIssue` (and so a finding), never an exception,
  assertion or abort. Malformed input must not stop other files from being analysed.
- New samples must be synthetic (extend `samples/gen/make_synthetic.py`) or built from
  source in `samples/src`. Never add third-party or malicious binaries.

## Adding a rule

1. Add it to `rule_catalog()` in `src/lib/findings.cpp` with the next free id, a default
   severity, points and a neutral explanation of why it matters.
2. Implement it in the `Analyzer` class and record evidence with file offsets.
3. Add tests that show it firing on a purpose-built sample and staying quiet on a clean
   one, and update the snapshot in `tests/test_regression.cpp` if sample results change.
4. Document it in the README rule table.

## Style

C++20, formatted by `.clang-format`; comments explain *why*, not *what*. Keep the library
(`include/binscope`, `src/lib`) free of I/O other than reading a config file: the CLI
(`src/cli`) owns files, logging and exit codes.
