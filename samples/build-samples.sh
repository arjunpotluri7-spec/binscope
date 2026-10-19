#!/usr/bin/env bash
# Rebuild the native Mach-O samples from samples/src/hello.c with the system clang.
#
#   hello_arm64             normal build: arm64, PIE, ad-hoc signed by the linker
#   hello_x86_64_nopie      hardening-reduced: x86_64 linked with -no_pie
#   hello_universal         universal (fat) file holding both of the above (lipo)
#
# Why x86_64 for the reduced variant: the current Apple linker ignores -no_pie for arm64
# ("-no_pie ignored for arm64") and no longer accepts -allow_stack_execute, so the only
# hardening reduction it still honours is -no_pie on x86_64 with an old deployment target
# (newer linkers warn that it is deprecated). Requires macOS with Xcode or the Command Line Tools.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
src="$here/src/hello.c"
out="$here/macho"
mkdir -p "$out"

clang -O2 -arch arm64 "$src" -o "$out/hello_arm64"
clang -O2 -arch x86_64 -mmacosx-version-min=10.6 "$src" -Wl,-no_pie -o "$out/hello_x86_64_nopie"
lipo -create "$out/hello_x86_64_nopie" "$out/hello_arm64" -output "$out/hello_universal"

ls -l "$out"
