# Binscope

Static triage for unknown executables: point it at an ELF, Mach-O (thin or universal) or PE file and get its structure plus explained red flags and a 0-100 suspicion score that shows its working, **without ever running or loading the file**.

![CI](../../actions/workflows/ci.yml/badge.svg)

## Why this exists

When an unfamiliar program turns up (an email attachment, a binary dropped on a server, a release artifact that suddenly got bigger), the first questions are simple: *what is it, how was it built, is it hardened, does it look packed, and is the file even well-formed?* The usual answer is a handful of format-specific tools (`readelf`, `otool`, `objdump`, PE viewers) whose output you then have to interpret yourself, and some of which were never designed for hostile input.

Binscope answers those questions in one pass, from bytes alone. It parses the headers, lists sections and segments with their entropy, checks hardening flags, and turns everything suspicious into a numbered finding that says what was seen, where (section name and file offset) and why it matters.

## Distinctive feature

**One defensive parser layer for three formats, plus a score you can audit.**

- **ELF, Mach-O (including universal/fat) and PE/COFF share one bounds-checked reader.** The parser never trusts an offset or size from the file: every read goes through `ByteView`, returns a `Result`, and combines offsets with overflow-checked arithmetic; fields are assembled byte by byte with explicit endianness, with no `reinterpret_cast` over the buffer. Every header-supplied count has a hard cap. Truncated, overlapping or out-of-range structures become findings, not crashes.
- **Proven with sanitizers and fuzzing.** The whole test suite runs under AddressSanitizer + UndefinedBehaviorSanitizer, a portable fuzz-smoke driver pushes 50,000 mutated inputs through the parse-analyse-render path, and a libFuzzer harness runs on Linux CI (see [Testing](#testing) for exactly what ran where).
- **The 0-100 suspicion score shows its working.** It is the clamped sum of per-finding points, and every report prints each factor:

  ```text
    score      70/100 (high)
       +30  W+X segment __DATA_EXEC
       +20  executable stack (MH_ALLOW_STACK_EXECUTION set)
       +10  not position independent (MH_PIE not set: fixed load address)
  ```

  Points and severities are configurable per rule, so the score can be tuned to your environment without guessing what a number means.

## Features

- **ELF32/ELF64, little and big endian**: ELF header, program headers, section headers and names (including extended numbering), `PT_INTERP`, `PT_GNU_STACK`, `PT_GNU_RELRO`, the dynamic section (`DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`, `DT_BIND_NOW`, `DT_FLAGS`, `DT_FLAGS_1`), undefined `.dynsym` symbols as imports, `.symtab`/`.dynsym` counts, and the GNU build-id (from `.note.gnu.build-id` or `PT_NOTE`). Files without section headers fall back to mapping `DT_STRTAB` through `PT_LOAD`.
- **Mach-O 32/64-bit in either byte order, plus universal files (fat32 and fat64)**: header flags (`MH_PIE`, `MH_ALLOW_STACK_EXECUTION`, `MH_NO_HEAP_EXECUTION`), segments and sections, `LC_LOAD_DYLIB` (and weak/re-export/lazy/upward), `LC_MAIN`, `LC_UNIXTHREAD` entry points (x86_64, arm64, i386, arm), `LC_CODE_SIGNATURE` presence, `LC_ENCRYPTION_INFO(_64)` `cryptid`, `LC_RPATH`, `LC_UUID`, minimum OS, and undefined symbols mapped to the dylib they bind to. Each slice of a universal file is analysed separately.
- **PE32/PE32+**: DOS header, PE signature, COFF header, optional header and `DllCharacteristics` (`DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, `NX_COMPAT`, `GUARD_CF`, `NO_SEH`, `FORCE_INTEGRITY`), section table (including `/N` long names), import directory with DLL names, function names and ordinals, timestamp, overlay size, `.NET` header presence, and whether a certificate (security) directory is **present**. Signatures are **not verified**.
- **Entropy everywhere**: Shannon entropy per section/segment (over the bytes actually in the file) and for the whole file.
- **23 rules** with ids, severities, points, evidence and plain explanations (table below), and a score labelled low / moderate / high / very high.
- **Four commands**: `inspect` (full report), `score` (one line per file or slice), `diff` (release-to-release review), `formats` (what is parsed), plus `rules` (the rule table after your config).
- **Three report formats**: human table, a stable documented JSON schema, and SARIF 2.1.0 for code-scanning dashboards.
- **Defensive by design**: read-only and offline, no subprocesses, 256 MiB input cap, count caps, reports written `0600` and never overwritten without `--force`, symlinked inputs refused unless asked, structured logs on stderr.

### Rules

| Id | Default severity | Points | Fires when |
|---|---|---|---|
| BS001 | high | 30 | a section or loadable segment is writable **and** executable |
| BS002 | high | 25 | an executable region has entropy above the threshold (default 7.2 bits/byte) |
| BS003 | medium | 10 | a large (default 64 KiB+) non-executable region has entropy above the threshold |
| BS004 | high | 25 | the entry point is outside every section, or in a non-executable one |
| BS005 | medium | 10 | the entry point is in the last section |
| BS006 | medium | 20 | a section name is one commonly produced by a packer or protector (UPX0/UPX1, .aspack, .MPRESS1, .vmp0, ... data table in `findings.cpp`) |
| BS007 | medium | 15 | few imports (default 5 or fewer) alongside high-entropy content |
| BS008 | medium | 15 | two sections claim overlapping file bytes |
| BS009 | high | 20 | a section, segment, table or slice extends past the end of the file |
| BS010 | medium | 15 | a header is truncated or inconsistent (bad sizes, missing signature, bad cmdsize, ...) |
| BS011 | medium | 10 | a count exceeds a safety cap, so parsing was truncated |
| BS012 | low | 10 | the executable is not position independent (ELF `ET_EXEC`, Mach-O without `MH_PIE`) |
| BS013 | low | 5 | ELF without `PT_GNU_RELRO` |
| BS014 | low | 5 | ELF with lazy binding (no `BIND_NOW`) |
| BS015 | high | 20 | executable stack (`PT_GNU_STACK` with `PF_X` or missing; `MH_ALLOW_STACK_EXECUTION`) |
| BS016 | medium | 10 | PE without ASLR (`DYNAMIC_BASE` unset, or set with relocations stripped) |
| BS017 | medium | 15 | PE without DEP (`NX_COMPAT` unset) |
| BS018 | low | 5 | PE without Control Flow Guard |
| BS019 | info | 0 | no code signature / certificate table (presence check only; informational) |
| BS020 | low | 5 | Mach-O with encrypted content (`cryptid` != 0) |
| BS021 | low | 5 | a relative or empty library search path (RPATH/RUNPATH/LC_RPATH) |
| BS022 | low | 10 | ELF executable without section headers |
| BS023 | low | 3 | PE32+ without `HIGH_ENTROPY_VA` |

Section names alone prove nothing: they are trivial to rename or copy, and packers and protectors are also used by legitimate software. BS006 only says how a file was likely built.

## Architecture

```text
           file bytes (read once, size-capped)
                     │
                     ▼
   ┌──────────── ByteView / StructReader ─────────────┐   bounds-checked, Result-returning,
   │  checked_add / checked_mul / range_ok            │   explicit endianness
   └──────────────────────────────────────────────────┘
          │                 │                  │
     detect_format ──► elf.cpp           macho.cpp            pe.cpp
                       ELF32/64          thin + universal     PE32/PE32+
          │                 │                  │
          └────────► Target (format-neutral model) ◄──────────┘
                     regions + entropy, hardening flags, imports,
                     properties, ParseIssues (malformed/out_of_bounds/limit)
                     │
                     ▼
              findings.cpp: Analyzer runs 23 rules ──► Finding[] ──► Score (sum, clamp, label)
                     │                                                    │
                     ▼                                                    ▼
              report.cpp: table | JSON | SARIF | score lines      diff.cpp: OLD vs NEW
                     │
                     ▼
              src/cli: argument parsing, safe file I/O, logging, exit codes
```

| Module | Role |
|---|---|
| `include/binscope/result.hpp` | `Result<T>` / `Error`, an `expected`-style type (C++20 has no `<expected>`) |
| `include/binscope/bytes.hpp`, `src/lib/bytes.cpp` | `ByteView` (range-checked `u8/u16/u32/u64`, strings, sub-views) and `StructReader` (sequential reads with a latched error), overflow-checked arithmetic |
| `src/lib/common.cpp` | magic-byte detection (including the Java-class vs universal-binary ambiguity), `parse()` dispatch, region entropy, issue capping |
| `src/lib/elf.cpp`, `macho.cpp`, `pe.cpp` | the three format parsers; each produces `Target`s with `ParseIssue`s instead of failing |
| `include/binscope/model.hpp` | `Target`, `Region`, `HardeningFlag`, `ImportedLibrary`, `Property`, `ParseIssue`, `FileInfo` |
| `src/lib/entropy.cpp` | Shannon entropy |
| `src/lib/findings.cpp` | the rule catalogue, the `Analyzer`, the packer-name table, scoring |
| `src/lib/config.cpp` | strict TOML-subset config loader with `file:line` errors |
| `src/lib/report.cpp`, `json.cpp`, `text.cpp` | renderers, a deterministic JSON writer, locale-independent number formatting |
| `src/lib/diff.cpp` | build-to-build comparison |
| `src/cli/` | `cli.cpp` (subcommands, options, exit codes), `io.cpp` (size-capped reads, `O_NOFOLLOW`, `0600` output), `log.cpp` (text/JSON logs) |
| `fuzz/` | `fuzz_target.hpp` (shared entry point), `fuzz_parse.cpp` (libFuzzer), `fuzz_smoke.cpp` (portable mutation driver) |

## Build & install

Requires a C++20 compiler, CMake 3.24+ and Ninja. GoogleTest v1.18.0 is fetched by CMake when tests are enabled; the tool itself has no third-party runtime dependencies.

```bash
git clone <this repository> binscope && cd binscope
python3 -m venv .tools && . .tools/bin/activate
pip install -r tools/requirements.txt     # pinned cmake, clang-format, clang-tidy
cmake --preset release && cmake --build --preset release
./build/release/binscope --version
```

- **macOS**: Apple clang from Xcode or the Command Line Tools; `brew install ninja`. Tested here on macOS 27 (arm64) with Apple clang 21.
- **Linux**: clang or GCC with libstdc++ 11+; `apt install ninja-build`. CI is configured to build with clang on Ubuntu; GCC builds are expected to work but are not tested in CI.
- **Windows**: the code has a Win32 file-I/O path and avoids POSIX-only headers elsewhere, but Windows builds are **not tested** in CI yet.

Presets: `dev` (debug, `-Werror`), `asan` (AddressSanitizer + UBSan, `-Werror`), `release` (optimised, no tests), `fuzz` (libFuzzer targets; needs a clang with libFuzzer, so not Apple clang).

## Quick start against `samples/`

Everything in `samples/` is synthetic or built from the included `hello.c` (see [samples/README.md](samples/README.md)).

```bash
B=./build/release/binscope
$B score samples/synthetic/* samples/macho/*            # one line per file/slice
$B inspect samples/synthetic/macho64_wx_synthetic       # full report with the score's working
$B inspect samples/synthetic/pe64_hardened.exe --sections --imports
$B diff samples/synthetic/pe64_hardened.exe samples/synthetic/pe64_packed_like.exe
$B inspect samples/macho/hello_universal --format sarif --output binscope.sarif
```

## Usage

```text
binscope inspect FILE... [--format table|json|sarif] [--sections] [--imports]
                         [--output FILE] [--force] [--fail-on SEVERITY]
binscope score FILE...   [--output FILE] [--force] [--fail-on SEVERITY]
binscope diff OLD NEW    [--format table|json] [--entropy-delta N]
                         [--fail-on SEVERITY] [--output FILE] [--force]
binscope formats
binscope rules

Common options: --config FILE  --max-size-mib N  --follow-symlinks
                --log-level debug|info|warn|error  --log-format text|json
                -h/--help  -V/--version
```

- `--fail-on info|low|medium|high|none` makes `inspect`/`score` exit 1 when any finding is at or above that severity (default: never).
- `diff` matches slices by architecture (a thin-to-thin comparison across architectures still compares). It reports added/removed libraries and imports, hardening flags lost or gained, added/removed sections, sections whose entropy moved by more than `--entropy-delta` (default 0.5), and new or resolved findings. It exits 1 on a **regression**: any lost hardening flag, or a new finding at or above `--fail-on` (default `high`).
- Diagnostics go to stderr; reports go to stdout or `--output` (created `0600`; an existing file is only replaced with `--force`; a symlink is never followed).

## Configuration

All settings are optional; see [`config.example.toml`](config.example.toml) (it lists the defaults). The format is a strict TOML subset, and unknown sections, keys or rule ids are errors that name the file and line.

```toml
[thresholds]
entropy_high = 7.2          # bits/byte
min_entropy_bytes = 512     # smaller regions are not judged on entropy
large_section_bytes = 65536 # BS003 size floor
few_imports = 5             # BS007 threshold
diff_entropy_delta = 0.5

[limits]
max_file_size_mib = 256
max_sections = 4096         # also program headers and segments
max_load_commands = 4096
max_libraries = 1024
max_imports = 20000
max_symbols = 200000
max_dynamic = 4096
max_fat_slices = 30

[points]                    # per-rule score weights (0-100)
BS003 = 5

[severity]                  # per-rule severity (info, low, medium, high)
BS019 = "low"

[rules]
disabled = ["BS023"]
```

`binscope rules --config FILE` prints the effective table.

## Sample output

All output below was produced by the commands shown, on this repository's samples.

```text
$ binscope score samples/synthetic/macho64_wx_synthetic samples/synthetic/pe64_packed_like.exe samples/synthetic/elf64_hardened.so samples/macho/hello_universal
samples/synthetic/macho64_wx_synthetic  Mach-O 64-bit  arm64  70/100 high  +30 W+X segment __DATA_EXEC | +20 executable stack (MH_ALLOW_STACK_EXECUTION set) | +10 not position independent (MH_PIE not set: fixed load address)
samples/synthetic/pe64_packed_like.exe  PE32+  x86_64  100/100 very high  +30 W+X sections UPX0, UPX1 | +25 high-entropy executable section UPX1 (7.98 bits/byte) | +20 packer-associated sections UPX0, UPX1 (UPX)
samples/synthetic/elf64_hardened.so  ELF64  x86_64  0/100 low  no findings
samples/macho/hello_universal [x86_64]  Mach-O 64-bit  x86_64  10/100 low  +10 not position independent (MH_PIE not set: fixed load address) | +0 no code signature (no LC_CODE_SIGNATURE)
samples/macho/hello_universal [arm64]  Mach-O 64-bit  arm64  0/100 low  no findings
```

```text
$ binscope inspect samples/synthetic/macho64_wx_synthetic
== samples/synthetic/macho64_wx_synthetic ==
  Mach-O 64-bit | arm64 | executable | 12336 bytes | entropy 2.36
  entry      0x100001010 in __TEXT,__text
  hardening  pie=no  nx_stack=no  no_heap_exec=no  code_signature=no
  imports    1 libraries, 2 imported symbols; search paths: lib/plugins
  layout     2 sections, 4 segments
  details    mh_flags=0x20084  ncmds=10  symbols=2  entryoff=0x1010  cryptid=1
  score      70/100 (high)
     +30  W+X segment __DATA_EXEC
     +20  executable stack (MH_ALLOW_STACK_EXECUTION set)
     +10  not position independent (MH_PIE not set: fixed load address)
      +5  encrypted content (cryptid 1)
      +5  relative library search path lib/plugins
      +0  no code signature (no LC_CODE_SIGNATURE)
  findings
    BS001  high   Writable and executable memory
           - segment __DATA_EXEC @ 0x2000: mapped writable and executable
           why: A region mapped both writable and executable lets code be written and then run in place. Normal toolchains never emit it; self-unpacking stubs and JIT-style loaders do.
    BS012  low    Not position independent
           - header @ 0x0: MH_PIE not set: fixed load address
           why: The executable loads at a fixed address, so ASLR cannot randomise its code location, which makes memory-corruption exploits easier.
    BS015  high   Executable stack
           - header @ 0x0: MH_ALLOW_STACK_EXECUTION set
           why: An executable stack lets injected data on the stack run as code, removing one of the most basic exploit mitigations.
    BS019  info   No code signature
           - header @ 0x0: no LC_CODE_SIGNATURE
           why: No code signature structure is present. Binscope only checks presence and never verifies signatures; unsigned builds are normal in development and open source.
    BS020  low    Encrypted Mach-O content
           - LC_ENCRYPTION_INFO: cryptid 1
           why: LC_ENCRYPTION_INFO marks part of the image as encrypted (FairPlay or similar), so its code cannot be inspected statically.
    BS021  low    Relative library search path
           - search path: lib/plugins
           why: A library search path that is relative (or empty) is resolved against the current directory, so running the program from an attacker-controlled directory can load planted libraries.
```

```text
$ binscope diff samples/macho/hello_x86_64_nopie samples/macho/hello_arm64
diff samples/macho/hello_x86_64_nopie -> samples/macho/hello_arm64
-- Mach-O 64-bit arm64: score 10 -> 0
  hardening added (2)
    + pie
    + code_signature
  imports removed (2)
    - /usr/lib/libSystem.B.dylib!_exit
    - /usr/lib/libSystem.B.dylib!dyld_stub_binder
  sections added (1)
    + __DATA_CONST,__got
  sections removed (7)
    - __DATA,__common
    - __DATA,__data
    - __DATA,__got
    - __DATA,__la_symbol_ptr
    - __DATA,__program_vars
    - __TEXT,__eh_frame
    - __TEXT,__stub_helper
  entropy changed by more than 0.50 (2)
    ~ __TEXT,__stubs 2.28 -> 3.02
    ~ __TEXT,__text 4.50 -> 3.77
  resolved findings (2)
    - BS012
    - BS019
result: no regression
```

`binscope diff samples/synthetic/pe64_hardened.exe samples/synthetic/pe64_packed_like.exe` lists five lost hardening flags (`aslr`, `high_entropy_va`, `dep`, `cfg`, `certificate`), the changed imports and sections, nine new findings, ends with `result: REGRESSION (hardening lost or new finding at/above high)` and exits 1.

## Output formats & exit codes

| Format | Use |
|---|---|
| `table` (default) | human triage; `--sections` adds the region table, `--imports` the import list |
| `json` | automation; stable schema documented in [docs/json-output.md](docs/json-output.md) |
| `sarif` | SARIF 2.1.0 for code-scanning UIs; one result per finding with a byte offset |

`score` always prints one line per target; `diff` supports `table` and `json`.

| Exit code | Meaning |
|---|---|
| 0 | ran fine and no finding at or above `--fail-on` (for `diff`: no regression) |
| 1 | at least one finding at or above `--fail-on` (for `diff`: a regression) |
| 2 | usage, configuration or input error: a file could not be read, was not a regular file, was too large, or was not a recognised format. All other files are still analysed and reported, and 2 takes precedence over 1. |

A file that *is* recognised but malformed is not an input error: it is analysed as far as it can be trusted and the damage is reported as findings BS008 to BS011.

## Testing

```bash
cmake --preset dev && cmake --build --preset dev && ctest --preset dev
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
./build/asan/fuzz_smoke --iterations 50000 samples
```

- **116 GoogleTest cases** (ctest also runs a 2,000-input fuzz-smoke pass, 117 tests in total) cover: the bounds-checked reader (overflow, out-of-range, endianness, latched errors), each parser against the samples with exact expected fields (ELF32 big-endian, ELF64, PE32, PE32+, thin and universal Mach-O, fat64, a hand-built big-endian Mach-O), PE imports by name and ordinal, entropy (all-zero = 0, uniform = 8), every rule firing and not firing, configurable thresholds and weights, score arithmetic, clamping and labels, every malformed sample producing findings, truncations of six samples at regular steps (every 7th or 61st length), size and count caps, `diff`, CLI exit codes and options, `0600` output and symlink refusal, the JSON schema, the SARIF structure, and a snapshot of every sample's score and rules.
- **Sanitizers**: the full suite passes under `-fsanitize=address,undefined -fno-sanitize-recover=all` locally (macOS arm64, Apple clang 21). CI is configured to run the same job on Ubuntu and macOS.
- **Fuzzing, what ran where**:
  - *Locally (macOS, Apple clang 21, ASan + UBSan)*: `fuzz_smoke` replayed the 22 files under `samples/` and then **50,000 deterministic mutations** of them (bit flips, interesting integers in both byte orders, truncation, insertion, deletion, splicing, biased towards the first 4 KiB), parsing 340,479,038 bytes in 81.6 s with no sanitizer reports or crashes (the counts are deterministic; the time varies by run). Apple clang does not ship libFuzzer, so `fuzz_parse` was **not** run locally.
  - *CI (configured in `.github/workflows/ci.yml`)*: the same 50,000-input smoke run under ASan + UBSan on Ubuntu and macOS, and `fuzz_parse` (libFuzzer + ASan + UBSan, built with clang on Ubuntu) for 60 seconds seeded with the samples. The job fails if the libFuzzer target cannot be built, so it cannot pass vacuously.
- **Lint**: `clang-format --dry-run --Werror` on all sources and `clang-tidy` (bugprone, cert, cppcoreguidelines, performance and a readability subset; exclusions are explained in `.clang-tidy`) on the library sources, both clean.

## Performance notes

The file is read into memory once (after a size check), and every structure is parsed in a single bounded pass; entropy is one linear scan per region. On the development Mac (Apple M2, macOS 27) the release build scores a 200 MiB PE file in about 0.4 s of wall time, with peak memory roughly the file size. All 18 sample files (19 images) together take about 10 ms.

## Limitations

- **Not a malware verdict.** The score measures how unusual a file's structure is. Packed, encrypted or hand-optimised legitimate software scores high; a malicious program built with a normal toolchain can score zero.
- **Signatures are not verified.** BS019 and the `certificate` / `code_signature` flags only report whether the structures are present.
- **No disassembly, no emulation, no unpacking.** Binscope never looks inside code beyond byte statistics.
- **Imports**: Mach-O imports come from the symbol table (`LC_SYMTAB`/`LC_DYSYMTAB`); chained-fixup and dyld-info bind opcodes are not decoded. ELF imports are undefined dynamic symbols and are not tied to a specific library. PE delay-load imports, exports, resources, relocations, TLS callbacks and the load-config directory (so CFG details beyond the `GUARD_CF` flag) are not parsed.
- **ELF without section headers**: imported symbol names need `.dynsym` and are not recovered from `DT_SYMTAB`/hash tables.
- **Mach-O**: `LC_UNIXTHREAD` entry points are decoded for x86_64, arm64, i386 and arm only; kernel extensions and filesets get structure but no special rules.
- **Large tables past EOF** are parsed as far as the file allows, so a header that lies about its table produces findings for the garbage entries too (evidence lists are capped at eight entries per finding).
- **Memory** use is roughly the input size; very large inputs are refused by the size cap rather than streamed.
- Windows builds are untested.

## Roadmap

- Decode Mach-O chained fixups and dyld bind opcodes for complete import lists.
- PE exports, delay imports, TLS callbacks, load-config (CFG tables, `/GS` cookie) and resource entropy.
- An overlay rule (large data appended after the last section).
- Rich-header and timestamp consistency checks for PE.
- Memory-mapped input for very large files.
- Windows CI.

## Ethical use

Binscope is a defensive tool for analysts, incident responders and release engineers. It reads files you already have and reports on them; it does not execute, unpack, modify or transmit them. Use it on files you are authorised to examine, handle real suspicious samples in an isolated environment with your organisation's procedures, and do not treat its score as proof that a file is safe or malicious.

## License

MIT. See [LICENSE](LICENSE).
