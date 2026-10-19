# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **private vulnerability reporting**:
open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a
public issue for security problems.

Include the Binscope version, compiler and OS, a minimal input that reproduces the problem
(ideally a synthetic file or a script that generates one; please do not attach live
malware), and what you expected to happen.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment within 10 business days.
- A fix or mitigation plan for confirmed issues, with credit in the release notes if you
  want it. We ask that you allow a reasonable time for a fix before public disclosure.

## Scope

In scope: anything that lets a crafted input or config file cause a crash, out-of-bounds
read or write, undefined behaviour, unbounded memory or CPU use out of proportion to the
input size, writes outside the requested `--output` path, reading files other than the
named inputs, or a misleading report (for example a finding that points at the wrong
offset).

Out of scope: detections that miss a packer or a suspicious file (please open a normal
issue or pull request for rule improvements), and problems in third-party dependencies
that are already public.

## Security design

- **Read-only and offline.** Binscope reads only the files named on the command line plus an
  optional config file. It never executes, loads, maps or modifies the files it analyses,
  makes no network connections, and runs no subprocesses.
- **Untrusted offsets.** All access to file bytes goes through a bounds-checked `ByteView`
  whose reads return a result type. Offsets and sizes are combined with overflow-checked
  arithmetic, and fields are assembled byte by byte with explicit endianness (no
  `reinterpret_cast` over the buffer).
- **Bounded work.** Input size is capped (256 MiB by default) before reading, and every
  count taken from a header (sections, program headers, load commands, imports, symbols,
  dynamic entries, universal slices) has a hard cap. Hitting a cap is reported as finding
  BS011.
- **Malformed input is data.** Truncated or inconsistent structures become findings
  (BS008 to BS011), never crashes; one bad file does not stop the others.
- **Safe output.** Reports go to stdout or to `--output`, created with mode `0600`,
  never through a symbolic link, and never replacing an existing file without `--force`.
  Input paths that are symbolic links are refused unless `--follow-symlinks` is given;
  directories, devices and FIFOs are always refused. Names read from files are escaped
  before printing, and JSON/SARIF output escapes invalid UTF-8.
- **Tested hostile.** The test suite runs under AddressSanitizer and
  UndefinedBehaviorSanitizer, a fuzz-smoke driver replays the samples plus 50,000
  deterministic mutations in CI, and a libFuzzer harness runs on Linux CI.
- **Signatures are not verified.** Binscope reports whether a code signature or
  certificate table is *present*. It does not validate signatures or trust chains, so
  presence must not be read as "trusted".
