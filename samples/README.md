# Samples

Everything in this directory is either **synthetic** or **built from the source included
here**. There are no third-party, real-world or malicious binaries.

| Path | Origin |
|---|---|
| `src/hello.c` | A five-line C program. |
| `macho/hello_arm64` | `build-samples.sh`: clang, arm64, PIE, ad-hoc signed by the linker. |
| `macho/hello_x86_64_nopie` | `build-samples.sh`: clang, x86_64, linked with `-no_pie` (the hardening-reduced variant). |
| `macho/hello_universal` | `build-samples.sh`: `lipo` of the two files above. |
| `synthetic/*` | `gen/make_synthetic.py` (Python standard library only). |

## Native Mach-O samples

`build-samples.sh` needs macOS with Xcode or the Command Line Tools. The current Apple linker
ignores `-no_pie` for arm64 and no longer accepts `-allow_stack_execute`, so the reduced
variant is an x86_64 build with an old deployment target, where `-no_pie` is still honoured.
Rebuilding produces equivalent files, though not necessarily byte-identical ones (the
linker's UUID and signature depend on the toolchain version), so the committed copies are
what the tests check.

## Synthetic files

`python3 gen/make_synthetic.py` rewrites `synthetic/` byte for byte (fixed timestamps,
fixed-seed pseudo-random filler). The files are header structures with known properties,
**not runnable programs**: "code" sections contain repetitive filler bytes, the
high-entropy sections are xorshift output, and the certificate table in
`pe64_hardened.exe` is a placeholder blob, not a signature.

| File | Built to show |
|---|---|
| `elf64_hardened.so` | PIE, full RELRO, BIND_NOW, NX stack, build-id, `$ORIGIN` RUNPATH: no findings |
| `elf64_packed_like.elf` | non-PIE, no RELRO, no PT_GNU_STACK, W+X `UPX0`/`UPX1`, random `UPX1`, entry in the last section, `./lib` RPATH |
| `elf32_be_ppc.elf` | big-endian ELF32 (PowerPC machine id) |
| `pe64_hardened.exe` | ASLR, high-entropy VA, DEP, CFG, imports from two DLLs, certificate table present |
| `pe64_packed_like.exe` | no ASLR, no DEP (missing NX flag), no CFG, W+X `UPX0`/`UPX1`, random `UPX1`, two imports |
| `pe32_ordinal.dll` | PE32 DLL with ordinal imports and no entry point |
| `macho64_wx_synthetic` | W+X `__DATA_EXEC` segment, no PIE, stack execution allowed, `cryptid` 1, relative LC_RPATH |
| `malformed_truncated_header.elf` | ELF header cut at 40 bytes |
| `malformed_section_past_eof.elf` | `.rodata` points past the end of the file; `.data` overlaps `.text` |
| `malformed_absurd_counts.elf` | 32768 program headers, inconsistent `e_shentsize` |
| `malformed_absurd_counts.exe` | `NumberOfSections` = 65535 |
| `malformed_bad_lfanew.exe` | `e_lfanew` points 2 GiB past the end |
| `malformed_overlap.exe` | two sections share raw file bytes |
| `malformed_ncmds.macho` | `ncmds` = 0xFFFFFFFF, `sizeofcmds` far beyond the file |
| `malformed_fat_past_eof` | universal header with one valid slice and one slice past EOF |
