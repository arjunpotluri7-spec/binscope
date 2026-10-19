#!/usr/bin/env python3
"""Write the synthetic ELF, PE and Mach-O test files used by Binscope's tests.

Every file is hand-assembled from header structures with known properties. None of them
is a runnable program: code sections hold filler bytes, not instructions. The output is
byte-for-byte deterministic (fixed timestamps, a fixed-seed xorshift generator), so
re-running this script reproduces the committed files exactly.

Usage: python3 samples/gen/make_synthetic.py [OUTPUT_DIR]   (default: samples/synthetic)
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

# --------------------------------------------------------------------------------------
# helpers


def xorshift_bytes(count: int, seed: int) -> bytes:
    """Deterministic pseudo-random bytes (xorshift64*), high entropy by construction."""
    state = seed & 0xFFFFFFFFFFFFFFFF or 1
    out = bytearray()
    while len(out) < count:
        state ^= (state >> 12) & 0xFFFFFFFFFFFFFFFF
        state ^= (state << 25) & 0xFFFFFFFFFFFFFFFF
        state ^= (state >> 27) & 0xFFFFFFFFFFFFFFFF
        value = (state * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF
        out += value.to_bytes(8, "little")
    return bytes(out[:count])


def filler_code(count: int) -> bytes:
    """Low-entropy, repetitive filler standing in for code (not real instructions)."""
    pattern = bytes([0x90, 0x90, 0x48, 0x89, 0xE5, 0x90, 0xC3, 0xCC])
    return (pattern * (count // len(pattern) + 1))[:count]


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def pad_to(buf: bytearray, offset: int) -> None:
    if len(buf) < offset:
        buf += b"\0" * (offset - len(buf))


class StrTab:
    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self.index: dict[str, int] = {"": 0}

    def add(self, text: str) -> int:
        if text not in self.index:
            self.index[text] = len(self.data)
            self.data += text.encode() + b"\0"
        return self.index[text]


# --------------------------------------------------------------------------------------
# ELF

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = (
    1,
    2,
    3,
    6,
    7,
    8,
    11,
)
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
PF_X, PF_W, PF_R = 1, 2, 4
DT_NULL, DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT = 0, 1, 5, 6, 10, 11
DT_RPATH, DT_BIND_NOW, DT_RUNPATH, DT_FLAGS, DT_FLAGS_1 = 15, 24, 29, 30, 0x6FFFFFFB


class ElfSection:
    def __init__(
        self,
        name: str,
        sh_type: int,
        flags: int,
        data: bytes = b"",
        nobits: int = 0,
        link: str | None = None,
        info: int = 0,
        align_to: int = 8,
        entsize: int = 0,
    ) -> None:
        self.name = name
        self.sh_type = sh_type
        self.flags = flags
        self.data = data
        self.nobits = nobits
        self.link = link
        self.info = info
        self.align = align_to
        self.entsize = entsize
        self.offset = 0
        self.addr = 0

    @property
    def size(self) -> int:
        return self.nobits if self.sh_type == SHT_NOBITS else len(self.data)


def build_elf(
    *,
    is64: bool,
    little: bool,
    e_type: int,
    machine: int,
    base: int,
    sections: list[ElfSection],
    segments: list[tuple[int, int, list[str]]],
    entry: tuple[str, int],
    fill_dynamic=None,
) -> bytearray:
    """Lay out sections after the headers, then emit header, phdrs, data and shdrs.

    segments: (p_type, p_flags, names) where names lists the sections the segment covers;
    the special name "@headers" covers the ELF header and program header table.
    """
    e = "<" if little else ">"
    ehsize = 64 if is64 else 52
    phentsize = 56 if is64 else 32
    shentsize = 64 if is64 else 40
    phoff = ehsize
    cursor = phoff + phentsize * len(segments)
    for sec in sections:
        cursor = align(cursor, sec.align)
        sec.offset = cursor
        sec.addr = base + cursor if sec.flags & SHF_ALLOC else 0
        if sec.sh_type != SHT_NOBITS:
            cursor += sec.size
    if fill_dynamic is not None:
        fill_dynamic(sections)

    shstr = StrTab()
    for sec in sections:
        shstr.add(sec.name)
    shstr.add(".shstrtab")
    shstrtab = ElfSection(".shstrtab", SHT_STRTAB, 0, bytes(shstr.data), align_to=1)
    shstrtab.offset = cursor
    cursor += shstrtab.size
    all_sections = sections + [shstrtab]
    shoff = align(cursor, 8)
    names = {s.name: i + 1 for i, s in enumerate(all_sections)}

    by_name = {s.name: s for s in sections}
    entry_sec, entry_delta = entry
    e_entry = by_name[entry_sec].addr + entry_delta if entry_sec else 0

    out = bytearray()
    ident = b"\x7fELF" + bytes([2 if is64 else 1, 1 if little else 2, 1, 0]) + b"\0" * 8
    out += ident
    if is64:
        out += struct.pack(
            e + "HHIQQQIHHHHHH",
            e_type,
            machine,
            1,
            e_entry,
            phoff,
            shoff,
            0,
            ehsize,
            phentsize,
            len(segments),
            shentsize,
            len(all_sections) + 1,
            names[".shstrtab"],
        )
    else:
        out += struct.pack(
            e + "HHIIIIIHHHHHH",
            e_type,
            machine,
            1,
            e_entry,
            phoff,
            shoff,
            0,
            ehsize,
            phentsize,
            len(segments),
            shentsize,
            len(all_sections) + 1,
            names[".shstrtab"],
        )

    headers_end = phoff + phentsize * len(segments)
    for p_type, p_flags, covered in segments:
        if covered:
            starts, ends, mends = [], [], []
            for name in covered:
                if name == "@headers":
                    starts.append(0)
                    ends.append(headers_end)
                    mends.append(headers_end)
                    continue
                sec = by_name[name]
                starts.append(sec.offset)
                file_end = sec.offset + (0 if sec.sh_type == SHT_NOBITS else sec.size)
                ends.append(file_end)
                mends.append(sec.offset + sec.size)
            off, end, mend = min(starts), max(ends), max(mends)
            vaddr = base + off
            filesz, memsz = end - off, mend - off
        else:
            off = vaddr = filesz = memsz = 0
        palign = 0x1000 if p_type == PT_LOAD else (16 if p_type == PT_GNU_STACK else 8)
        if is64:
            out += struct.pack(
                e + "IIQQQQQQ", p_type, p_flags, off, vaddr, vaddr, filesz, memsz, palign
            )
        else:
            out += struct.pack(
                e + "IIIIIIII", p_type, off, vaddr, vaddr, filesz, memsz, p_flags, palign
            )

    for sec in all_sections:
        if sec.sh_type == SHT_NOBITS:
            continue
        pad_to(out, sec.offset)
        out += sec.data
    pad_to(out, shoff)

    def shdr(name_off, sh_type, flags, addr, offset, size, link, info, salign, entsize):
        if is64:
            return struct.pack(
                e + "IIQQQQIIQQ",
                name_off,
                sh_type,
                flags,
                addr,
                offset,
                size,
                link,
                info,
                salign,
                entsize,
            )
        return struct.pack(
            e + "IIIIIIIIII",
            name_off,
            sh_type,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            salign,
            entsize,
        )

    out += shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    for sec in all_sections:
        link = names[sec.link] if sec.link else 0
        out += shdr(
            shstr.index[sec.name],
            sec.sh_type,
            sec.flags,
            sec.addr,
            sec.offset,
            sec.size,
            link,
            sec.info,
            sec.align,
            sec.entsize,
        )
    return out


def elf_dynamic_parts(is64: bool, little: bool, needed: list[str], undefined: list[str]):
    """Build .dynstr/.dynsym content and a callback that fills .dynamic after layout."""
    e = "<" if little else ">"
    dynstr = StrTab()
    for lib in needed:
        dynstr.add(lib)
    sym_names = [dynstr.add(s) for s in undefined]
    syms = bytearray()
    entsize = 24 if is64 else 16
    syms += b"\0" * entsize
    for name_off in sym_names:
        if is64:
            syms += struct.pack(e + "IBBHQQ", name_off, 0x12, 0, 0, 0, 0)
        else:
            syms += struct.pack(e + "IIIBBH", name_off, 0, 0, 0x12, 0, 0)
    return dynstr, bytes(syms), entsize


def make_elf_dynamic_bytes(is64: bool, little: bool, entries: list[tuple[int, int]]) -> bytes:
    e = "<" if little else ">"
    fmt = e + ("qQ" if is64 else "iI")
    return b"".join(struct.pack(fmt, tag, val) for tag, val in entries)


def build_id_note(little: bool, desc: bytes) -> bytes:
    e = "<" if little else ">"
    return struct.pack(e + "III", 4, len(desc), 3) + b"GNU\0" + desc


def elf64_hardened() -> bytearray:
    """A well-hardened PIE: full RELRO, BIND_NOW, NX stack, build-id, RUNPATH."""
    dynstr, dynsym, entsize = elf_dynamic_parts(
        True, True, ["libc.so.6", "libm.so.6"], ["puts", "printf", "__libc_start_main", "cos"]
    )
    runpath = dynstr.add("$ORIGIN/../lib")
    dyn_entries_template = 9
    sections = [
        ElfSection(".interp", SHT_PROGBITS, SHF_ALLOC, b"/lib64/ld-linux-x86-64.so.2\0", align_to=1),
        ElfSection(
            ".note.gnu.build-id",
            SHT_NOTE,
            SHF_ALLOC,
            build_id_note(True, bytes(range(0xA0, 0xB4))),
            align_to=4,
        ),
        ElfSection(".dynsym", SHT_DYNSYM, SHF_ALLOC, dynsym, link=".dynstr", info=1, entsize=entsize),
        ElfSection(".dynstr", SHT_STRTAB, SHF_ALLOC, bytes(dynstr.data), align_to=1),
        ElfSection(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, filler_code(1024), align_to=16),
        ElfSection(".rodata", SHT_PROGBITS, SHF_ALLOC, b"hello from a synthetic file\0" * 4),
        ElfSection(
            ".dynamic",
            SHT_DYNAMIC,
            SHF_ALLOC | SHF_WRITE,
            b"\0" * (16 * dyn_entries_template),
            link=".dynstr",
            entsize=16,
        ),
        ElfSection(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, b"\x01\x02\x03\x04" * 8),
        ElfSection(".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, nobits=256),
    ]

    def fill(secs):
        by = {s.name: s for s in secs}
        entries = [
            (DT_NEEDED, dynstr.index["libc.so.6"]),
            (DT_NEEDED, dynstr.index["libm.so.6"]),
            (DT_RUNPATH, runpath),
            (DT_STRTAB, by[".dynstr"].addr),
            (DT_STRSZ, len(dynstr.data)),
            (DT_SYMTAB, by[".dynsym"].addr),
            (DT_FLAGS, 0x8),
            (DT_FLAGS_1, 0x08000001),
            (DT_NULL, 0),
        ]
        by[".dynamic"].data = make_elf_dynamic_bytes(True, True, entries)

    return build_elf(
        is64=True,
        little=True,
        e_type=3,
        machine=0x3E,
        base=0,
        sections=sections,
        segments=[
            (PT_LOAD, PF_R | PF_X, ["@headers", ".interp", ".text", ".rodata"]),
            (PT_LOAD, PF_R | PF_W, [".dynamic", ".data", ".bss"]),
            (PT_INTERP, PF_R, [".interp"]),
            (PT_DYNAMIC, PF_R | PF_W, [".dynamic"]),
            (PT_NOTE, PF_R, [".note.gnu.build-id"]),
            (PT_GNU_STACK, PF_R | PF_W, []),
            (PT_GNU_RELRO, PF_R, [".dynamic"]),
        ],
        entry=(".text", 0x40),
        fill_dynamic=fill,
    )


def elf64_packed_like() -> bytearray:
    """Non-PIE, no RELRO, no PT_GNU_STACK, W+X UPX1 section full of random bytes."""
    dynstr, dynsym, entsize = elf_dynamic_parts(True, True, ["libc.so.6"], ["mmap"])
    rpath = dynstr.add("./lib")
    sections = [
        ElfSection("UPX0", SHT_NOBITS, SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR, nobits=0x4000, align_to=16),
        ElfSection(".dynsym", SHT_DYNSYM, SHF_ALLOC, dynsym, link=".dynstr", info=1, entsize=entsize),
        ElfSection(".dynstr", SHT_STRTAB, SHF_ALLOC, bytes(dynstr.data), align_to=1),
        ElfSection(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, b"\0" * 64, link=".dynstr", entsize=16),
        ElfSection(
            "UPX1",
            SHT_PROGBITS,
            SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR,
            xorshift_bytes(8192, 0x5EED0001),
            align_to=16,
        ),
    ]

    def fill(secs):
        by = {s.name: s for s in secs}
        entries = [
            (DT_NEEDED, dynstr.index["libc.so.6"]),
            (DT_RPATH, rpath),
            (DT_STRTAB, by[".dynstr"].addr),
            (DT_NULL, 0),
        ]
        by[".dynamic"].data = make_elf_dynamic_bytes(True, True, entries)

    return build_elf(
        is64=True,
        little=True,
        e_type=2,
        machine=0x3E,
        base=0x400000,
        sections=sections,
        segments=[
            (PT_LOAD, PF_R | PF_W | PF_X, ["@headers", "UPX0", ".dynsym", ".dynstr", ".dynamic", "UPX1"]),
            (PT_DYNAMIC, PF_R | PF_W, [".dynamic"]),
        ],
        entry=("UPX1", 0x100),
        fill_dynamic=fill,
    )


def elf32_be() -> bytearray:
    """Big-endian ELF32 (PowerPC machine id) to exercise byte order handling."""
    sections = [
        ElfSection(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, filler_code(512), align_to=4),
        ElfSection(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, b"\xde\xad\xbe\xef" * 16, align_to=4),
    ]
    return build_elf(
        is64=False,
        little=False,
        e_type=2,
        machine=0x14,
        base=0x10000000,
        sections=sections,
        segments=[
            (PT_LOAD, PF_R | PF_X, ["@headers", ".text"]),
            (PT_LOAD, PF_R | PF_W, [".data"]),
            (PT_GNU_STACK, PF_R | PF_W, []),
        ],
        entry=(".text", 0x10),
    )


# --------------------------------------------------------------------------------------
# PE / COFF

SCN_CODE, SCN_IDATA, SCN_UDATA = 0x20, 0x40, 0x80
SCN_EXEC, SCN_READ, SCN_WRITE = 0x20000000, 0x40000000, 0x80000000
DLL_HIGH_ENTROPY_VA, DLL_DYNAMIC_BASE, DLL_NX_COMPAT, DLL_GUARD_CF = 0x20, 0x40, 0x100, 0x4000
DLL_TERMINAL_SERVER_AWARE = 0x8000
FIXED_TIMESTAMP = 0x5F5E1000  # 2020-09-13, fixed so the output is reproducible


class PeSection:
    def __init__(self, name: str, chars: int, data: bytes = b"", vsize: int | None = None, gen=None):
        self.name = name
        self.chars = chars
        self.data = data
        self.vsize = vsize
        self.gen = gen  # callable(rva) -> bytes, for content that depends on its own RVA
        self.rva = 0
        self.raw_off = 0
        self.raw_size = 0


def import_table(rva: int, is64: bool, imports: list[tuple[str, list[str | int]]]) -> bytes:
    """Import descriptors, lookup and address tables, hint/name entries and DLL names."""
    thunk = 8 if is64 else 4
    ordinal_flag = 1 << (63 if is64 else 31)
    n = len(imports)
    desc_size = 20 * (n + 1)
    ilt_sizes = [thunk * (len(funcs) + 1) for _, funcs in imports]
    ilt_off = desc_size
    iat_off = ilt_off + sum(ilt_sizes)
    names_off = iat_off + sum(ilt_sizes)
    names = bytearray()
    name_rvas = []
    func_rvas: list[list[int]] = []
    for dll, funcs in imports:
        name_rvas.append(rva + names_off + len(names))
        names += dll.encode() + b"\0"
        if len(names) % 2:
            names += b"\0"
    for _, funcs in imports:
        rvas = []
        for f in funcs:
            if isinstance(f, int):
                rvas.append(ordinal_flag | f)
            else:
                rvas.append(rva + names_off + len(names))
                names += struct.pack("<H", 0) + f.encode() + b"\0"
                if len(names) % 2:
                    names += b"\0"
        func_rvas.append(rvas)
    out = bytearray()
    ilt_cursor = ilt_off
    iat_cursor = iat_off
    for i in range(n):
        out += struct.pack("<IIIII", rva + ilt_cursor, 0, 0, name_rvas[i], rva + iat_cursor)
        ilt_cursor += ilt_sizes[i]
        iat_cursor += ilt_sizes[i]
    out += b"\0" * 20
    fmt = "<Q" if is64 else "<I"
    for _ in range(2):  # lookup table, then address table (identical on disk)
        for rvas in func_rvas:
            for value in rvas:
                out += struct.pack(fmt, value)
            out += struct.pack(fmt, 0)
    out += names
    return bytes(out)


def build_pe(
    *,
    is64: bool,
    machine: int,
    characteristics: int,
    dll_chars: int,
    sections: list[PeSection],
    entry: tuple[str, int] | None,
    imports: tuple[str, list[tuple[str, list[str | int]]]] | None,
    certificate: bytes | None,
    number_of_sections_override: int | None = None,
) -> bytearray:
    file_align, sect_align = 0x200, 0x1000
    e_lfanew = 0x80
    opt_size = 240 if is64 else 224
    headers_size = align(e_lfanew + 4 + 20 + opt_size + 40 * len(sections), file_align)
    rva = sect_align
    raw = headers_size
    import_rva = import_size = 0
    for sec in sections:
        sec.rva = rva
        if sec.gen is not None:
            sec.data = sec.gen(rva)
        if imports and sec.name == imports[0]:
            sec.data = import_table(rva, is64, imports[1])
            import_rva, import_size = rva, 20 * (len(imports[1]) + 1)
        sec.raw_size = align(len(sec.data), file_align) if sec.data else 0
        sec.raw_off = raw if sec.data else 0
        raw += sec.raw_size
        vsize = sec.vsize if sec.vsize is not None else max(len(sec.data), 1)
        rva += align(vsize, sect_align)
        sec.vsize = vsize
    size_of_image = rva
    cert_off = align(raw, 8) if certificate else 0

    by = {s.name: s for s in sections}
    entry_rva = by[entry[0]].rva + entry[1] if entry else 0
    code_size = sum(s.raw_size for s in sections if s.chars & SCN_CODE)

    out = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", e_lfanew))
    pad_to(out, e_lfanew)
    out += b"PE\0\0"
    nsections = number_of_sections_override if number_of_sections_override is not None else len(sections)
    out += struct.pack("<HHIIIHH", machine, nsections, FIXED_TIMESTAMP, 0, 0, opt_size, characteristics)
    dirs = [(0, 0)] * 16
    if imports:
        dirs[1] = (import_rva, import_size)
    if certificate:
        dirs[4] = (cert_off, len(certificate))
    if is64:
        out += struct.pack(
            "<HBBIIIII",
            0x20B,
            14,
            0,
            code_size,
            0,
            0,
            entry_rva,
            sect_align,
        )
        out += struct.pack("<QII", 0x140000000, sect_align, file_align)
        out += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
        out += struct.pack("<IIIHH", size_of_image, headers_size, 0, 3, dll_chars)
        out += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        out += struct.pack(
            "<HBBIIIIII",
            0x10B,
            14,
            0,
            code_size,
            0,
            0,
            entry_rva,
            sect_align,
            2 * sect_align,
        )
        out += struct.pack("<III", 0x10000000, sect_align, file_align)
        out += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
        out += struct.pack("<IIIHH", size_of_image, headers_size, 0, 2, dll_chars)
        out += struct.pack("<IIIIII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    for d in dirs:
        out += struct.pack("<II", *d)
    for sec in sections:
        name = sec.name.encode()[:8].ljust(8, b"\0")
        out += name + struct.pack(
            "<IIIIIIHHI", sec.vsize, sec.rva, sec.raw_size, sec.raw_off, 0, 0, 0, 0, sec.chars
        )
    pad_to(out, headers_size)
    for sec in sections:
        if sec.data:
            pad_to(out, sec.raw_off)
            out += sec.data
            pad_to(out, sec.raw_off + sec.raw_size)
    if certificate:
        pad_to(out, cert_off)
        out += certificate
    return out


def fake_certificate_blob() -> bytes:
    """WIN_CERTIFICATE header with placeholder bytes. Binscope only checks presence."""
    body = b"SYNTHETIC-PLACEHOLDER-NOT-A-SIGNATURE".ljust(56, b"\0")
    return struct.pack("<IHH", 8 + len(body), 0x0200, 0x0002) + body


def pe64_hardened() -> bytearray:
    return build_pe(
        is64=True,
        machine=0x8664,
        characteristics=0x0022,
        dll_chars=DLL_HIGH_ENTROPY_VA | DLL_DYNAMIC_BASE | DLL_NX_COMPAT | DLL_GUARD_CF | DLL_TERMINAL_SERVER_AWARE,
        sections=[
            PeSection(".text", SCN_CODE | SCN_EXEC | SCN_READ, filler_code(0x600)),
            PeSection(".rdata", SCN_IDATA | SCN_READ),
            PeSection(".data", SCN_IDATA | SCN_READ | SCN_WRITE, b"\x00\x11\x22\x33" * 32, vsize=0x200),
        ],
        entry=(".text", 0x20),
        imports=(
            ".rdata",
            [
                ("KERNEL32.dll", ["GetStdHandle", "WriteFile", "ExitProcess", "GetLastError"]),
                ("USER32.dll", ["MessageBoxW"]),
            ],
        ),
        certificate=fake_certificate_blob(),
    )


def pe64_packed_like() -> bytearray:
    """No ASLR, no DEP (missing NX flag), W+X UPX sections, two imports, high entropy."""
    return build_pe(
        is64=True,
        machine=0x8664,
        characteristics=0x0023,  # includes RELOCS_STRIPPED
        dll_chars=0,
        sections=[
            PeSection("UPX0", SCN_UDATA | SCN_EXEC | SCN_READ | SCN_WRITE, b"", vsize=0x10000),
            PeSection("UPX1", SCN_IDATA | SCN_EXEC | SCN_READ | SCN_WRITE, xorshift_bytes(0x3000, 0x5EED0002)),
            PeSection(".rsrc", SCN_IDATA | SCN_READ),
        ],
        entry=("UPX1", 0x2F00),
        imports=(".rsrc", [("KERNEL32.DLL", ["LoadLibraryA", "GetProcAddress"])]),
        certificate=None,
    )


def pe32_dll() -> bytearray:
    """32-bit DLL with an ordinal import and no entry point."""
    return build_pe(
        is64=False,
        machine=0x14C,
        characteristics=0x2102,  # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL
        dll_chars=DLL_DYNAMIC_BASE | DLL_NX_COMPAT,
        sections=[
            PeSection(".text", SCN_CODE | SCN_EXEC | SCN_READ, filler_code(0x400)),
            PeSection(".idata", SCN_IDATA | SCN_READ | SCN_WRITE),
        ],
        entry=None,
        imports=(".idata", [("WS2_32.dll", [23, 115, "inet_pton"]), ("KERNEL32.dll", ["Sleep"])]),
        certificate=None,
    )


# --------------------------------------------------------------------------------------
# Mach-O

LC_SEGMENT_64, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLIB = 0x19, 0x2, 0xB, 0xC
LC_RPATH, LC_MAIN, LC_ENCRYPTION_INFO_64 = 0x8000001C, 0x80000028, 0x2C
MH_EXECUTE, MH_DYLDLINK, MH_TWOLEVEL, MH_ALLOW_STACK_EXECUTION = 2, 0x4, 0x80, 0x20000
CPU_ARM64 = 0x0100000C


def lc_str(cmd: int, fixed: bytes, text: str) -> bytes:
    """A load command whose trailing string is referenced by an lc_str offset."""
    header_len = 8 + len(fixed)
    payload = text.encode() + b"\0"
    size = align(header_len + len(payload), 8)
    return struct.pack("<II", cmd, size) + fixed + payload + b"\0" * (size - header_len - len(payload))


def macho_segment(name: str, vmaddr: int, vmsize: int, fileoff: int, filesize: int, prot: int, sects) -> bytes:
    body = struct.pack(
        "<16sQQQQiiII",
        name.encode(),
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        prot,
        prot,
        len(sects),
        0,
    )
    for sectname, addr, size, offset, flags in sects:
        body += struct.pack(
            "<16s16sQQIIIIIIII",
            sectname.encode(),
            name.encode(),
            addr,
            size,
            offset,
            4,
            0,
            0,
            flags,
            0,
            0,
            0,
        )
    return struct.pack("<II", LC_SEGMENT_64, 8 + len(body)) + body


def macho64_wx() -> bytearray:
    """Thin arm64 Mach-O: no PIE, allow-stack-exec, a W+X __DATA_EXEC segment, cryptid 1."""
    base = 0x100000000
    text_off, text_size = 0x1000, 0x800
    dexec_off, dexec_size = 0x2000, 0x1000
    link_off = 0x3000
    strtab = StrTab()
    sym_puts = strtab.add("_puts")
    sym_exit = strtab.add("_exit")
    nlist = struct.pack("<IBBHQ", sym_puts, 0x01, 0, 0x0100, 0) + struct.pack("<IBBHQ", sym_exit, 0x01, 0, 0x0100, 0)
    symoff = link_off
    stroff = symoff + len(nlist)
    linkedit = nlist + bytes(strtab.data)
    link_size = align(len(linkedit), 16)

    cmds = [
        macho_segment("__PAGEZERO", 0, base, 0, 0, 0, []),
        macho_segment(
            "__TEXT",
            base,
            0x2000,
            0,
            0x2000,
            5,
            [("__text", base + text_off, text_size, text_off, 0x80000400)],
        ),
        macho_segment(
            "__DATA_EXEC",
            base + 0x2000,
            0x1000,
            dexec_off,
            dexec_size,
            7,
            [("__data_exec", base + dexec_off, dexec_size, dexec_off, 0)],
        ),
        macho_segment("__LINKEDIT", base + 0x3000, 0x1000, link_off, link_size, 1, []),
        struct.pack("<IIIIII", LC_SYMTAB, 24, symoff, 2, stroff, len(strtab.data)),
        struct.pack("<II" + "I" * 18, LC_DYSYMTAB, 80, 0, 0, 0, 0, 0, 2, *([0] * 12)),
        lc_str(LC_LOAD_DYLIB, struct.pack("<IIII", 24, 2, 0x10000, 0x10000), "/usr/lib/libSystem.B.dylib"),
        lc_str(LC_RPATH, struct.pack("<I", 12), "lib/plugins"),
        struct.pack("<IIQQ", LC_MAIN, 24, text_off + 0x10, 0),
        struct.pack("<IIIIII", LC_ENCRYPTION_INFO_64, 24, text_off, text_size, 1, 0),
    ]
    blob = b"".join(cmds)
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        CPU_ARM64,
        0,
        MH_EXECUTE,
        len(cmds),
        len(blob),
        MH_DYLDLINK | MH_TWOLEVEL | MH_ALLOW_STACK_EXECUTION,
        0,
    )
    out = bytearray(header + blob)
    pad_to(out, text_off)
    out += filler_code(text_size)
    pad_to(out, dexec_off)
    out += b"\x00\x01\x02\x03" * (dexec_size // 4)
    pad_to(out, link_off)
    out += linkedit
    pad_to(out, link_off + link_size)
    return out


# --------------------------------------------------------------------------------------
# deliberately malformed inputs


def malformed_truncated_elf() -> bytes:
    return bytes(elf64_hardened()[:40])


def malformed_section_past_eof() -> bytearray:
    data = elf64_hardened()
    # Point .rodata (section index 6) far past the end of the file and make two
    # sections overlap by moving .data onto .text.
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    rodata_hdr = shoff + 6 * 64
    struct.pack_into("<Q", data, rodata_hdr + 0x18, len(data) + 0x10000)
    text_off = struct.unpack_from("<Q", data, shoff + 5 * 64 + 0x18)[0]
    data_hdr = shoff + 8 * 64
    struct.pack_into("<Q", data, data_hdr + 0x18, text_off + 0x10)
    return data


def malformed_absurd_counts_elf() -> bytearray:
    data = elf64_hardened()
    struct.pack_into("<H", data, 0x38, 0x8000)  # e_phnum: 32768 entries, far past EOF
    struct.pack_into("<H", data, 0x3C, 0xFFFE)  # e_shnum
    struct.pack_into("<H", data, 0x3A, 0x1234)  # e_shentsize (inconsistent)
    return data


def malformed_absurd_counts_pe() -> bytearray:
    return build_pe(
        is64=True,
        machine=0x8664,
        characteristics=0x0022,
        dll_chars=DLL_DYNAMIC_BASE | DLL_NX_COMPAT,
        sections=[PeSection(".text", SCN_CODE | SCN_EXEC | SCN_READ, filler_code(0x200))],
        entry=(".text", 0),
        imports=None,
        certificate=None,
        number_of_sections_override=0xFFFF,
    )


def malformed_pe_bad_lfanew() -> bytes:
    out = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x7FFFFFF0))
    out += b"\0" * 64
    return bytes(out)


def malformed_pe_overlap() -> bytearray:
    data = build_pe(
        is64=True,
        machine=0x8664,
        characteristics=0x0022,
        dll_chars=DLL_DYNAMIC_BASE | DLL_NX_COMPAT | DLL_HIGH_ENTROPY_VA,
        sections=[
            PeSection(".text", SCN_CODE | SCN_EXEC | SCN_READ, filler_code(0x400)),
            PeSection(".data", SCN_IDATA | SCN_READ | SCN_WRITE, b"\x42" * 0x200),
        ],
        entry=(".text", 0x10),
        imports=None,
        certificate=None,
    )
    sec_table = 0x80 + 4 + 20 + 240
    text_raw = struct.unpack_from("<I", data, sec_table + 20)[0]
    struct.pack_into("<I", data, sec_table + 40 + 20, text_raw + 0x100)  # .data raw inside .text
    return data


def malformed_macho_ncmds() -> bytes:
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, CPU_ARM64, 0, MH_EXECUTE, 0xFFFFFFFF, 0xFFFFFF00, 0x200085, 0)
    return header + struct.pack("<II", LC_MAIN, 24) + struct.pack("<QQ", 0, 0)


def malformed_fat() -> bytes:
    thin = bytes(macho64_wx())
    slice_off = 0x4000
    header = struct.pack(">II", 0xCAFEBABE, 2)
    header += struct.pack(">iiIII", CPU_ARM64, 0, slice_off, len(thin), 14)
    header += struct.pack(">iiIII", 0x01000007, 3, 0x100000, 0x200000, 14)  # past EOF
    out = bytearray(header)
    pad_to(out, slice_off)
    out += thin
    return bytes(out)


FILES = {
    "elf64_hardened.so": elf64_hardened,
    "elf64_packed_like.elf": elf64_packed_like,
    "elf32_be_ppc.elf": elf32_be,
    "pe64_hardened.exe": pe64_hardened,
    "pe64_packed_like.exe": pe64_packed_like,
    "pe32_ordinal.dll": pe32_dll,
    "macho64_wx_synthetic": macho64_wx,
    "malformed_truncated_header.elf": malformed_truncated_elf,
    "malformed_section_past_eof.elf": malformed_section_past_eof,
    "malformed_absurd_counts.elf": malformed_absurd_counts_elf,
    "malformed_absurd_counts.exe": malformed_absurd_counts_pe,
    "malformed_bad_lfanew.exe": malformed_pe_bad_lfanew,
    "malformed_overlap.exe": malformed_pe_overlap,
    "malformed_ncmds.macho": malformed_macho_ncmds,
    "malformed_fat_past_eof": malformed_fat,
}


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "synthetic"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, builder in FILES.items():
        data = bytes(builder())
        (out_dir / name).write_bytes(data)
        print(f"{name:34s} {len(data):6d} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
