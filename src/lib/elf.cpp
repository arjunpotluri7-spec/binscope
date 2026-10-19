// ELF32/ELF64 parser, both byte orders.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "binscope/entropy.hpp"
#include "parsers.hpp"

namespace binscope::detail {

namespace {

constexpr std::uint16_t ET_REL = 1;
constexpr std::uint16_t ET_EXEC = 2;
constexpr std::uint16_t ET_DYN = 3;
constexpr std::uint16_t ET_CORE = 4;

constexpr std::uint32_t PT_LOAD = 1;
constexpr std::uint32_t PT_DYNAMIC = 2;
constexpr std::uint32_t PT_INTERP = 3;
constexpr std::uint32_t PT_NOTE = 4;
constexpr std::uint32_t PT_PHDR = 6;
constexpr std::uint32_t PT_TLS = 7;
constexpr std::uint32_t PT_GNU_EH_FRAME = 0x6474E550;
constexpr std::uint32_t PT_GNU_STACK = 0x6474E551;
constexpr std::uint32_t PT_GNU_RELRO = 0x6474E552;
constexpr std::uint32_t PT_GNU_PROPERTY = 0x6474E553;

constexpr std::uint32_t PF_X = 1;
constexpr std::uint32_t PF_W = 2;
constexpr std::uint32_t PF_R = 4;

constexpr std::uint32_t SHT_SYMTAB = 2;
constexpr std::uint32_t SHT_STRTAB = 3;
constexpr std::uint32_t SHT_DYNAMIC = 6;
constexpr std::uint32_t SHT_NOTE = 7;
constexpr std::uint32_t SHT_NOBITS = 8;
constexpr std::uint32_t SHT_DYNSYM = 11;

constexpr std::uint64_t SHF_WRITE = 1;
constexpr std::uint64_t SHF_ALLOC = 2;
constexpr std::uint64_t SHF_EXECINSTR = 4;

constexpr std::uint16_t PN_XNUM = 0xFFFF;
constexpr std::uint16_t SHN_XINDEX = 0xFFFF;

constexpr std::int64_t DT_NULL = 0;
constexpr std::int64_t DT_NEEDED = 1;
constexpr std::int64_t DT_STRTAB = 5;
constexpr std::int64_t DT_STRSZ = 10;
constexpr std::int64_t DT_RPATH = 15;
constexpr std::int64_t DT_BIND_NOW = 24;
constexpr std::int64_t DT_RUNPATH = 29;
constexpr std::int64_t DT_FLAGS = 30;
constexpr std::int64_t DT_FLAGS_1 = 0x6FFFFFFB;
constexpr std::uint64_t DF_BIND_NOW = 0x8;
constexpr std::uint64_t DF_1_NOW = 0x1;
constexpr std::uint64_t DF_1_PIE = 0x08000000;

constexpr std::uint64_t kMaxStringLength = 4096;

struct RawSection {
    std::uint32_t name = 0;
    std::uint32_t type = 0;
    std::uint64_t flags = 0;
    std::uint64_t addr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t link = 0;
    std::uint32_t info = 0;
    std::uint64_t entsize = 0;
};

struct RawSegment {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
};

std::string machine_name(std::uint16_t machine) {
    switch (machine) {
        case 0x03:
            return "x86";
        case 0x08:
            return "mips";
        case 0x14:
            return "ppc";
        case 0x15:
            return "ppc64";
        case 0x16:
            return "s390";
        case 0x28:
            return "arm";
        case 0x2B:
            return "sparcv9";
        case 0x3E:
            return "x86_64";
        case 0xB7:
            return "aarch64";
        case 0xF3:
            return "riscv";
        case 0x102:
            return "loongarch";
        default:
            return "machine-" + hex(machine);
    }
}

std::string segment_type_name(std::uint32_t type) {
    switch (type) {
        case 0:
            return "PT_NULL";
        case PT_LOAD:
            return "PT_LOAD";
        case PT_DYNAMIC:
            return "PT_DYNAMIC";
        case PT_INTERP:
            return "PT_INTERP";
        case PT_NOTE:
            return "PT_NOTE";
        case PT_PHDR:
            return "PT_PHDR";
        case PT_TLS:
            return "PT_TLS";
        case PT_GNU_EH_FRAME:
            return "PT_GNU_EH_FRAME";
        case PT_GNU_STACK:
            return "PT_GNU_STACK";
        case PT_GNU_RELRO:
            return "PT_GNU_RELRO";
        case PT_GNU_PROPERTY:
            return "PT_GNU_PROPERTY";
        default:
            return "PT_" + hex(type);
    }
}

std::string section_type_name(std::uint32_t type) {
    switch (type) {
        case 0:
            return "SHT_NULL";
        case 1:
            return "SHT_PROGBITS";
        case SHT_SYMTAB:
            return "SHT_SYMTAB";
        case SHT_STRTAB:
            return "SHT_STRTAB";
        case 4:
            return "SHT_RELA";
        case 5:
            return "SHT_HASH";
        case SHT_DYNAMIC:
            return "SHT_DYNAMIC";
        case SHT_NOTE:
            return "SHT_NOTE";
        case SHT_NOBITS:
            return "SHT_NOBITS";
        case 9:
            return "SHT_REL";
        case SHT_DYNSYM:
            return "SHT_DYNSYM";
        case 14:
            return "SHT_INIT_ARRAY";
        case 15:
            return "SHT_FINI_ARRAY";
        case 0x6FFFFFF6:
            return "SHT_GNU_HASH";
        default:
            return "SHT_" + hex(type);
    }
}

std::string hex_bytes(ByteView bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes.span()) {
        out.push_back(kDigits[b >> 4U]);
        out.push_back(kDigits[b & 0xFU]);
    }
    return out;
}

/// Walks an ELF note area looking for the GNU build-id note (type 3, name "GNU").
std::optional<std::string> find_build_id(ByteView notes, Endian endian) {
    std::uint64_t pos = 0;
    for (int guard = 0; guard < 64 && notes.contains(pos, 12); ++guard) {
        StructReader r(notes, pos, endian);
        const std::uint32_t namesz = r.u32();
        const std::uint32_t descsz = r.u32();
        const std::uint32_t type = r.u32();
        if (!r.ok()) {
            return std::nullopt;
        }
        const std::uint64_t name_off = pos + 12;
        const std::uint64_t desc_off =
            name_off + ((static_cast<std::uint64_t>(namesz) + 3U) & ~3ULL);
        const auto next = checked_add(desc_off, (static_cast<std::uint64_t>(descsz) + 3U) & ~3ULL);
        if (!next || !notes.contains(desc_off, descsz)) {
            return std::nullopt;
        }
        const auto name = notes.fixed_string(name_off, namesz);
        if (type == 3 && name && *name == "GNU" && descsz > 0 && descsz <= 64) {
            const auto desc = notes.sub(desc_off, descsz);
            if (desc) {
                return hex_bytes(*desc);
            }
        }
        pos = *next;
    }
    return std::nullopt;
}

class ElfParser {
public:
    ElfParser(ByteView image, const Limits& limits) : img_(image), limits_(limits) {}

    Target run();

private:
    bool read_header();
    void read_program_headers();
    void read_section_headers();
    void read_dynamic();
    void read_dynamic_symbols();
    void read_build_id();
    void derive_hardening();

    [[nodiscard]] std::optional<std::uint64_t> vaddr_to_offset(std::uint64_t vaddr) const;
    [[nodiscard]] Result<std::string> string_at(ByteView table, std::uint64_t offset) const;

    ByteView img_;
    const Limits& limits_;
    Target t_;
    Endian e_ = Endian::little;
    bool is64_ = false;
    std::uint16_t type_ = 0;
    std::uint64_t entry_ = 0;
    std::uint64_t phoff_ = 0;
    std::uint64_t shoff_ = 0;
    std::uint16_t phentsize_ = 0;
    std::uint32_t phnum_ = 0;
    std::uint16_t shentsize_ = 0;
    std::uint32_t shnum_ = 0;
    std::uint32_t shstrndx_ = 0;
    std::vector<RawSegment> segs_;
    std::vector<RawSection> secs_;  // index 0 is the null section when present
    std::optional<std::string> interp_;
    std::optional<std::uint32_t> gnu_stack_flags_;
    bool phdrs_readable_ = true;
    bool relro_ = false;
    bool has_dynamic_ = false;
    bool bind_now_ = false;
    bool flag_pie_ = false;
};

Target ElfParser::run() {
    t_.format = Format::elf;
    t_.format_name = "ELF";
    t_.size = img_.size();
    t_.entropy = shannon_entropy(img_.span());
    if (!read_header()) {
        return t_;
    }
    read_program_headers();
    read_section_headers();
    read_dynamic();
    read_dynamic_symbols();
    read_build_id();
    derive_hardening();
    for (auto& s : t_.sections) {
        finish_region(s, img_);
    }
    for (auto& s : t_.segments) {
        finish_region(s, img_);
    }
    return t_;
}

bool ElfParser::read_header() {
    const auto cls = img_.u8(4);
    const auto data = img_.u8(5);
    if (!cls || !data || img_.size() < 16) {
        add_issue(
            t_, IssueKind::malformed,
            "ELF identification is truncated (" + std::to_string(img_.size()) + " bytes, need 16)");
        return false;
    }
    if (*cls != 1 && *cls != 2) {
        add_issue(t_, IssueKind::malformed, "unknown ELF class " + std::to_string(*cls), 4);
        return false;
    }
    if (*data != 1 && *data != 2) {
        add_issue(t_, IssueKind::malformed, "unknown ELF data encoding " + std::to_string(*data),
                  5);
        return false;
    }
    is64_ = *cls == 2;
    e_ = *data == 1 ? Endian::little : Endian::big;
    t_.bits = is64_ ? 64 : 32;
    t_.endian = e_;
    t_.format_name = is64_ ? "ELF64" : "ELF32";
    const std::uint64_t ehsize = is64_ ? 64 : 52;
    if (img_.size() < ehsize) {
        add_issue(t_, IssueKind::malformed,
                  "ELF header is truncated: file has " + std::to_string(img_.size()) +
                      " bytes, the header needs " + std::to_string(ehsize));
        return false;
    }
    StructReader r(img_, 16, e_);
    type_ = r.u16();
    const std::uint16_t machine = r.u16();
    r.u32();  // e_version
    entry_ = r.word(is64_);
    phoff_ = r.word(is64_);
    shoff_ = r.word(is64_);
    r.u32();  // e_flags
    const std::uint16_t e_ehsize = r.u16();
    phentsize_ = r.u16();
    phnum_ = r.u16();
    shentsize_ = r.u16();
    shnum_ = r.u16();
    shstrndx_ = r.u16();
    if (!r.ok()) {
        add_issue(t_, IssueKind::malformed, "ELF header is truncated", r.error().offset);
        return false;
    }
    t_.arch = machine_name(machine);
    switch (type_) {
        case ET_REL:
            t_.file_type = "relocatable object";
            break;
        case ET_EXEC:
            t_.file_type = "executable";
            break;
        case ET_DYN:
            t_.file_type = "shared object";
            break;
        case ET_CORE:
            t_.file_type = "core dump";
            break;
        default:
            t_.file_type = "type " + hex(type_);
            break;
    }
    if (e_ehsize != ehsize) {
        add_issue(
            t_, IssueKind::malformed,
            "e_ehsize is " + std::to_string(e_ehsize) + ", expected " + std::to_string(ehsize),
            is64_ ? 0x34 : 0x28);
    }
    return true;
}

void ElfParser::read_program_headers() {
    const std::uint16_t expected = is64_ ? 56 : 32;
    if (phnum_ == PN_XNUM) {
        // The real count lives in sh_info of section header 0.
        const std::uint64_t info_off = shoff_ + (is64_ ? 44 : 28);
        const auto real = img_.u32(info_off, e_);
        if (shoff_ != 0 && real) {
            phnum_ = *real;
        } else {
            add_issue(t_, IssueKind::malformed,
                      "e_phnum is PN_XNUM but section header 0 is unreadable", shoff_);
            phnum_ = 0;
        }
    }
    if (phnum_ == 0) {
        return;
    }
    if (phentsize_ != expected) {
        add_issue(t_, IssueKind::malformed,
                  "e_phentsize is " + std::to_string(phentsize_) + ", expected " +
                      std::to_string(expected) + "; program headers ignored");
        phdrs_readable_ = false;
        return;
    }
    std::uint64_t count = phnum_;
    if (count > limits_.max_sections) {
        add_issue(t_, IssueKind::limit,
                  "program header count " + std::to_string(count) + " exceeds the limit of " +
                      std::to_string(limits_.max_sections) + "; parsing stops there");
        count = limits_.max_sections;
    }
    const auto table = checked_mul(count, expected);
    if (!table || !img_.contains(phoff_, *table)) {
        add_issue(t_, IssueKind::out_of_bounds,
                  "program header table (" + std::to_string(phnum_) + " entries at offset " +
                      hex(phoff_) + ") extends past the end of the file",
                  phoff_);
        count = records_that_fit(phoff_, expected, count, img_.size());
    }
    for (std::uint64_t i = 0; i < count; ++i) {
        StructReader r(img_, phoff_ + i * expected, e_);
        RawSegment s;
        s.type = r.u32();
        if (is64_) {
            s.flags = r.u32();
            s.offset = r.u64();
            s.vaddr = r.u64();
            r.u64();  // p_paddr
            s.filesz = r.u64();
            s.memsz = r.u64();
        } else {
            s.offset = r.u32();
            s.vaddr = r.u32();
            r.u32();  // p_paddr
            s.filesz = r.u32();
            s.memsz = r.u32();
            s.flags = r.u32();
        }
        if (!r.ok()) {
            break;
        }
        segs_.push_back(s);

        Region reg;
        reg.kind = "segment";
        reg.type = segment_type_name(s.type);
        reg.name = reg.type.substr(3) + "[" + std::to_string(i) + "]";
        reg.offset = s.offset;
        reg.file_size = s.filesz;
        reg.vaddr = s.vaddr;
        reg.mem_size = s.memsz;
        reg.raw_flags = s.flags;
        reg.readable = (s.flags & PF_R) != 0;
        reg.writable = (s.flags & PF_W) != 0;
        reg.executable = (s.flags & PF_X) != 0;
        reg.has_file_data = s.filesz > 0;
        reg.allocated = s.type == PT_LOAD;
        t_.segments.push_back(reg);

        if (s.type == PT_INTERP) {
            const auto path =
                img_.cstring(s.offset, s.filesz < kMaxStringLength ? s.filesz : kMaxStringLength);
            if (path) {
                interp_ = printable(*path);
            } else {
                add_issue(t_, IssueKind::out_of_bounds, "PT_INTERP path is unreadable", s.offset);
            }
        } else if (s.type == PT_GNU_STACK) {
            gnu_stack_flags_ = s.flags;
        } else if (s.type == PT_GNU_RELRO) {
            relro_ = true;
        }
    }
}

void ElfParser::read_section_headers() {
    if (shoff_ == 0) {
        set_property(t_, "section_headers", false);
        if (shnum_ != 0) {
            add_issue(t_, IssueKind::malformed, "e_shnum is non-zero but e_shoff is 0");
        }
        return;
    }
    const std::uint16_t expected = is64_ ? 64 : 40;
    if (shentsize_ != expected) {
        add_issue(t_, IssueKind::malformed,
                  "e_shentsize is " + std::to_string(shentsize_) + ", expected " +
                      std::to_string(expected) + "; section headers ignored");
        return;
    }
    if (shnum_ == 0 || shstrndx_ == SHN_XINDEX) {
        // Extended numbering: section header 0 carries the real values.
        StructReader r(img_, shoff_, e_);
        r.skip(is64_ ? 32 : 20);
        const std::uint64_t size = r.word(is64_);
        const std::uint32_t link = r.u32();
        if (!r.ok()) {
            add_issue(t_, IssueKind::out_of_bounds, "section header 0 is outside the file", shoff_);
            return;
        }
        if (shnum_ == 0) {
            shnum_ = size > 0xFFFFFFFFULL ? 0xFFFFFFFFU : static_cast<std::uint32_t>(size);
        }
        if (shstrndx_ == SHN_XINDEX) {
            shstrndx_ = link;
        }
    }
    std::uint64_t count = shnum_;
    if (count > limits_.max_sections) {
        add_issue(t_, IssueKind::limit,
                  "section count " + std::to_string(count) + " exceeds the limit of " +
                      std::to_string(limits_.max_sections) + "; parsing stops there");
        count = limits_.max_sections;
    }
    const auto table = checked_mul(count, expected);
    if (!table || !img_.contains(shoff_, *table)) {
        add_issue(t_, IssueKind::out_of_bounds,
                  "section header table (" + std::to_string(shnum_) + " entries at offset " +
                      hex(shoff_) + ") extends past the end of the file",
                  shoff_);
        count = records_that_fit(shoff_, expected, count, img_.size());
    }
    for (std::uint64_t i = 0; i < count; ++i) {
        StructReader r(img_, shoff_ + i * expected, e_);
        RawSection s;
        s.name = r.u32();
        s.type = r.u32();
        s.flags = r.word(is64_);
        s.addr = r.word(is64_);
        s.offset = r.word(is64_);
        s.size = r.word(is64_);
        s.link = r.u32();
        s.info = r.u32();
        r.word(is64_);  // sh_addralign
        s.entsize = r.word(is64_);
        if (!r.ok()) {
            break;
        }
        secs_.push_back(s);
    }

    ByteView names;
    if (shstrndx_ < secs_.size() && secs_[shstrndx_].type == SHT_STRTAB) {
        names = img_.clamp(secs_[shstrndx_].offset, secs_[shstrndx_].size);
    } else if (!secs_.empty()) {
        add_issue(t_, IssueKind::malformed,
                  "e_shstrndx " + std::to_string(shstrndx_) +
                      " does not name a string table; section names unavailable");
    }
    bool reported_bad_name = false;
    for (std::size_t i = 1; i < secs_.size(); ++i) {
        const auto& s = secs_[i];
        Region reg;
        reg.kind = "section";
        reg.type = section_type_name(s.type);
        auto name =
            names.empty() ? Result<std::string>(make_error("no names")) : string_at(names, s.name);
        if (name) {
            reg.name = printable(*name);
        } else {
            reg.name = "<section " + std::to_string(i) + ">";
            if (!names.empty() && !reported_bad_name) {
                add_issue(t_, IssueKind::out_of_bounds,
                          "section " + std::to_string(i) + " name offset " +
                              std::to_string(s.name) + " is outside the section name table");
                reported_bad_name = true;
            }
        }
        reg.offset = s.offset;
        reg.file_size = s.type == SHT_NOBITS ? 0 : s.size;
        reg.vaddr = s.addr;
        reg.mem_size = s.size;
        reg.raw_flags = s.flags;
        reg.allocated = (s.flags & SHF_ALLOC) != 0;
        reg.readable = reg.allocated;
        reg.writable = (s.flags & SHF_WRITE) != 0;
        reg.executable = (s.flags & SHF_EXECINSTR) != 0;
        reg.has_file_data = s.type != SHT_NOBITS;
        t_.sections.push_back(reg);

        if (s.type == SHT_SYMTAB || s.type == SHT_DYNSYM) {
            const std::uint64_t entsize = is64_ ? 24 : 16;
            set_property(t_, s.type == SHT_SYMTAB ? "symtab_symbols" : "dynsym_symbols",
                         s.size / entsize);
        }
    }
    set_property(t_, "section_headers", !secs_.empty());
}

Result<std::string> ElfParser::string_at(ByteView table, std::uint64_t offset) const {
    return table.cstring(offset, kMaxStringLength);
}

std::optional<std::uint64_t> ElfParser::vaddr_to_offset(std::uint64_t vaddr) const {
    for (const auto& s : segs_) {
        if (s.type != PT_LOAD) {
            continue;
        }
        const auto end = checked_add(s.vaddr, s.filesz);
        if (end && vaddr >= s.vaddr && vaddr < *end) {
            return checked_add(s.offset, vaddr - s.vaddr);
        }
    }
    return std::nullopt;
}

void ElfParser::read_dynamic() {
    std::optional<std::uint64_t> dyn_off;
    std::uint64_t dyn_size = 0;
    std::optional<std::uint32_t> link;
    for (const auto& s : secs_) {
        if (s.type == SHT_DYNAMIC) {
            dyn_off = s.offset;
            dyn_size = s.size;
            link = s.link;
            break;
        }
    }
    if (!dyn_off) {
        for (const auto& s : segs_) {
            if (s.type == PT_DYNAMIC) {
                dyn_off = s.offset;
                dyn_size = s.filesz;
                break;
            }
        }
    }
    if (!dyn_off) {
        return;
    }
    has_dynamic_ = true;
    const std::uint64_t entsize = is64_ ? 16 : 8;
    std::uint64_t count = dyn_size / entsize;
    const ByteView dyn = img_.clamp(*dyn_off, dyn_size);
    if (dyn.size() < dyn_size) {
        add_issue(t_, IssueKind::out_of_bounds, "dynamic section extends past the end of the file",
                  *dyn_off);
        count = dyn.size() / entsize;
    }
    if (count > limits_.max_dynamic) {
        add_issue(t_, IssueKind::limit,
                  "dynamic section has " + std::to_string(count) + " entries; only the first " +
                      std::to_string(limits_.max_dynamic) + " were read");
        count = limits_.max_dynamic;
    }

    std::vector<std::uint64_t> needed;
    std::vector<std::uint64_t> rpath;
    std::vector<std::uint64_t> runpath;
    std::optional<std::uint64_t> strtab_addr;
    std::optional<std::uint64_t> strsz;
    std::uint64_t flags = 0;
    std::uint64_t flags1 = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        StructReader r(dyn, i * entsize, e_);
        const auto tag = static_cast<std::int64_t>(
            is64_ ? r.u64() : static_cast<std::uint64_t>(static_cast<std::int32_t>(r.u32())));
        const std::uint64_t val = r.word(is64_);
        if (!r.ok() || tag == DT_NULL) {
            break;
        }
        switch (tag) {
            case DT_NEEDED:
                needed.push_back(val);
                break;
            case DT_RPATH:
                rpath.push_back(val);
                break;
            case DT_RUNPATH:
                runpath.push_back(val);
                break;
            case DT_STRTAB:
                strtab_addr = val;
                break;
            case DT_STRSZ:
                strsz = val;
                break;
            case DT_BIND_NOW:
                bind_now_ = true;
                break;
            case DT_FLAGS:
                flags = val;
                break;
            case DT_FLAGS_1:
                flags1 = val;
                break;
            default:
                break;
        }
    }
    if ((flags & DF_BIND_NOW) != 0 || (flags1 & DF_1_NOW) != 0) {
        bind_now_ = true;
    }
    flag_pie_ = (flags1 & DF_1_PIE) != 0;
    set_property(t_, "dt_flags", hex(flags));
    set_property(t_, "dt_flags_1", hex(flags1));

    // Prefer the string table the section headers link to; fall back to mapping
    // DT_STRTAB through the PT_LOAD segments for files without section headers.
    ByteView strtab;
    if (link && *link < secs_.size()) {
        strtab = img_.clamp(secs_[*link].offset, secs_[*link].size);
    } else if (strtab_addr) {
        const auto off = vaddr_to_offset(*strtab_addr);
        if (off) {
            strtab = img_.clamp(*off, strsz.value_or(img_.size()));
        }
    }
    if (strtab.empty() && (!needed.empty() || !rpath.empty() || !runpath.empty())) {
        add_issue(t_, IssueKind::out_of_bounds, "dynamic string table could not be located",
                  *dyn_off);
        return;
    }
    auto resolve = [&](std::uint64_t off, const char* what) -> std::optional<std::string> {
        const auto s = strtab.cstring(off, kMaxStringLength);
        if (!s) {
            add_issue(t_, IssueKind::out_of_bounds,
                      std::string(what) + " string offset " + std::to_string(off) +
                          " is outside the dynamic string table");
            return std::nullopt;
        }
        return printable(*s);
    };
    for (const auto off : needed) {
        if (t_.libraries.size() >= limits_.max_libraries) {
            add_issue(t_, IssueKind::limit,
                      "more than " + std::to_string(limits_.max_libraries) +
                          " DT_NEEDED entries; the rest were ignored");
            break;
        }
        if (auto name = resolve(off, "DT_NEEDED")) {
            t_.libraries.push_back(ImportedLibrary{*name, {}});
        }
    }
    auto add_paths = [&](const std::vector<std::uint64_t>& offs, const char* what,
                         const char* key) {
        for (const auto off : offs) {
            if (auto value = resolve(off, what)) {
                set_property(t_, key, *value);
                std::size_t start = 0;
                while (start <= value->size()) {
                    const auto colon = value->find(':', start);
                    const auto part = value->substr(
                        start, colon == std::string::npos ? std::string::npos : colon - start);
                    t_.rpaths.push_back(part);  // an empty entry means the current directory
                    if (colon == std::string::npos) {
                        break;
                    }
                    start = colon + 1;
                }
            }
        }
    };
    add_paths(rpath, "DT_RPATH", "rpath");
    add_paths(runpath, "DT_RUNPATH", "runpath");
}

void ElfParser::read_dynamic_symbols() {
    for (const auto& s : secs_) {
        if (s.type != SHT_DYNSYM) {
            continue;
        }
        const std::uint64_t entsize = is64_ ? 24 : 16;
        if (s.link >= secs_.size()) {
            add_issue(t_, IssueKind::malformed, ".dynsym links to a missing string table");
            return;
        }
        const ByteView strtab = img_.clamp(secs_[s.link].offset, secs_[s.link].size);
        const ByteView table = img_.clamp(s.offset, s.size);
        std::uint64_t count = table.size() / entsize;
        if (count > limits_.max_symbols) {
            add_issue(
                t_, IssueKind::limit,
                "dynamic symbol count exceeds the limit of " + std::to_string(limits_.max_symbols));
            count = limits_.max_symbols;
        }
        for (std::uint64_t i = 1; i < count; ++i) {
            StructReader r(table, i * entsize, e_);
            const std::uint32_t name = r.u32();
            std::uint16_t shndx = 0;
            if (is64_) {
                r.u8();  // st_info
                r.u8();  // st_other
                shndx = r.u16();
            } else {
                r.u32();  // st_value
                r.u32();  // st_size
                r.u8();
                r.u8();
                shndx = r.u16();
            }
            if (!r.ok()) {
                break;
            }
            if (shndx != 0 || name == 0) {
                continue;
            }
            if (t_.unbound_imports.size() >= limits_.max_imports) {
                add_issue(t_, IssueKind::limit,
                          "more than " + std::to_string(limits_.max_imports) +
                              " imported symbols; the rest were ignored");
                break;
            }
            const auto text = strtab.cstring(name, kMaxStringLength);
            if (text) {
                t_.unbound_imports.push_back(printable(*text));
            }
        }
        t_.import_count = t_.unbound_imports.size();
        return;
    }
}

void ElfParser::read_build_id() {
    for (std::size_t i = 1; i < secs_.size(); ++i) {
        if (t_.sections.size() >= i && t_.sections[i - 1].name == ".note.gnu.build-id") {
            set_property(t_, "build_id_section", true);
            if (auto id = find_build_id(img_.clamp(secs_[i].offset, secs_[i].size), e_)) {
                set_property(t_, "build_id", *id);
            }
            return;
        }
    }
    set_property(t_, "build_id_section", false);
    for (const auto& s : segs_) {
        if (s.type == PT_NOTE) {
            if (auto id = find_build_id(img_.clamp(s.offset, s.filesz), e_)) {
                set_property(t_, "build_id", *id);
                return;
            }
        }
    }
}

void ElfParser::derive_hardening() {
    const bool pie_exec = type_ == ET_DYN && (interp_.has_value() || flag_pie_);
    if (pie_exec) {
        t_.file_type = "PIE executable";
    } else if (type_ == ET_DYN) {
        t_.file_type = "shared library";
    }
    const bool runnable = type_ == ET_EXEC || type_ == ET_DYN;
    t_.expects_entry = type_ == ET_EXEC || pie_exec;
    if (entry_ != 0 || t_.expects_entry) {
        t_.entry = entry_;
    }
    if (interp_) {
        set_property(t_, "interpreter", *interp_);
    }

    HardeningFlag pie{"pie", "Position independent (PIE)", std::nullopt, ""};
    if (type_ == ET_EXEC) {
        pie.enabled = false;
        pie.detail = "ET_EXEC: loads at a fixed address, so ASLR cannot move it";
    } else if (pie_exec) {
        pie.enabled = true;
        pie.detail = "ET_DYN with an interpreter";
    } else {
        pie.detail = "not applicable to this file type";
    }
    t_.hardening.push_back(pie);

    HardeningFlag nx{"nx_stack", "Non-executable stack", std::nullopt, ""};
    if (runnable && !phdrs_readable_) {
        nx.detail = "program headers unreadable";
    } else if (runnable) {
        if (gnu_stack_flags_) {
            nx.enabled = (*gnu_stack_flags_ & PF_X) == 0;
            nx.detail = nx.enabled.value_or(false) ? "PT_GNU_STACK is RW" : "PT_GNU_STACK has PF_X";
        } else {
            nx.enabled = false;
            nx.detail = "no PT_GNU_STACK header; many loaders then default to an executable stack";
        }
    } else {
        nx.detail = "not applicable to this file type";
    }
    t_.hardening.push_back(nx);

    HardeningFlag relro{"relro", "RELRO (read-only relocations)", std::nullopt, ""};
    HardeningFlag now{"bind_now", "BIND_NOW (no lazy binding)", std::nullopt, ""};
    if (runnable && !phdrs_readable_) {
        relro.detail = "program headers unreadable";
        now.detail = relro.detail;
    } else if (runnable) {
        relro.enabled = relro_;
        relro.detail = relro_ ? (bind_now_ ? "full RELRO" : "partial RELRO") : "no PT_GNU_RELRO";
        if (has_dynamic_) {
            now.enabled = bind_now_;
            now.detail = bind_now_ ? "DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW set" : "lazy binding";
        } else {
            now.detail = "no dynamic section (statically linked)";
        }
    } else {
        relro.detail = "not applicable to this file type";
        now.detail = relro.detail;
    }
    t_.hardening.push_back(relro);
    t_.hardening.push_back(now);
    set_property(t_, "relro", !relro_ ? "none" : (bind_now_ ? "full" : "partial"));
}

}  // namespace

Target parse_elf(ByteView image, const Limits& limits) {
    ElfParser parser(image, limits);
    return parser.run();
}

}  // namespace binscope::detail
