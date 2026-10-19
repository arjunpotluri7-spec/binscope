// Mach-O parser: thin 32/64-bit images in either byte order, plus universal (fat) files.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "binscope/entropy.hpp"
#include "parsers.hpp"

namespace binscope::detail {

namespace {

constexpr std::uint32_t MH_EXECUTE = 2;
constexpr std::uint32_t MH_DYLIB = 6;
constexpr std::uint32_t MH_BUNDLE = 8;

constexpr std::uint32_t MH_PIE = 0x200000;
constexpr std::uint32_t MH_ALLOW_STACK_EXECUTION = 0x20000;
constexpr std::uint32_t MH_NO_HEAP_EXECUTION = 0x1000000;

constexpr std::uint32_t LC_REQ_DYLD = 0x80000000;
constexpr std::uint32_t LC_SEGMENT = 0x1;
constexpr std::uint32_t LC_SYMTAB = 0x2;
constexpr std::uint32_t LC_UNIXTHREAD = 0x5;
constexpr std::uint32_t LC_DYSYMTAB = 0xB;
constexpr std::uint32_t LC_LOAD_DYLIB = 0xC;
constexpr std::uint32_t LC_ID_DYLIB = 0xD;
constexpr std::uint32_t LC_LOAD_DYLINKER = 0xE;
constexpr std::uint32_t LC_LOAD_WEAK_DYLIB = 0x18U | LC_REQ_DYLD;
constexpr std::uint32_t LC_SEGMENT_64 = 0x19;
constexpr std::uint32_t LC_UUID = 0x1B;
constexpr std::uint32_t LC_RPATH = 0x1CU | LC_REQ_DYLD;
constexpr std::uint32_t LC_CODE_SIGNATURE = 0x1D;
constexpr std::uint32_t LC_REEXPORT_DYLIB = 0x1FU | LC_REQ_DYLD;
constexpr std::uint32_t LC_LAZY_LOAD_DYLIB = 0x20;
constexpr std::uint32_t LC_ENCRYPTION_INFO = 0x21;
constexpr std::uint32_t LC_LOAD_UPWARD_DYLIB = 0x23U | LC_REQ_DYLD;
constexpr std::uint32_t LC_VERSION_MIN_MACOSX = 0x24;
constexpr std::uint32_t LC_MAIN = 0x28U | LC_REQ_DYLD;
constexpr std::uint32_t LC_ENCRYPTION_INFO_64 = 0x2C;
constexpr std::uint32_t LC_BUILD_VERSION = 0x32;

constexpr std::uint32_t VM_PROT_READ = 1;
constexpr std::uint32_t VM_PROT_WRITE = 2;
constexpr std::uint32_t VM_PROT_EXECUTE = 4;

constexpr std::uint32_t S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
constexpr std::uint32_t S_ATTR_SOME_INSTRUCTIONS = 0x400;

constexpr std::uint32_t CPU_TYPE_X86 = 7;
constexpr std::uint32_t CPU_TYPE_ARM = 12;
constexpr std::uint32_t CPU_TYPE_PPC = 18;
constexpr std::uint32_t CPU_ARCH_ABI64 = 0x01000000;
constexpr std::uint32_t CPU_ARCH_ABI64_32 = 0x02000000;

constexpr std::uint64_t kMaxStringLength = 4096;

std::string cpu_name(std::uint32_t cputype, std::uint32_t subtype) {
    switch (cputype) {
        case CPU_TYPE_X86:
            return "i386";
        case CPU_TYPE_X86 | CPU_ARCH_ABI64:
            return (subtype & 0xFFU) == 8 ? "x86_64h" : "x86_64";
        case CPU_TYPE_ARM:
            return "arm";
        case CPU_TYPE_ARM | CPU_ARCH_ABI64:
            return (subtype & 0xFFU) == 2 ? "arm64e" : "arm64";
        case CPU_TYPE_ARM | CPU_ARCH_ABI64_32:
            return "arm64_32";
        case CPU_TYPE_PPC:
            return "ppc";
        case CPU_TYPE_PPC | CPU_ARCH_ABI64:
            return "ppc64";
        default:
            return "cpu-" + hex(cputype);
    }
}

std::string filetype_name(std::uint32_t type) {
    switch (type) {
        case 1:
            return "object";
        case MH_EXECUTE:
            return "executable";
        case 4:
            return "core";
        case 5:
            return "preload";
        case MH_DYLIB:
            return "dylib";
        case 7:
            return "dylinker";
        case MH_BUNDLE:
            return "bundle";
        case 9:
            return "dylib stub";
        case 10:
            return "dSYM companion";
        case 11:
            return "kext bundle";
        case 12:
            return "fileset";
        default:
            return "type " + hex(type);
    }
}

std::string section_type_name(std::uint32_t flags) {
    switch (flags & 0xFFU) {
        case 0x0:
            return "regular";
        case 0x1:
            return "zerofill";
        case 0x2:
            return "cstring_literals";
        case 0x6:
            return "non_lazy_symbol_pointers";
        case 0x7:
            return "lazy_symbol_pointers";
        case 0x8:
            return "symbol_stubs";
        case 0x9:
            return "mod_init_func_pointers";
        case 0xC:
            return "gb_zerofill";
        case 0x12:
            return "thread_local_zerofill";
        default:
            return "type " + hex(flags & 0xFFU);
    }
}

bool is_zerofill(std::uint32_t flags) {
    const auto type = flags & 0xFFU;
    return type == 0x1 || type == 0xC || type == 0x12;
}

std::string version_string(std::uint32_t v) {
    return std::to_string(v >> 16U) + "." + std::to_string((v >> 8U) & 0xFFU) + "." +
           std::to_string(v & 0xFFU);
}

class MachoParser {
public:
    MachoParser(ByteView image, const Limits& limits) : img_(image), limits_(limits) {}
    Target run();

private:
    void on_segment(ByteView cmd, bool seg64);
    void on_dylib(ByteView cmd, std::uint32_t type);
    void on_thread(ByteView cmd);
    void read_symbols();
    void derive();
    std::optional<std::string> lc_string(ByteView cmd, const char* what);

    ByteView img_;
    const Limits& limits_;
    Target t_;
    Endian e_ = Endian::little;
    bool is64_ = false;
    std::uint32_t cputype_ = 0;
    std::uint32_t filetype_ = 0;
    std::uint32_t flags_ = 0;
    std::optional<std::uint64_t> main_offset_;
    std::optional<std::uint64_t> thread_pc_;
    bool code_signature_ = false;
    std::optional<std::uint32_t> cryptid_;
    std::optional<std::uint32_t> symoff_, nsyms_, stroff_, strsize_;
    std::optional<std::uint32_t> iundef_, nundef_;
    std::uint64_t section_count_ = 0;
    bool section_limit_reported_ = false;
};

std::optional<std::string> MachoParser::lc_string(ByteView cmd, const char* what) {
    const auto off = cmd.u32(8, e_);
    if (!off || *off < 12 || *off >= cmd.size()) {
        add_issue(t_, IssueKind::malformed, std::string(what) + " string offset is invalid");
        return std::nullopt;
    }
    const auto s = cmd.cstring(*off, kMaxStringLength);
    if (!s) {
        add_issue(t_, IssueKind::malformed, std::string(what) + " string is not terminated");
        return std::nullopt;
    }
    return printable(*s);
}

Target MachoParser::run() {
    t_.format = Format::macho;
    t_.format_name = "Mach-O";
    t_.size = img_.size();
    t_.entropy = shannon_entropy(img_.span());
    const auto magic = img_.u32(0, Endian::little);
    if (!magic) {
        add_issue(t_, IssueKind::malformed, "Mach-O header is truncated");
        return t_;
    }
    is64_ = *magic == 0xFEEDFACFU || *magic == 0xCFFAEDFEU;
    e_ = (*magic == 0xFEEDFACEU || *magic == 0xFEEDFACFU) ? Endian::little : Endian::big;
    t_.bits = is64_ ? 64 : 32;
    t_.endian = e_;
    t_.format_name = is64_ ? "Mach-O 64-bit" : "Mach-O 32-bit";
    const std::uint64_t header_size = is64_ ? 32 : 28;
    if (img_.size() < header_size) {
        add_issue(t_, IssueKind::malformed,
                  "Mach-O header is truncated: " + std::to_string(img_.size()) +
                      " bytes, the header needs " + std::to_string(header_size));
        return t_;
    }
    StructReader r(img_, 4, e_);
    cputype_ = r.u32();
    const std::uint32_t subtype = r.u32();
    filetype_ = r.u32();
    std::uint64_t ncmds = r.u32();
    const std::uint32_t sizeofcmds = r.u32();
    flags_ = r.u32();
    if (!r.ok()) {
        add_issue(t_, IssueKind::malformed, "Mach-O header is truncated");
        return t_;
    }
    t_.arch = cpu_name(cputype_, subtype);
    t_.file_type = filetype_name(filetype_);
    t_.expects_entry = filetype_ == MH_EXECUTE;
    set_property(t_, "mh_flags", hex(flags_));
    set_property(t_, "ncmds", ncmds);

    std::uint64_t cmds_end = header_size + static_cast<std::uint64_t>(sizeofcmds);
    if (cmds_end > img_.size()) {
        add_issue(t_, IssueKind::out_of_bounds,
                  "load commands (sizeofcmds " + std::to_string(sizeofcmds) +
                      ") extend past the end of the file",
                  header_size);
        cmds_end = img_.size();
    }
    if (ncmds > limits_.max_load_commands) {
        add_issue(t_, IssueKind::limit,
                  "ncmds " + std::to_string(ncmds) + " exceeds the limit of " +
                      std::to_string(limits_.max_load_commands) + "; parsing stops there");
        ncmds = limits_.max_load_commands;
    }
    std::uint64_t pos = header_size;
    for (std::uint64_t i = 0; i < ncmds; ++i) {
        if (!range_ok(pos, 8, cmds_end)) {
            add_issue(t_, IssueKind::malformed,
                      "load command " + std::to_string(i) + " starts beyond sizeofcmds", pos);
            break;
        }
        const auto cmd = img_.u32(pos, e_);
        const auto cmdsize = img_.u32(pos + 4, e_);
        if (!cmd || !cmdsize) {
            break;
        }
        if (*cmdsize < 8 || !range_ok(pos, *cmdsize, cmds_end)) {
            add_issue(t_, IssueKind::malformed,
                      "load command " + std::to_string(i) + " has invalid cmdsize " +
                          std::to_string(*cmdsize),
                      pos);
            break;
        }
        const auto view = img_.sub(pos, *cmdsize);
        if (!view) {
            break;
        }
        switch (*cmd) {
            case LC_SEGMENT:
                on_segment(*view, false);
                break;
            case LC_SEGMENT_64:
                on_segment(*view, true);
                break;
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LAZY_LOAD_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_ID_DYLIB:
                on_dylib(*view, *cmd);
                break;
            case LC_LOAD_DYLINKER:
                if (auto s = lc_string(*view, "LC_LOAD_DYLINKER")) {
                    set_property(t_, "dylinker", *s);
                }
                break;
            case LC_RPATH:
                if (auto s = lc_string(*view, "LC_RPATH")) {
                    t_.rpaths.push_back(*s);
                }
                break;
            case LC_MAIN: {
                const auto off = view->u64(8, e_);
                if (off) {
                    main_offset_ = *off;
                    set_property(t_, "entryoff", hex(*off));
                }
                break;
            }
            case LC_UNIXTHREAD:
                on_thread(*view);
                break;
            case LC_CODE_SIGNATURE: {
                code_signature_ = true;
                const auto off = view->u32(8, e_);
                const auto size = view->u32(12, e_);
                if (off && size) {
                    set_property(t_, "code_signature_size", static_cast<std::uint64_t>(*size));
                    if (!img_.contains(*off, *size)) {
                        add_issue(t_, IssueKind::out_of_bounds,
                                  "LC_CODE_SIGNATURE data lies outside the file", *off);
                    }
                }
                break;
            }
            case LC_ENCRYPTION_INFO:
            case LC_ENCRYPTION_INFO_64: {
                const auto id = view->u32(16, e_);
                if (id) {
                    cryptid_ = *id;
                }
                break;
            }
            case LC_SYMTAB: {
                StructReader s(*view, 8, e_);
                const auto so = s.u32();
                const auto ns = s.u32();
                const auto st = s.u32();
                const auto ss = s.u32();
                if (s.ok()) {
                    symoff_ = so;
                    nsyms_ = ns;
                    stroff_ = st;
                    strsize_ = ss;
                    set_property(t_, "symbols", static_cast<std::uint64_t>(ns));
                }
                break;
            }
            case LC_DYSYMTAB: {
                const auto iu = view->u32(24, e_);
                const auto nu = view->u32(28, e_);
                if (iu && nu) {
                    iundef_ = *iu;
                    nundef_ = *nu;
                }
                break;
            }
            case LC_UUID: {
                const auto id = view->sub(8, 16);
                if (id) {
                    std::string text;
                    static constexpr char kDigits[] = "0123456789ABCDEF";
                    int n = 0;
                    for (const auto b : id->span()) {
                        if (n == 4 || n == 6 || n == 8 || n == 10) {
                            text.push_back('-');
                        }
                        text.push_back(kDigits[b >> 4U]);
                        text.push_back(kDigits[b & 0xFU]);
                        ++n;
                    }
                    set_property(t_, "uuid", text);
                }
                break;
            }
            case LC_BUILD_VERSION: {
                const auto minos = view->u32(12, e_);
                if (minos) {
                    set_property(t_, "min_os", version_string(*minos));
                }
                break;
            }
            case LC_VERSION_MIN_MACOSX: {
                const auto v = view->u32(8, e_);
                if (v) {
                    set_property(t_, "min_os", version_string(*v));
                }
                break;
            }
            default:
                break;
        }
        pos += *cmdsize;
    }
    read_symbols();
    derive();
    for (auto& s : t_.sections) {
        finish_region(s, img_);
    }
    for (auto& s : t_.segments) {
        finish_region(s, img_);
    }
    return t_;
}

void MachoParser::on_segment(ByteView cmd, bool seg64) {
    const std::uint64_t header = seg64 ? 72 : 56;
    const std::uint64_t sect_size = seg64 ? 80 : 68;
    StructReader r(cmd, 8, e_);
    Region seg;
    seg.kind = "segment";
    seg.type = seg64 ? "LC_SEGMENT_64" : "LC_SEGMENT";
    seg.name = printable(r.fixed_string(16));
    seg.vaddr = r.word(seg64);
    seg.mem_size = r.word(seg64);
    seg.offset = r.word(seg64);
    seg.file_size = r.word(seg64);
    r.u32();  // maxprot
    const std::uint32_t initprot = r.u32();
    std::uint64_t nsects = r.u32();
    r.u32();  // flags
    if (!r.ok()) {
        add_issue(t_, IssueKind::malformed, "segment command is truncated");
        return;
    }
    seg.raw_flags = initprot;
    seg.readable = (initprot & VM_PROT_READ) != 0;
    seg.writable = (initprot & VM_PROT_WRITE) != 0;
    seg.executable = (initprot & VM_PROT_EXECUTE) != 0;
    seg.has_file_data = seg.file_size > 0;
    if (t_.segments.size() < limits_.max_sections) {
        t_.segments.push_back(seg);
    }

    const auto need = checked_mul(nsects, sect_size);
    if (!need || header + *need > cmd.size()) {
        add_issue(t_, IssueKind::malformed,
                  "segment " + seg.name + " claims " + std::to_string(nsects) +
                      " sections, more than its cmdsize holds");
        nsects = records_that_fit(header, sect_size, nsects, cmd.size());
    }
    for (std::uint64_t i = 0; i < nsects; ++i) {
        if (section_count_ >= limits_.max_sections) {
            if (!section_limit_reported_) {
                add_issue(t_, IssueKind::limit,
                          "more than " + std::to_string(limits_.max_sections) +
                              " sections; the rest were ignored");
                section_limit_reported_ = true;
            }
            return;
        }
        StructReader s(cmd, header + i * sect_size, e_);
        const std::string sectname = printable(s.fixed_string(16));
        const std::string segname = printable(s.fixed_string(16));
        Region sec;
        sec.kind = "section";
        sec.name = segname;
        sec.name += ',';
        sec.name += sectname;
        sec.vaddr = s.word(seg64);
        sec.mem_size = s.word(seg64);
        sec.offset = s.u32();
        s.u32();  // align
        s.u32();  // reloff
        s.u32();  // nreloc
        const std::uint32_t flags = s.u32();
        if (!s.ok()) {
            break;
        }
        sec.type = section_type_name(flags);
        sec.raw_flags = flags;
        sec.has_file_data = !is_zerofill(flags);
        sec.file_size = sec.has_file_data ? sec.mem_size : 0;
        sec.readable = seg.readable;
        sec.writable = seg.writable;
        sec.executable = seg.executable && ((flags & S_ATTR_PURE_INSTRUCTIONS) != 0 ||
                                            (flags & S_ATTR_SOME_INSTRUCTIONS) != 0);
        t_.sections.push_back(sec);
        ++section_count_;
    }
}

void MachoParser::on_dylib(ByteView cmd, std::uint32_t type) {
    const char* what = type == LC_ID_DYLIB ? "LC_ID_DYLIB" : "LC_LOAD_DYLIB";
    auto name = lc_string(cmd, what);
    if (!name) {
        return;
    }
    if (type == LC_ID_DYLIB) {
        set_property(t_, "install_name", *name);
        return;
    }
    if (t_.libraries.size() >= limits_.max_libraries) {
        add_issue(t_, IssueKind::limit,
                  "more than " + std::to_string(limits_.max_libraries) +
                      " dylib load commands; the rest were ignored");
        return;
    }
    t_.libraries.push_back(ImportedLibrary{*name, {}});
}

void MachoParser::on_thread(ByteView cmd) {
    const auto flavor = cmd.u32(8, e_);
    if (!flavor) {
        return;
    }
    const std::uint32_t type = cputype_;
    std::optional<std::uint64_t> pc;
    if (type == (CPU_TYPE_X86 | CPU_ARCH_ABI64) && *flavor == 4) {
        if (auto v = cmd.u64(16 + 16 * 8, e_)) {
            pc = *v;
        }
    } else if (type == (CPU_TYPE_ARM | CPU_ARCH_ABI64) && *flavor == 6) {
        if (auto v = cmd.u64(16 + 32 * 8, e_)) {
            pc = *v;
        }
    } else if (type == CPU_TYPE_X86 && *flavor == 1) {
        if (auto v = cmd.u32(16 + 10 * 4, e_)) {
            pc = *v;
        }
    } else if (type == CPU_TYPE_ARM && *flavor == 1) {
        if (auto v = cmd.u32(16 + 15 * 4, e_)) {
            pc = *v;
        }
    }
    if (pc) {
        thread_pc_ = pc;
    } else {
        add_issue(t_, IssueKind::malformed, "LC_UNIXTHREAD state is truncated or unsupported");
    }
}

void MachoParser::read_symbols() {
    if (!symoff_ || !nsyms_ || !stroff_ || !strsize_) {
        return;
    }
    const std::uint64_t entry = is64_ ? 16 : 12;
    const ByteView strtab = img_.clamp(*stroff_, *strsize_);
    std::uint64_t first = 0;
    std::uint64_t count = *nsyms_;
    if (iundef_ && nundef_) {
        first = *iundef_;
        count = *nundef_;
    }
    const auto start = checked_mul(first, entry);
    const auto table = start ? checked_add(*symoff_, *start) : std::nullopt;
    if (!table) {
        add_issue(t_, IssueKind::out_of_bounds, "symbol table offset overflows", *symoff_);
        return;
    }
    const std::uint64_t table_start = *table;
    const auto table_len = checked_mul(count, entry);
    if (!table_len || !img_.contains(table_start, *table_len)) {
        add_issue(t_, IssueKind::out_of_bounds, "symbol table extends past the end of the file",
                  *symoff_);
        count = records_that_fit(table_start, entry, count, img_.size());
    }
    if (count > limits_.max_symbols) {
        add_issue(t_, IssueKind::limit,
                  "symbol count exceeds the limit of " + std::to_string(limits_.max_symbols));
        count = limits_.max_symbols;
    }
    for (std::uint64_t i = 0; i < count; ++i) {
        StructReader r(img_, table_start + i * entry, e_);
        const std::uint32_t strx = r.u32();
        const std::uint8_t ntype = r.u8();
        r.u8();  // n_sect
        const std::uint16_t desc = r.u16();
        if (!r.ok()) {
            break;
        }
        const bool undefined_ext =
            (ntype & 0xE0U) == 0 && (ntype & 0x0EU) == 0 && (ntype & 0x01U) != 0;
        if (!undefined_ext) {
            continue;
        }
        if (t_.import_count >= limits_.max_imports) {
            add_issue(t_, IssueKind::limit,
                      "more than " + std::to_string(limits_.max_imports) +
                          " imported symbols; the rest were ignored");
            break;
        }
        const auto name = strtab.cstring(strx, kMaxStringLength);
        if (!name) {
            continue;
        }
        const unsigned ordinal = (static_cast<unsigned>(desc) >> 8U) & 0xFFU;
        if (ordinal >= 1 && ordinal <= t_.libraries.size()) {
            t_.libraries[ordinal - 1].functions.push_back(printable(*name));
        } else {
            t_.unbound_imports.push_back(printable(*name));
        }
        ++t_.import_count;
    }
}

void MachoParser::derive() {
    if (main_offset_) {
        std::optional<std::uint64_t> vaddr;
        for (const auto& seg : t_.segments) {
            const auto end = checked_add(seg.offset, seg.file_size);
            if (end && *main_offset_ >= seg.offset && *main_offset_ < *end) {
                vaddr = seg.vaddr + (*main_offset_ - seg.offset);
                break;
            }
        }
        // An unmappable entry offset is kept as-is so the entry-point check reports it.
        t_.entry = vaddr.value_or(*main_offset_);
    } else if (thread_pc_) {
        t_.entry = thread_pc_;
    }

    const bool exec = filetype_ == MH_EXECUTE;
    HardeningFlag pie{"pie", "Position independent (MH_PIE)", std::nullopt, ""};
    HardeningFlag nx{"nx_stack", "Non-executable stack", std::nullopt, ""};
    if (exec) {
        pie.enabled = (flags_ & MH_PIE) != 0;
        pie.detail = *pie.enabled ? "MH_PIE set" : "MH_PIE not set: fixed load address";
        nx.enabled = (flags_ & MH_ALLOW_STACK_EXECUTION) == 0;
        nx.detail =
            *nx.enabled ? "MH_ALLOW_STACK_EXECUTION not set" : "MH_ALLOW_STACK_EXECUTION set";
    } else {
        pie.detail = "not applicable to this file type";
        nx.detail = pie.detail;
    }
    t_.hardening.push_back(pie);
    t_.hardening.push_back(nx);
    t_.hardening.push_back(HardeningFlag{"no_heap_exec", "MH_NO_HEAP_EXECUTION",
                                         (flags_ & MH_NO_HEAP_EXECUTION) != 0,
                                         "opt-in flag; arm64 heaps are non-executable regardless"});
    t_.hardening.push_back(
        HardeningFlag{"code_signature", "Code signature present", code_signature_,
                      code_signature_ ? "LC_CODE_SIGNATURE present (presence only; not verified)"
                                      : "no LC_CODE_SIGNATURE"});
    if (cryptid_) {
        set_property(t_, "cryptid", static_cast<std::uint64_t>(*cryptid_));
    }
}

}  // namespace

Target parse_macho_thin(ByteView image, const Limits& limits) {
    MachoParser parser(image, limits);
    return parser.run();
}

FileInfo parse_macho_fat(ByteView file, const Limits& limits) {
    FileInfo info;
    info.container = Format::macho_fat;
    Target container;
    container.format = Format::macho_fat;
    container.format_name = "Mach-O universal";
    container.size = file.size();

    const auto magic = file.u32(0, Endian::big);
    const auto nfat = file.u32(4, Endian::big);
    if (!magic || !nfat) {
        add_issue(container, IssueKind::malformed, "universal header is truncated");
        info.targets.push_back(container);
        return info;
    }
    const bool fat64 = *magic == 0xCAFEBABFU;
    const std::uint64_t entry = fat64 ? 32 : 20;
    std::uint64_t count = *nfat;
    if (count > limits.max_fat_slices) {
        add_issue(container, IssueKind::limit,
                  "universal header lists " + std::to_string(count) +
                      " slices, more than the limit of " + std::to_string(limits.max_fat_slices) +
                      "; parsing stops there");
        count = limits.max_fat_slices;
    }
    if (!file.contains(8, count * entry)) {
        add_issue(container, IssueKind::out_of_bounds,
                  "universal header slice table extends past the end of the file", 8);
        count = records_that_fit(8, entry, count, file.size());
    }
    const std::uint64_t header_end = 8 + count * entry;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> taken;
    for (std::uint64_t i = 0; i < count; ++i) {
        StructReader r(file, 8 + i * entry, Endian::big);
        const std::uint32_t cputype = r.u32();
        const std::uint32_t subtype = r.u32();
        const std::uint64_t offset = fat64 ? r.u64() : r.u32();
        const std::uint64_t size = fat64 ? r.u64() : r.u32();
        if (!r.ok()) {
            break;
        }
        const std::string arch = cpu_name(cputype, subtype);
        const std::string label = "slice " + std::to_string(i) + " (" + arch + ")";
        if (!range_ok(offset, size, file.size())) {
            add_issue(container, IssueKind::out_of_bounds,
                      label + " at offset " + hex(offset) + " with size " + std::to_string(size) +
                          " extends past the end of the file",
                      offset);
            continue;
        }
        if (offset < header_end) {
            add_issue(container, IssueKind::malformed, label + " overlaps the universal header",
                      offset);
            continue;
        }
        bool overlaps = false;
        for (const auto& [o, s] : taken) {
            if (offset < o + s && o < offset + size) {
                overlaps = true;
            }
        }
        if (overlaps) {
            add_issue(container, IssueKind::malformed, label + " overlaps another slice", offset);
            continue;
        }
        taken.emplace_back(offset, size);
        const auto slice = file.sub(offset, size);
        if (!slice) {
            continue;
        }
        if (detect_format(*slice) != Format::macho) {
            add_issue(container, IssueKind::malformed, label + " is not a thin Mach-O image",
                      offset);
            continue;
        }
        Target t = parse_macho_thin(*slice, limits);
        t.slice_offset = offset;
        if (t.arch != arch) {
            add_issue(t, IssueKind::malformed,
                      "universal header says " + arch + " but the slice header says " + t.arch,
                      offset);
        }
        info.targets.push_back(std::move(t));
    }
    if (info.targets.empty()) {
        add_issue(container, IssueKind::malformed, "universal file contains no usable slices");
        info.targets.push_back(container);
        return info;
    }
    auto& first = info.targets.front();
    for (auto& issue : container.issues) {
        issue.message = "universal header: " + issue.message;
        issue.absolute = true;
    }
    first.issues.insert(first.issues.begin(), container.issues.begin(), container.issues.end());
    return info;
}

}  // namespace binscope::detail
