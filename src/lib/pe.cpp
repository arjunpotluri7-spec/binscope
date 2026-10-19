// PE/COFF parser for PE32 and PE32+ images.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "binscope/entropy.hpp"
#include "parsers.hpp"

namespace binscope::detail {

namespace {

constexpr std::uint32_t kPeSignature = 0x00004550;  // "PE\0\0"
constexpr std::uint16_t kMagicPe32 = 0x10B;
constexpr std::uint16_t kMagicPe32Plus = 0x20B;

constexpr std::uint16_t IMAGE_FILE_RELOCS_STRIPPED = 0x0001;
constexpr std::uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
constexpr std::uint16_t IMAGE_FILE_DLL = 0x2000;

constexpr std::uint16_t DLL_HIGH_ENTROPY_VA = 0x0020;
constexpr std::uint16_t DLL_DYNAMIC_BASE = 0x0040;
constexpr std::uint16_t DLL_FORCE_INTEGRITY = 0x0080;
constexpr std::uint16_t DLL_NX_COMPAT = 0x0100;
constexpr std::uint16_t DLL_NO_SEH = 0x0400;
constexpr std::uint16_t DLL_GUARD_CF = 0x4000;

constexpr std::uint32_t SCN_CNT_CODE = 0x00000020;
constexpr std::uint32_t SCN_CNT_INITIALIZED_DATA = 0x00000040;
constexpr std::uint32_t SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
constexpr std::uint32_t SCN_MEM_EXECUTE = 0x20000000;
constexpr std::uint32_t SCN_MEM_READ = 0x40000000;
constexpr std::uint32_t SCN_MEM_WRITE = 0x80000000;

constexpr std::uint32_t kDirImport = 1;
constexpr std::uint32_t kDirSecurity = 4;
constexpr std::uint32_t kDirClr = 14;

constexpr std::uint64_t kMaxNameLength = 512;
constexpr std::uint64_t kMaxThunksPerLibrary = 65536;

std::string machine_name(std::uint16_t machine) {
    switch (machine) {
        case 0x014C:
            return "i386";
        case 0x8664:
            return "x86_64";
        case 0xAA64:
            return "arm64";
        case 0x01C0:
            return "arm";
        case 0x01C4:
            return "armnt";
        case 0x0200:
            return "ia64";
        case 0x5064:
            return "riscv64";
        default:
            return "machine-" + hex(machine);
    }
}

/// UTC "YYYY-MM-DDTHH:MM:SSZ" without locale- or thread-sensitive C library calls.
std::string utc_timestamp(std::uint32_t seconds) {
    const std::int64_t days = seconds / 86400;
    const std::int64_t rem = seconds % 86400;
    // Howard Hinnant's civil-from-days algorithm.
    const std::int64_t z = days + 719468;
    const std::int64_t era = z / 146097;
    const std::int64_t doe = z - era * 146097;
    const std::int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const std::int64_t mp = (5 * doy + 2) / 153;
    const std::int64_t d = doy - (153 * mp + 2) / 5 + 1;
    const std::int64_t m = mp < 10 ? mp + 3 : mp - 9;
    const std::int64_t y = yoe + era * 400 + (m <= 2 ? 1 : 0);
    auto pad = [](std::int64_t v, std::size_t w) {
        return zero_pad(static_cast<std::uint64_t>(v), w);
    };
    return pad(y, 4) + "-" + pad(m, 2) + "-" + pad(d, 2) + "T" + pad(rem / 3600, 2) + ":" +
           pad((rem % 3600) / 60, 2) + ":" + pad(rem % 60, 2) + "Z";
}

struct RawSection {
    std::uint32_t vsize = 0;
    std::uint32_t va = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t raw_ptr = 0;
};

class PeParser {
public:
    PeParser(ByteView image, const Limits& limits) : img_(image), limits_(limits) {}
    Target run();

private:
    void read_sections(std::uint64_t table, std::uint32_t count, std::uint32_t symptr,
                       std::uint32_t nsyms);
    void read_imports(std::uint32_t rva);
    [[nodiscard]] std::optional<std::uint64_t> rva_to_offset(std::uint64_t rva) const;
    [[nodiscard]] Result<std::uint64_t> read_thunk(std::uint64_t offset) const;

    ByteView img_;
    const Limits& limits_;
    Target t_;
    bool pe64_ = false;
    std::uint32_t size_of_headers_ = 0;
    std::vector<RawSection> raw_;
};

std::optional<std::uint64_t> PeParser::rva_to_offset(std::uint64_t rva) const {
    for (const auto& s : raw_) {
        const std::uint64_t span = s.vsize > s.raw_size ? s.vsize : s.raw_size;
        if (rva >= s.va && rva < static_cast<std::uint64_t>(s.va) + span) {
            const std::uint64_t delta = rva - s.va;
            if (delta >= s.raw_size) {
                return std::nullopt;  // inside the section, but in its zero-filled tail
            }
            return static_cast<std::uint64_t>(s.raw_ptr) + delta;
        }
    }
    if (rva < size_of_headers_) {
        return rva;
    }
    return std::nullopt;
}

Result<std::uint64_t> PeParser::read_thunk(std::uint64_t offset) const {
    if (pe64_) {
        return img_.u64(offset, Endian::little);
    }
    const auto v = img_.u32(offset, Endian::little);
    if (!v) {
        return v.error();
    }
    return static_cast<std::uint64_t>(*v);
}

Target PeParser::run() {
    t_.format = Format::pe;
    t_.format_name = "PE";
    t_.size = img_.size();
    t_.entropy = shannon_entropy(img_.span());
    const auto lfanew = img_.u32(0x3C, Endian::little);
    if (!lfanew) {
        t_.format_name = "MZ";
        add_issue(t_, IssueKind::malformed,
                  "DOS header is truncated (" + std::to_string(img_.size()) + " bytes, need 64)");
        return t_;
    }
    if (!img_.contains(*lfanew, 24)) {
        t_.format_name = "MZ";
        add_issue(t_, IssueKind::out_of_bounds,
                  "e_lfanew " + hex(*lfanew) + " points past the end of the file", 0x3C);
        return t_;
    }
    const auto sig = img_.u32(*lfanew, Endian::little);
    if (!sig || *sig != kPeSignature) {
        t_.format_name = "MZ";
        add_issue(t_, IssueKind::malformed,
                  "no PE signature at e_lfanew " + hex(*lfanew) + " (DOS-only or corrupt file)",
                  *lfanew);
        return t_;
    }
    StructReader coff(img_, *lfanew + 4, Endian::little);
    const std::uint16_t machine = coff.u16();
    const std::uint16_t nsections = coff.u16();
    const std::uint32_t timestamp = coff.u32();
    const std::uint32_t symptr = coff.u32();
    const std::uint32_t nsyms = coff.u32();
    const std::uint16_t opt_size = coff.u16();
    const std::uint16_t chars = coff.u16();
    if (!coff.ok()) {
        add_issue(t_, IssueKind::malformed, "COFF header is truncated", *lfanew);
        return t_;
    }
    t_.arch = machine_name(machine);
    t_.bits = 32;
    const bool dll = (chars & IMAGE_FILE_DLL) != 0;
    t_.file_type =
        dll ? "DLL" : ((chars & IMAGE_FILE_EXECUTABLE_IMAGE) != 0 ? "executable" : "object");
    t_.expects_entry = !dll && (chars & IMAGE_FILE_EXECUTABLE_IMAGE) != 0;
    set_property(t_, "timestamp", static_cast<std::uint64_t>(timestamp));
    set_property(t_, "timestamp_utc", utc_timestamp(timestamp));
    set_property(t_, "coff_characteristics", hex(chars));

    const std::uint64_t opt = static_cast<std::uint64_t>(*lfanew) + 24;
    std::uint16_t dll_chars = 0;
    std::uint32_t entry = 0;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> dirs;
    bool have_optional = false;
    if (opt_size == 0) {
        add_issue(t_, IssueKind::malformed, "image has no optional header", opt);
    } else {
        const auto magic = img_.u16(opt, Endian::little);
        if (!magic || (*magic != kMagicPe32 && *magic != kMagicPe32Plus)) {
            add_issue(t_, IssueKind::malformed,
                      "unknown optional header magic " + hex(magic.value_or(0)), opt);
        } else {
            pe64_ = *magic == kMagicPe32Plus;
            t_.bits = pe64_ ? 64 : 32;
            t_.format_name = pe64_ ? "PE32+" : "PE32";
            const std::uint64_t fixed = pe64_ ? 112 : 96;
            if (opt_size < fixed) {
                add_issue(t_, IssueKind::malformed,
                          "SizeOfOptionalHeader " + std::to_string(opt_size) +
                              " is smaller than the " + std::to_string(fixed) +
                              " bytes this header type needs",
                          *lfanew + 20);
            } else if (!img_.contains(opt, opt_size)) {
                add_issue(t_, IssueKind::out_of_bounds,
                          "optional header extends past the end of the file", opt);
            } else {
                have_optional = true;
                StructReader r(img_, opt + 16, Endian::little);
                entry = r.u32();
                const std::uint64_t image_base =
                    pe64_ ? img_.u64(opt + 24, Endian::little).value_or(0)
                          : img_.u32(opt + 28, Endian::little).value_or(0);
                const std::uint32_t section_align = img_.u32(opt + 32, Endian::little).value_or(0);
                const std::uint32_t file_align = img_.u32(opt + 36, Endian::little).value_or(0);
                const std::uint32_t size_of_image = img_.u32(opt + 56, Endian::little).value_or(0);
                size_of_headers_ = img_.u32(opt + 60, Endian::little).value_or(0);
                const std::uint16_t subsystem = img_.u16(opt + 68, Endian::little).value_or(0);
                dll_chars = img_.u16(opt + 70, Endian::little).value_or(0);
                std::uint32_t nrva = img_.u32(opt + (pe64_ ? 108 : 92), Endian::little).value_or(0);
                set_property(t_, "image_base", hex(image_base));
                set_property(t_, "section_alignment", static_cast<std::uint64_t>(section_align));
                set_property(t_, "file_alignment", static_cast<std::uint64_t>(file_align));
                set_property(t_, "size_of_image", static_cast<std::uint64_t>(size_of_image));
                set_property(t_, "size_of_headers", static_cast<std::uint64_t>(size_of_headers_));
                set_property(t_, "subsystem", static_cast<std::uint64_t>(subsystem));
                set_property(t_, "dll_characteristics", hex(dll_chars));
                if (size_of_headers_ > img_.size()) {
                    add_issue(t_, IssueKind::malformed,
                              "SizeOfHeaders " + std::to_string(size_of_headers_) +
                                  " is larger than the file",
                              opt + 60);
                }
                if (nrva > 16) {
                    add_issue(t_, IssueKind::malformed,
                              "NumberOfRvaAndSizes is " + std::to_string(nrva) +
                                  "; only 16 directories are defined",
                              opt + (pe64_ ? 108 : 92));
                    nrva = 16;
                }
                const std::uint64_t room = (opt_size - fixed) / 8;
                if (nrva > room) {
                    add_issue(t_, IssueKind::malformed,
                              "data directories do not fit in SizeOfOptionalHeader", opt);
                    nrva = static_cast<std::uint32_t>(room);
                }
                for (std::uint32_t i = 0; i < nrva; ++i) {
                    const std::uint64_t at = opt + fixed + static_cast<std::uint64_t>(i) * 8;
                    dirs.emplace_back(img_.u32(at, Endian::little).value_or(0),
                                      img_.u32(at + 4, Endian::little).value_or(0));
                }
            }
        }
    }

    read_sections(opt + opt_size, nsections, symptr, nsyms);

    if (have_optional) {
        if (entry != 0 || t_.expects_entry) {
            t_.entry = entry;
        }
        if (dirs.size() > kDirImport && dirs[kDirImport].first != 0) {
            read_imports(dirs[kDirImport].first);
        }
        bool cert = false;
        if (dirs.size() > kDirSecurity && dirs[kDirSecurity].first != 0 &&
            dirs[kDirSecurity].second != 0) {
            cert = true;
            // The security directory holds a file offset, not an RVA.
            if (!img_.contains(dirs[kDirSecurity].first, dirs[kDirSecurity].second)) {
                add_issue(t_, IssueKind::out_of_bounds, "certificate table lies outside the file",
                          dirs[kDirSecurity].first);
            }
        }
        if (dirs.size() > kDirClr && dirs[kDirClr].first != 0) {
            set_property(t_, "dotnet", true);
        }

        const bool dynbase = (dll_chars & DLL_DYNAMIC_BASE) != 0;
        const bool stripped = (chars & IMAGE_FILE_RELOCS_STRIPPED) != 0;
        HardeningFlag aslr{"aslr", "ASLR (DYNAMIC_BASE)", dynbase && !stripped, ""};
        if (!dynbase) {
            aslr.detail = "DYNAMIC_BASE not set";
        } else if (stripped) {
            aslr.detail = "DYNAMIC_BASE set but relocations are stripped, so it cannot move";
        } else {
            aslr.detail = "DYNAMIC_BASE set";
        }
        t_.hardening.push_back(aslr);
        HardeningFlag heva{"high_entropy_va", "High-entropy 64-bit ASLR", std::nullopt, ""};
        if (pe64_) {
            heva.enabled = (dll_chars & DLL_HIGH_ENTROPY_VA) != 0;
            heva.detail = *heva.enabled ? "HIGH_ENTROPY_VA set" : "HIGH_ENTROPY_VA not set";
        } else {
            heva.detail = "not applicable to PE32";
        }
        t_.hardening.push_back(heva);
        const bool nx = (dll_chars & DLL_NX_COMPAT) != 0;
        t_.hardening.push_back(HardeningFlag{"dep", "DEP (NX_COMPAT)", nx,
                                             nx ? "NX_COMPAT set" : "NX_COMPAT not set"});
        const bool cfg = (dll_chars & DLL_GUARD_CF) != 0;
        t_.hardening.push_back(HardeningFlag{"cfg", "Control Flow Guard (GUARD_CF)", cfg,
                                             cfg ? "GUARD_CF set" : "GUARD_CF not set"});
        t_.hardening.push_back(HardeningFlag{
            "certificate", "Authenticode certificate table present", cert,
            cert ? "security directory present (presence only; the signature is not verified)"
                 : "no security directory"});
        set_property(t_, "no_seh", (dll_chars & DLL_NO_SEH) != 0);
        set_property(t_, "force_integrity", (dll_chars & DLL_FORCE_INTEGRITY) != 0);

        std::uint64_t data_end = size_of_headers_;
        for (const auto& s : t_.sections) {
            if (s.has_file_data && !s.past_eof) {
                const std::uint64_t end = s.offset + s.file_size;
                data_end = end > data_end ? end : data_end;
            }
        }
        if (cert && img_.contains(dirs[kDirSecurity].first, dirs[kDirSecurity].second)) {
            const std::uint64_t end =
                static_cast<std::uint64_t>(dirs[kDirSecurity].first) + dirs[kDirSecurity].second;
            data_end = end > data_end ? end : data_end;
        }
        set_property(t_, "overlay_bytes", img_.size() > data_end ? img_.size() - data_end : 0);
    }
    return t_;
}

void PeParser::read_sections(std::uint64_t table, std::uint32_t count, std::uint32_t symptr,
                             std::uint32_t nsyms) {
    std::uint64_t n = count;
    if (n > limits_.max_sections) {
        add_issue(t_, IssueKind::limit,
                  "NumberOfSections " + std::to_string(n) + " exceeds the limit of " +
                      std::to_string(limits_.max_sections) + "; parsing stops there");
        n = limits_.max_sections;
    }
    if (!img_.contains(table, n * 40)) {
        add_issue(t_, IssueKind::out_of_bounds,
                  "section table (" + std::to_string(count) + " entries at offset " + hex(table) +
                      ") extends past the end of the file",
                  table);
        n = records_that_fit(table, 40, n, img_.size());
    }
    // Long section names ("/123") index the COFF string table that follows the symbols.
    const std::uint64_t strtab =
        static_cast<std::uint64_t>(symptr) + static_cast<std::uint64_t>(nsyms) * 18;
    for (std::uint64_t i = 0; i < n; ++i) {
        StructReader r(img_, table + i * 40, Endian::little);
        std::string name = r.fixed_string(8);
        RawSection raw;
        raw.vsize = r.u32();
        raw.va = r.u32();
        raw.raw_size = r.u32();
        raw.raw_ptr = r.u32();
        r.skip(12);
        const std::uint32_t chars = r.u32();
        if (!r.ok()) {
            break;
        }
        if (name.size() > 1 && name[0] == '/' && symptr != 0) {
            std::uint64_t index = 0;
            bool digits = true;
            for (std::size_t k = 1; k < name.size(); ++k) {
                if (name[k] < '0' || name[k] > '9') {
                    digits = false;
                    break;
                }
                index = index * 10 + static_cast<std::uint64_t>(name[k] - '0');
            }
            if (digits) {
                const auto at = checked_add(strtab, index);
                const auto full =
                    at ? img_.cstring(*at, kMaxNameLength) : Result<std::string>(make_error(""));
                if (full) {
                    name = *full;
                }
            }
        }
        raw_.push_back(raw);
        Region reg;
        reg.kind = "section";
        reg.name = printable(name);
        if ((chars & SCN_CNT_CODE) != 0) {
            reg.type = "code";
        } else if ((chars & SCN_CNT_UNINITIALIZED_DATA) != 0) {
            reg.type = "uninitialized data";
        } else if ((chars & SCN_CNT_INITIALIZED_DATA) != 0) {
            reg.type = "initialized data";
        } else {
            reg.type = "other";
        }
        reg.offset = raw.raw_ptr;
        reg.file_size = raw.raw_size;
        reg.vaddr = raw.va;
        reg.mem_size = raw.vsize;
        reg.raw_flags = chars;
        reg.readable = (chars & SCN_MEM_READ) != 0;
        reg.writable = (chars & SCN_MEM_WRITE) != 0;
        reg.executable = (chars & SCN_MEM_EXECUTE) != 0;
        reg.has_file_data = raw.raw_size > 0;
        finish_region(reg, img_);
        t_.sections.push_back(reg);
    }
}

void PeParser::read_imports(std::uint32_t rva) {
    const auto start = rva_to_offset(rva);
    if (!start) {
        add_issue(t_, IssueKind::out_of_bounds,
                  "import directory RVA " + hex(rva) + " does not map to file data");
        return;
    }
    const std::uint64_t thunk_size = pe64_ ? 8 : 4;
    const std::uint64_t ordinal_flag = pe64_ ? (1ULL << 63U) : (1ULL << 31U);
    bool bad_thunk_reported = false;
    for (std::uint64_t d = 0;; ++d) {
        if (d >= limits_.max_libraries) {
            add_issue(t_, IssueKind::limit,
                      "more than " + std::to_string(limits_.max_libraries) +
                          " import descriptors; the rest were ignored");
            break;
        }
        StructReader r(img_, *start + d * 20, Endian::little);
        const std::uint32_t oft = r.u32();
        r.u32();  // TimeDateStamp
        r.u32();  // ForwarderChain
        const std::uint32_t name_rva = r.u32();
        const std::uint32_t ft = r.u32();
        if (!r.ok()) {
            add_issue(t_, IssueKind::out_of_bounds,
                      "import descriptor table runs past the end of the file", *start + d * 20);
            break;
        }
        if (oft == 0 && name_rva == 0 && ft == 0) {
            break;
        }
        ImportedLibrary lib;
        const auto name_off = rva_to_offset(name_rva);
        const auto name = name_off ? img_.cstring(*name_off, kMaxNameLength)
                                   : Result<std::string>(make_error("unmapped"));
        if (name) {
            lib.name = printable(*name);
        } else {
            lib.name = "<unreadable>";
            add_issue(t_, IssueKind::out_of_bounds,
                      "import descriptor " + std::to_string(d) + " has an unreadable DLL name");
        }
        const std::uint32_t thunks_rva = oft != 0 ? oft : ft;
        const auto thunks = rva_to_offset(thunks_rva);
        if (!thunks) {
            add_issue(t_, IssueKind::out_of_bounds,
                      "import thunks for " + lib.name + " do not map to file data");
        } else {
            for (std::uint64_t k = 0; k < kMaxThunksPerLibrary; ++k) {
                const auto at = checked_add(*thunks, k * thunk_size);
                if (!at) {
                    break;
                }
                const auto value = read_thunk(*at);
                if (!value || *value == 0) {
                    break;
                }
                if (t_.import_count >= limits_.max_imports) {
                    add_issue(t_, IssueKind::limit,
                              "more than " + std::to_string(limits_.max_imports) +
                                  " imported functions; the rest were ignored");
                    t_.libraries.push_back(lib);
                    return;
                }
                if ((*value & ordinal_flag) != 0) {
                    lib.functions.push_back("#" + std::to_string(*value & 0xFFFFU));
                } else {
                    const auto hint = rva_to_offset(*value & 0x7FFFFFFFU);
                    const auto fn = hint ? img_.cstring(*hint + 2, kMaxNameLength)
                                         : Result<std::string>(make_error("unmapped"));
                    if (fn) {
                        lib.functions.push_back(printable(*fn));
                    } else if (!bad_thunk_reported) {
                        add_issue(t_, IssueKind::out_of_bounds,
                                  "an import name for " + lib.name + " does not map to file data");
                        bad_thunk_reported = true;
                    }
                }
                ++t_.import_count;
            }
        }
        t_.libraries.push_back(std::move(lib));
    }
}

}  // namespace

Target parse_pe(ByteView image, const Limits& limits) {
    PeParser parser(image, limits);
    return parser.run();
}

}  // namespace binscope::detail
