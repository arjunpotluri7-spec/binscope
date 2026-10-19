// Format-neutral description of a parsed executable.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "binscope/bytes.hpp"

namespace binscope {

enum class Format : std::uint8_t { elf, macho, macho_fat, pe };

[[nodiscard]] const char* format_id(Format format) noexcept;  // "elf", "macho", ...

/// A section or a segment (ELF program header, Mach-O segment). Addresses are virtual
/// addresses for ELF and Mach-O and RVAs for PE.
struct Region {
    std::string name;
    std::string kind;  // "section" or "segment"
    std::string type;  // e.g. "PT_LOAD", "SHT_PROGBITS", "__TEXT", "code"
    std::uint64_t offset = 0;
    std::uint64_t file_size = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t mem_size = 0;
    std::uint64_t raw_flags = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool has_file_data = true;        // false for SHT_NOBITS, Mach-O zerofill, PE uninitialized
    bool allocated = true;            // mapped into memory at run time (ELF SHF_ALLOC)
    bool past_eof = false;            // offset + file_size is beyond the end of the file
    double entropy = 0.0;             // Shannon entropy (bits per byte) of the in-file bytes
    std::uint64_t entropy_bytes = 0;  // how many bytes the entropy was computed over
};

struct ImportedLibrary {
    std::string name;
    std::vector<std::string> functions;  // empty when the format does not bind names to it
};

/// A security-relevant property. `enabled` is empty when the check does not apply
/// (for example PIE on a shared library).
struct HardeningFlag {
    std::string key;
    std::string label;
    std::optional<bool> enabled;
    std::string detail;
};

using PropertyValue = std::variant<std::string, std::uint64_t, bool>;

struct Property {
    std::string key;
    PropertyValue value;
};

enum class IssueKind : std::uint8_t {
    malformed,      // header field inconsistent or truncated
    out_of_bounds,  // a structure the file describes lies outside the file
    limit,          // a count cap was reached and parsing was truncated
};

struct ParseIssue {
    IssueKind kind;
    std::string message;
    std::uint64_t offset = 0;  // relative to the target's image unless `absolute`
    bool absolute = false;     // offset is already a whole-file offset
};

/// One parsed image. A thin file has one target; a universal Mach-O has one per slice.
struct Target {
    Format format = Format::elf;
    std::string format_name;  // "ELF64", "Mach-O 64-bit", "PE32+", ...
    std::string arch;
    unsigned bits = 0;
    Endian endian = Endian::little;
    std::string file_type;           // "executable", "shared library", "dylib", "DLL", ...
    bool expects_entry = false;      // executables have an entry point; libraries may not
    std::uint64_t slice_offset = 0;  // offset of this image within the file
    std::uint64_t size = 0;
    double entropy = 0.0;
    std::optional<std::uint64_t> entry;  // virtual address (RVA for PE)
    std::vector<Region> sections;
    std::vector<Region> segments;
    std::vector<ImportedLibrary> libraries;
    std::vector<std::string> unbound_imports;  // ELF: undefined dynamic symbols
    std::uint64_t import_count = 0;            // imported functions/symbols in total
    std::vector<std::string> rpaths;
    std::vector<HardeningFlag> hardening;
    std::vector<Property> properties;
    std::vector<ParseIssue> issues;

    [[nodiscard]] const HardeningFlag* flag(const std::string& key) const;
    [[nodiscard]] const Property* property(const std::string& key) const;
};

struct FileInfo {
    Format container = Format::elf;
    std::uint64_t size = 0;
    double entropy = 0.0;
    std::vector<Target> targets;
};

}  // namespace binscope
