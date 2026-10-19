// Format detection and parsing entry points.
#pragma once

#include <cstdint>
#include <optional>

#include "binscope/bytes.hpp"
#include "binscope/model.hpp"
#include "binscope/result.hpp"

namespace binscope {

/// Caps that bound the work done on any input, whatever its headers claim.
struct Limits {
    std::uint64_t max_file_size = 256ULL * 1024 * 1024;
    std::uint32_t max_sections = 4096;       // per table: sections, program headers
    std::uint32_t max_load_commands = 4096;  // Mach-O load commands
    std::uint32_t max_libraries = 1024;      // imported libraries / DLLs
    std::uint32_t max_imports = 20000;       // imported functions in total
    std::uint32_t max_symbols = 200000;      // symbol table entries scanned
    std::uint32_t max_dynamic = 4096;        // ELF dynamic entries
    std::uint32_t max_fat_slices = 30;
};

/// Recognises the container format from magic bytes, without parsing further.
[[nodiscard]] std::optional<Format> detect_format(ByteView data);

/// Parses any supported format. Fails only when the format is not recognised or the
/// input exceeds max_file_size; a recognised but malformed file still yields a FileInfo
/// whose targets carry ParseIssues.
[[nodiscard]] Result<FileInfo> parse(ByteView data, const Limits& limits = {});

}  // namespace binscope
