#include <string>
#include <utility>

#include "binscope/entropy.hpp"
#include "binscope/model.hpp"
#include "binscope/parse.hpp"
#include "parsers.hpp"

namespace binscope {

const char* format_id(Format format) noexcept {
    switch (format) {
        case Format::elf:
            return "elf";
        case Format::macho:
            return "macho";
        case Format::macho_fat:
            return "macho-fat";
        case Format::pe:
            return "pe";
    }
    return "unknown";
}

const HardeningFlag* Target::flag(const std::string& key) const {
    for (const auto& f : hardening) {
        if (f.key == key) {
            return &f;
        }
    }
    return nullptr;
}

const Property* Target::property(const std::string& key) const {
    for (const auto& p : properties) {
        if (p.key == key) {
            return &p;
        }
    }
    return nullptr;
}

std::optional<Format> detect_format(ByteView data) {
    const auto b0 = data.u8(0);
    const auto b1 = data.u8(1);
    if (!b0 || !b1) {
        return std::nullopt;
    }
    if (*b0 == 'M' && *b1 == 'Z') {
        return Format::pe;
    }
    const auto le = data.u32(0, Endian::little);
    if (!le) {
        return std::nullopt;
    }
    switch (*le) {
        case 0x464C457FU:  // "\x7fELF"
            return Format::elf;
        case 0xFEEDFACEU:
        case 0xFEEDFACFU:
        case 0xCEFAEDFEU:
        case 0xCFFAEDFEU:
            return Format::macho;
        default:
            break;
    }
    const auto be = data.u32(0, Endian::big);
    if (be && (*be == 0xCAFEBABEU || *be == 0xCAFEBABFU)) {
        // Java class files share 0xCAFEBABE; their next word (minor/major version) is
        // at least 45, while universal binaries hold a small slice count there.
        const auto count = data.u32(4, Endian::big);
        if (count && *count >= 1 && *count < 45) {
            return Format::macho_fat;
        }
    }
    return std::nullopt;
}

Result<FileInfo> parse(ByteView data, const Limits& limits) {
    if (data.size() > limits.max_file_size) {
        return make_error("file is " + std::to_string(data.size()) +
                          " bytes, larger than the configured limit of " +
                          std::to_string(limits.max_file_size) + " bytes");
    }
    const auto format = detect_format(data);
    if (!format) {
        return make_error("not a recognised executable format (expected ELF, Mach-O or PE)");
    }
    if (*format == Format::macho_fat) {
        auto info = detail::parse_macho_fat(data, limits);
        info.size = data.size();
        info.entropy = shannon_entropy(data.span());
        return info;
    }
    FileInfo info;
    info.container = *format;
    info.size = data.size();
    info.entropy = shannon_entropy(data.span());
    switch (*format) {
        case Format::elf:
            info.targets.push_back(detail::parse_elf(data, limits));
            break;
        case Format::macho:
            info.targets.push_back(detail::parse_macho_thin(data, limits));
            break;
        case Format::pe:
            info.targets.push_back(detail::parse_pe(data, limits));
            break;
        case Format::macho_fat:
            break;
    }
    return info;
}

namespace detail {

void finish_region(Region& region, ByteView image) {
    if (!region.has_file_data || region.file_size == 0) {
        region.entropy = 0.0;
        region.entropy_bytes = 0;
        return;
    }
    region.past_eof = !range_ok(region.offset, region.file_size, image.size());
    const ByteView bytes = image.clamp(region.offset, region.file_size);
    region.entropy = shannon_entropy(bytes.span());
    region.entropy_bytes = bytes.size();
}

void add_issue(Target& target, IssueKind kind, std::string message, std::uint64_t offset) {
    // A hostile file can repeat the same defect thousands of times; keep reports bounded.
    constexpr std::size_t kMaxIssues = 64;
    if (target.issues.size() >= kMaxIssues) {
        return;
    }
    target.issues.push_back(ParseIssue{kind, std::move(message), offset});
}

void set_property(Target& target, std::string key, PropertyValue value) {
    for (auto& p : target.properties) {
        if (p.key == key) {
            p.value = std::move(value);
            return;
        }
    }
    target.properties.push_back(Property{std::move(key), std::move(value)});
}

std::uint64_t records_that_fit(std::uint64_t offset, std::uint64_t entry_size, std::uint64_t wanted,
                               std::uint64_t size) {
    if (entry_size == 0 || offset >= size) {
        return 0;
    }
    const std::uint64_t fit = (size - offset) / entry_size;
    return fit < wanted ? fit : wanted;
}

std::string printable(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (const char ch : raw) {
        const auto c = static_cast<unsigned char>(ch);
        if (c >= 0x20 && c < 0x7F) {
            out.push_back(ch);
        } else {
            out += "\\x";
            append_hex_byte(out, c);
        }
    }
    return out;
}

}  // namespace detail
}  // namespace binscope
