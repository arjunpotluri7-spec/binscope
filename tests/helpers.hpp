#pragma once

#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "binscope/bytes.hpp"
#include "binscope/findings.hpp"
#include "binscope/parse.hpp"
#include "binscope/report.hpp"

namespace bs_test {

inline std::string sample_path(const std::string& rel) {
    return std::string(BINSCOPE_SAMPLES_DIR) + "/" + rel;
}

inline std::vector<std::uint8_t> read_sample(const std::string& rel) {
    std::ifstream in(sample_path(rel), std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

inline binscope::ByteView view(const std::vector<std::uint8_t>& bytes) {
    return binscope::ByteView(std::span<const std::uint8_t>(bytes));
}

/// Parses a sample; keeps the bytes alive alongside the result.
struct Parsed {
    std::vector<std::uint8_t> bytes;
    binscope::FileInfo info;
    [[nodiscard]] const binscope::Target& target(std::size_t i = 0) const {
        return info.targets.at(i);
    }
};

inline Parsed parse_sample(const std::string& rel, const binscope::Limits& limits = {}) {
    Parsed p;
    p.bytes = read_sample(rel);
    auto r = binscope::parse(view(p.bytes), limits);
    if (r) {
        p.info = *r;
    }
    return p;
}

inline binscope::FileReport report_sample(const std::string& rel,
                                          const binscope::Config& config = {}) {
    const auto bytes = read_sample(rel);
    return binscope::analyze_bytes(rel, view(bytes), config);
}

inline const binscope::Finding* find(const binscope::TargetReport& t, const std::string& id) {
    for (const auto& f : t.findings) {
        if (f.id == id) {
            return &f;
        }
    }
    return nullptr;
}

inline bool has(const binscope::TargetReport& t, const std::string& id) {
    return find(t, id) != nullptr;
}

inline const binscope::Region* section(const binscope::Target& t, const std::string& name) {
    for (const auto& s : t.sections) {
        if (s.name == name) {
            return &s;
        }
    }
    return nullptr;
}

inline const binscope::Region* segment(const binscope::Target& t, const std::string& name) {
    for (const auto& s : t.segments) {
        if (s.name == name) {
            return &s;
        }
    }
    return nullptr;
}

inline std::optional<bool> flag(const binscope::Target& t, const std::string& key) {
    const auto* f = t.flag(key);
    return f == nullptr ? std::nullopt : f->enabled;
}

inline void put(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v, int width,
                bool little = true) {
    if (b.size() < off + static_cast<std::size_t>(width)) {
        b.resize(off + static_cast<std::size_t>(width));
    }
    for (int i = 0; i < width; ++i) {
        const int shift = 8 * (little ? i : width - 1 - i);
        b[off + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> shift);
    }
}

}  // namespace bs_test
