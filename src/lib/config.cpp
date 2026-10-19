#include "binscope/config.hpp"

#include <charconv>
#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace binscope {

namespace {

constexpr std::uint64_t kMaxConfigBytes = 1024ULL * 1024;

std::string trim(std::string_view s) {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) {
        ++b;
    }
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) {
        --e;
    }
    return std::string(s.substr(b, e - b));
}

/// Removes a trailing # comment that is not inside a string.
std::string strip_comment(std::string_view line) {
    bool quoted = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '"') {
            quoted = !quoted;
        } else if (line[i] == '#' && !quoted) {
            return std::string(line.substr(0, i));
        }
    }
    return std::string(line);
}

struct Ctx {
    std::string where;  // "file:line"
    Error fail(const std::string& message) const { return make_error(where + ": " + message); }
};

Result<std::uint64_t> as_uint(const std::string& v, const Ctx& ctx, std::uint64_t max) {
    std::uint64_t out = 0;
    const auto* end = v.data() + v.size();
    const auto [ptr, ec] = std::from_chars(v.data(), end, out);
    if (ec != std::errc() || ptr != end || v.empty()) {
        return ctx.fail("expected a non-negative integer, got '" + v + "'");
    }
    if (out > max) {
        return ctx.fail("value " + v + " is larger than the maximum " + std::to_string(max));
    }
    return out;
}

Result<double> as_double(const std::string& v, const Ctx& ctx, double lo, double hi) {
    // from_chars for double is not available on every supported standard library, so
    // parse a plain decimal by hand: digits, optional fraction.
    double whole = 0.0;
    double scale = 0.0;
    bool any = false;
    for (const char c : v) {
        if (c >= '0' && c <= '9') {
            any = true;
            if (scale == 0.0) {
                whole = whole * 10.0 + (c - '0');
            } else {
                whole += (c - '0') * scale;
                scale /= 10.0;
            }
        } else if (c == '.' && scale == 0.0) {
            scale = 0.1;
        } else {
            return ctx.fail("expected a decimal number, got '" + v + "'");
        }
    }
    if (!any) {
        return ctx.fail("expected a decimal number, got '" + v + "'");
    }
    if (whole < lo || whole > hi) {
        return ctx.fail("value " + v + " is outside the range " + std::to_string(lo) + " to " +
                        std::to_string(hi));
    }
    return whole;
}

Result<std::string> as_string(const std::string& v, const Ctx& ctx) {
    if (v.size() < 2 || v.front() != '"' || v.back() != '"') {
        return ctx.fail("expected a quoted string, got '" + v + "'");
    }
    return v.substr(1, v.size() - 2);
}

Result<std::vector<std::string>> as_string_array(const std::string& v, const Ctx& ctx) {
    if (v.size() < 2 || v.front() != '[' || v.back() != ']') {
        return ctx.fail("expected an array like [\"BS019\"], got '" + v + "'");
    }
    std::vector<std::string> out;
    const std::string inner = trim(std::string_view(v).substr(1, v.size() - 2));
    if (inner.empty()) {
        return out;
    }
    std::stringstream ss(inner);
    std::string item;
    while (std::getline(ss, item, ',')) {
        auto s = as_string(trim(item), ctx);
        if (!s) {
            return s.error();
        }
        out.push_back(*s);
    }
    return out;
}

Result<std::uint32_t> as_u32(const std::string& v, const Ctx& ctx) {
    auto r = as_uint(v, ctx, std::numeric_limits<std::uint32_t>::max());
    if (!r) {
        return r.error();
    }
    if (*r == 0) {
        return ctx.fail("limit must be at least 1");
    }
    return static_cast<std::uint32_t>(*r);
}

}  // namespace

Result<Config> parse_config(std::string_view text, std::string_view source) {
    Config cfg;
    std::string section;
    std::size_t line_no = 0;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t nl = text.find('\n', start);
        const std::string_view raw =
            text.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start);
        start = nl == std::string_view::npos ? text.size() + 1 : nl + 1;
        ++line_no;
        const Ctx ctx{std::string(source) + ":" + std::to_string(line_no)};
        const std::string line = trim(strip_comment(raw));
        if (line.empty()) {
            continue;
        }
        if (line.front() == '[') {
            if (line.back() != ']') {
                return ctx.fail("malformed section header '" + line + "'");
            }
            section = trim(std::string_view(line).substr(1, line.size() - 2));
            if (section != "thresholds" && section != "limits" && section != "points" &&
                section != "severity" && section != "rules") {
                return ctx.fail("unknown section [" + section + "]");
            }
            continue;
        }
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            return ctx.fail("expected 'key = value', got '" + line + "'");
        }
        const std::string key = trim(std::string_view(line).substr(0, eq));
        const std::string value = trim(std::string_view(line).substr(eq + 1));
        if (section.empty()) {
            return ctx.fail("key '" + key + "' must be inside a [section]");
        }

        if (section == "thresholds") {
            if (key == "entropy_high") {
                auto v = as_double(value, ctx, 0.0, 8.0);
                if (!v) {
                    return v.error();
                }
                cfg.entropy_threshold = *v;
            } else if (key == "diff_entropy_delta") {
                auto v = as_double(value, ctx, 0.0, 8.0);
                if (!v) {
                    return v.error();
                }
                cfg.diff_entropy_delta = *v;
            } else if (key == "min_entropy_bytes" || key == "large_section_bytes" ||
                       key == "few_imports") {
                auto v = as_uint(value, ctx, std::numeric_limits<std::uint32_t>::max());
                if (!v) {
                    return v.error();
                }
                if (key == "min_entropy_bytes") {
                    cfg.min_entropy_bytes = *v;
                } else if (key == "large_section_bytes") {
                    cfg.large_section_bytes = *v;
                } else {
                    cfg.few_imports = *v;
                }
            } else {
                return ctx.fail("unknown key '" + key + "' in [thresholds]");
            }
        } else if (section == "limits") {
            if (key == "max_file_size_mib") {
                auto v = as_uint(value, ctx, 4096);
                if (!v) {
                    return v.error();
                }
                if (*v == 0) {
                    return ctx.fail("max_file_size_mib must be at least 1");
                }
                cfg.limits.max_file_size = *v * 1024 * 1024;
                continue;
            }
            std::uint32_t* target = nullptr;
            if (key == "max_sections") {
                target = &cfg.limits.max_sections;
            } else if (key == "max_load_commands") {
                target = &cfg.limits.max_load_commands;
            } else if (key == "max_libraries") {
                target = &cfg.limits.max_libraries;
            } else if (key == "max_imports") {
                target = &cfg.limits.max_imports;
            } else if (key == "max_symbols") {
                target = &cfg.limits.max_symbols;
            } else if (key == "max_dynamic") {
                target = &cfg.limits.max_dynamic;
            } else if (key == "max_fat_slices") {
                target = &cfg.limits.max_fat_slices;
            } else {
                return ctx.fail("unknown key '" + key + "' in [limits]");
            }
            auto v = as_u32(value, ctx);
            if (!v) {
                return v.error();
            }
            *target = *v;
        } else if (section == "points" || section == "severity") {
            if (find_rule(key) == nullptr) {
                return ctx.fail("unknown rule id '" + key + "'");
            }
            if (section == "points") {
                auto v = as_uint(value, ctx, 100);
                if (!v) {
                    return v.error();
                }
                cfg.points[key] = static_cast<int>(*v);
            } else {
                auto v = as_string(value, ctx);
                if (!v) {
                    return v.error();
                }
                const auto sev = parse_severity(*v);
                if (!sev) {
                    return ctx.fail("severity must be info, low, medium or high, got '" + *v + "'");
                }
                cfg.severities[key] = *sev;
            }
        } else if (section == "rules") {
            if (key != "disabled") {
                return ctx.fail("unknown key '" + key + "' in [rules]");
            }
            auto v = as_string_array(value, ctx);
            if (!v) {
                return v.error();
            }
            for (const auto& id : *v) {
                if (find_rule(id) == nullptr) {
                    return ctx.fail("unknown rule id '" + id + "'");
                }
                cfg.disabled.insert(id);
            }
        }
    }
    return cfg;
}

Result<Config> load_config(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return make_error(path + ": cannot open config file");
    }
    std::string text;
    char buf[4096];
    while (in.read(buf, sizeof buf) || in.gcount() > 0) {
        text.append(buf, static_cast<std::size_t>(in.gcount()));
        if (text.size() > kMaxConfigBytes) {
            return make_error(path + ": config file is larger than 1 MiB");
        }
    }
    return parse_config(text, path);
}

}  // namespace binscope
