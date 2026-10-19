// Findings, the rule catalogue, and the explainable suspicion score.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "binscope/model.hpp"
#include "binscope/parse.hpp"

namespace binscope {

enum class Severity : std::uint8_t { info, low, medium, high };

[[nodiscard]] const char* severity_name(Severity severity) noexcept;
[[nodiscard]] std::optional<Severity> parse_severity(std::string_view text) noexcept;

struct Evidence {
    std::string location;                 // e.g. "section UPX1", "segment __DATA_EXEC"
    std::optional<std::uint64_t> offset;  // absolute file offset
    std::string detail;
};

struct Finding {
    std::string id;  // BS001 ...
    Severity severity = Severity::info;
    std::string title;        // fixed rule title
    std::string summary;      // short, specific: "W+X segment __DATA_EXEC"
    std::string explanation;  // why it matters
    std::vector<Evidence> evidence;
    int points = 0;
};

struct Rule {
    const char* id;
    Severity severity;
    int points;
    const char* title;
    const char* explanation;
};

/// Every rule Binscope knows, in id order, with default severity and points.
[[nodiscard]] const std::vector<Rule>& rule_catalog();
[[nodiscard]] const Rule* find_rule(std::string_view id);

/// Analysis settings; every field can be set from the config file.
struct Config {
    Limits limits;
    double entropy_threshold = 7.2;
    std::uint64_t min_entropy_bytes = 512;  // smaller regions cannot reach high entropy
    std::uint64_t large_section_bytes = 64ULL * 1024;
    std::uint64_t few_imports = 5;
    double diff_entropy_delta = 0.5;
    std::map<std::string, int> points;           // per-rule overrides
    std::map<std::string, Severity> severities;  // per-rule overrides
    std::set<std::string> disabled;

    [[nodiscard]] int points_for(const Rule& rule) const;
    [[nodiscard]] Severity severity_for(const Rule& rule) const;
    [[nodiscard]] bool enabled(const Rule& rule) const;
};

/// Runs every rule against one target. Findings are ordered by rule id; each rule
/// fires at most once per target and lists all of its evidence.
[[nodiscard]] std::vector<Finding> analyze(const Target& target, const Config& config);

struct Score {
    int total = 0;  // clamp(sum of points, 0, 100)
    int raw = 0;    // unclamped sum
    std::string label;
};

[[nodiscard]] Score compute_score(const std::vector<Finding>& findings);
/// 0-19 low, 20-49 moderate, 50-79 high, 80+ very high.
[[nodiscard]] std::string score_label(int score);

/// Section names commonly associated with packers and protectors.
struct PackerName {
    const char* section;
    const char* tool;
};
[[nodiscard]] const std::vector<PackerName>& packer_names();

}  // namespace binscope
