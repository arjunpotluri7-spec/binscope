// Release-to-release comparison of two builds.
#pragma once

#include <string>
#include <vector>

#include "binscope/findings.hpp"
#include "binscope/report.hpp"

namespace binscope {

struct EntropyChange {
    std::string region;
    double before = 0.0;
    double after = 0.0;
};

struct TargetDiff {
    std::string arch;
    std::string format_name;
    int score_before = 0;
    int score_after = 0;
    std::vector<std::string> libraries_added;
    std::vector<std::string> libraries_removed;
    std::vector<std::string> imports_added;  // "library!function" or bare symbol name
    std::vector<std::string> imports_removed;
    std::vector<std::string> hardening_removed;  // keys that went from enabled to not
    std::vector<std::string> hardening_added;
    std::vector<std::string> sections_added;
    std::vector<std::string> sections_removed;
    std::vector<EntropyChange> entropy_changes;
    std::vector<Finding> findings_new;
    std::vector<std::string> findings_resolved;  // rule ids
};

struct DiffReport {
    std::string old_path;
    std::string new_path;
    std::vector<TargetDiff> targets;    // matched by architecture
    std::vector<std::string> only_old;  // architectures present in only one build
    std::vector<std::string> only_new;
    double entropy_delta = 0.5;
    Severity fail_on = Severity::high;

    /// True when a hardening flag was lost or a new finding at/above fail_on appeared.
    [[nodiscard]] bool regression() const;
};

[[nodiscard]] DiffReport diff_reports(const FileReport& before, const FileReport& after,
                                      double entropy_delta, Severity fail_on);
[[nodiscard]] std::string render_diff_table(const DiffReport& diff);
[[nodiscard]] std::string render_diff_json(const DiffReport& diff);

}  // namespace binscope
