// Per-file analysis results and the table / JSON / SARIF / score renderers.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "binscope/bytes.hpp"
#include "binscope/findings.hpp"
#include "binscope/model.hpp"

namespace binscope {

inline constexpr int kJsonSchemaVersion = 1;

struct TargetReport {
    Target target;
    std::vector<Finding> findings;
    Score score;
};

struct FileReport {
    std::string path;
    std::optional<std::string> error;  // set when the file could not be analysed at all
    Format container = Format::elf;
    std::uint64_t size = 0;
    double entropy = 0.0;
    std::vector<TargetReport> targets;

    /// Highest target score (a universal file is as suspicious as its worst slice).
    [[nodiscard]] int score() const;
    [[nodiscard]] bool has_finding_at_or_above(Severity severity) const;
};

/// Parses and analyses bytes already read from `path`.
[[nodiscard]] FileReport analyze_bytes(const std::string& path, ByteView data,
                                       const Config& config);

/// A report for a file that could not be read or recognised.
[[nodiscard]] FileReport error_report(const std::string& path, std::string message);

struct TableOptions {
    bool sections = false;
    bool imports = false;
};

[[nodiscard]] std::string render_table(const std::vector<FileReport>& reports,
                                       const TableOptions& options);
[[nodiscard]] std::string render_json(const std::vector<FileReport>& reports);
[[nodiscard]] std::string render_sarif(const std::vector<FileReport>& reports);
/// One compact line per target: path, format, arch, score, label, top three factors.
[[nodiscard]] std::string render_score_lines(const std::vector<FileReport>& reports);
/// The `formats` subcommand text.
[[nodiscard]] std::string render_formats();

}  // namespace binscope
