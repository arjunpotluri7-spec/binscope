// The single entry point shared by the libFuzzer harness and the portable smoke driver:
// auto-detect, parse, analyse and render every output format.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "binscope/bytes.hpp"
#include "binscope/diff.hpp"
#include "binscope/findings.hpp"
#include "binscope/report.hpp"

namespace binscope::fuzz {

/// Returns the number of findings so the optimiser cannot discard the work.
inline std::size_t run_one(const std::uint8_t* data, std::size_t size) {
    static const Config config = [] {
        Config c;
        c.limits.max_file_size = 16ULL * 1024 * 1024;
        return c;
    }();
    const ByteView view(std::span<const std::uint8_t>(data, size));
    std::vector<FileReport> reports;
    reports.push_back(analyze_bytes("fuzz-input", view, config));
    std::size_t sink = render_table(reports, TableOptions{true, true}).size();
    sink += render_json(reports).size();
    sink += render_sarif(reports).size();
    sink += render_score_lines(reports).size();
    sink += render_diff_json(diff_reports(reports.front(), reports.front(), 0.5, Severity::high))
                .size();
    std::size_t findings = 0;
    for (const auto& t : reports.front().targets) {
        findings += t.findings.size();
    }
    return findings + (sink == 0 ? 1 : 0);
}

}  // namespace binscope::fuzz
