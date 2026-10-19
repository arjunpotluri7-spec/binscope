// Output contracts: the JSON schema, SARIF 2.1.0 structure, table and score lines.
#include <gtest/gtest.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include "binscope/report.hpp"
#include "helpers.hpp"
#include "mini_json.hpp"

using namespace bs_test;
using mini_json::Value;
using T = mini_json::Value::Type;

namespace {
std::vector<binscope::FileReport> mixed_reports() {
    return {report_sample("synthetic/elf64_packed_like.elf"),
            report_sample("macho/hello_universal"),
            binscope::error_report("missing.bin", "cannot open")};
}

void expect_keys(const Value& obj, const std::vector<std::pair<std::string, T>>& keys) {
    ASSERT_TRUE(obj.is(T::object));
    for (const auto& [k, type] : keys) {
        ASSERT_TRUE(obj.has(k)) << "missing " << k;
        EXPECT_TRUE(obj.at(k).is(type)) << k;
    }
}
}  // namespace

TEST(JsonOutput, TopLevelSchema) {
    const auto doc = mini_json::parse(binscope::render_json(mixed_reports()));
    expect_keys(doc, {{"schema_version", T::number},
                      {"tool", T::object},
                      {"files", T::array},
                      {"summary", T::object}});
    EXPECT_EQ(doc.at("schema_version").n, 1.0);
    EXPECT_EQ(doc.at("tool").at("name").s, "binscope");
    EXPECT_EQ(doc.at("files").items.size(), 3U);
    EXPECT_EQ(doc.at("summary").at("errors").n, 1.0);
    expect_keys(
        doc.at("summary").at("findings_by_severity"),
        {{"high", T::number}, {"medium", T::number}, {"low", T::number}, {"info", T::number}});
}

TEST(JsonOutput, FileTargetAndFindingSchema) {
    const auto doc = mini_json::parse(binscope::render_json(mixed_reports()));
    const auto& file = doc.at("files")[0];
    expect_keys(file, {{"path", T::string},
                       {"error", T::null},
                       {"container", T::string},
                       {"size", T::number},
                       {"entropy", T::number},
                       {"score", T::number},
                       {"label", T::string},
                       {"targets", T::array}});
    const auto& t = file.at("targets")[0];
    expect_keys(
        t, {{"format", T::string},         {"format_name", T::string},  {"arch", T::string},
            {"bits", T::number},           {"endian", T::string},       {"file_type", T::string},
            {"slice_offset", T::number},   {"size", T::number},         {"entropy", T::number},
            {"entry", T::number},          {"hardening", T::array},     {"properties", T::object},
            {"segments", T::array},        {"sections", T::array},      {"libraries", T::array},
            {"unbound_imports", T::array}, {"import_count", T::number}, {"rpaths", T::array},
            {"issues", T::array},          {"findings", T::array},      {"score", T::object}});
    expect_keys(t.at("sections")[0], {{"name", T::string},
                                      {"kind", T::string},
                                      {"type", T::string},
                                      {"offset", T::number},
                                      {"file_size", T::number},
                                      {"vaddr", T::number},
                                      {"mem_size", T::number},
                                      {"flags", T::number},
                                      {"readable", T::boolean},
                                      {"writable", T::boolean},
                                      {"executable", T::boolean},
                                      {"has_file_data", T::boolean},
                                      {"past_eof", T::boolean},
                                      {"entropy", T::number},
                                      {"entropy_bytes", T::number}});
    const auto& f = t.at("findings")[0];
    expect_keys(f, {{"id", T::string},
                    {"severity", T::string},
                    {"title", T::string},
                    {"summary", T::string},
                    {"explanation", T::string},
                    {"points", T::number},
                    {"evidence", T::array}});
    expect_keys(f.at("evidence")[0], {{"location", T::string}, {"detail", T::string}});
    expect_keys(
        t.at("score"),
        {{"total", T::number}, {"raw", T::number}, {"label", T::string}, {"factors", T::array}});
    EXPECT_EQ(t.at("score").at("total").n, 100.0);
    const std::set<std::string> severities = {"info", "low", "medium", "high"};
    for (const auto& finding : t.at("findings").items) {
        EXPECT_EQ(severities.count(finding.at("severity").s), 1U);
    }
    const auto& hard = t.at("hardening")[0];
    expect_keys(hard, {{"key", T::string}, {"label", T::string}, {"detail", T::string}});
    EXPECT_TRUE(hard.at("enabled").is(T::boolean) || hard.at("enabled").is(T::null));
}

TEST(JsonOutput, ErrorFileAndUniversalFile) {
    const auto doc = mini_json::parse(binscope::render_json(mixed_reports()));
    const auto& fat = doc.at("files")[1];
    EXPECT_EQ(fat.at("container").s, "macho-fat");
    EXPECT_EQ(fat.at("targets").items.size(), 2U);
    EXPECT_EQ(fat.at("targets")[1].at("slice_offset").n, 16384.0);
    const auto& err = doc.at("files")[2];
    EXPECT_EQ(err.at("error").s, "cannot open");
    EXPECT_TRUE(err.at("targets").items.empty());
}

TEST(JsonOutput, EscapesHostileStrings) {
    auto r = report_sample("synthetic/pe64_hardened.exe");
    r.path = std::string("we\"ird\\path\n\x01") + "\xff\xfe";
    const auto text = binscope::render_json({r});
    const auto doc = mini_json::parse(text);  // throws if the escaping is wrong
    EXPECT_EQ(doc.at("files")[0].at("path").s.substr(0, 12), "we\"ird\\path\n");
}

TEST(SarifOutput, Structure) {
    const auto doc = mini_json::parse(binscope::render_sarif(mixed_reports()));
    EXPECT_EQ(doc.at("version").s, "2.1.0");
    EXPECT_NE(doc.at("$schema").s.find("sarif-2.1.0"), std::string::npos);
    ASSERT_EQ(doc.at("runs").items.size(), 1U);
    const auto& run = doc.at("runs")[0];
    const auto& driver = run.at("tool").at("driver");
    EXPECT_EQ(driver.at("name").s, "Binscope");
    const auto& rules = driver.at("rules").items;
    ASSERT_EQ(rules.size(), binscope::rule_catalog().size());
    std::set<std::string> rule_ids;
    for (const auto& r : rules) {
        expect_keys(r, {{"id", T::string},
                        {"shortDescription", T::object},
                        {"fullDescription", T::object},
                        {"defaultConfiguration", T::object}});
        rule_ids.insert(r.at("id").s);
    }
    const std::set<std::string> levels = {"error", "warning", "note"};
    const auto& results = run.at("results").items;
    ASSERT_FALSE(results.empty());
    for (const auto& res : results) {
        EXPECT_EQ(rule_ids.count(res.at("ruleId").s), 1U);
        const auto idx = static_cast<std::size_t>(res.at("ruleIndex").n);
        EXPECT_EQ(rules.at(idx).at("id").s, res.at("ruleId").s);
        EXPECT_EQ(levels.count(res.at("level").s), 1U);
        EXPECT_FALSE(res.at("message").at("text").s.empty());
        const auto& loc = res.at("locations")[0].at("physicalLocation");
        EXPECT_FALSE(loc.at("artifactLocation").at("uri").s.empty());
        if (loc.has("region")) {
            EXPECT_TRUE(loc.at("region").at("byteOffset").is(T::number));
        }
    }
    EXPECT_EQ(run.at("artifacts").items.size(), 3U);
    const auto& notes = run.at("invocations")[0].at("toolExecutionNotifications").items;
    ASSERT_EQ(notes.size(), 1U);
    EXPECT_NE(notes[0].at("message").at("text").s.find("missing.bin"), std::string::npos);
}

TEST(SarifOutput, PercentEncodesUris) {
    auto r = report_sample("synthetic/pe64_packed_like.exe");
    r.path = "dir with space/a#b.exe";
    const auto doc = mini_json::parse(binscope::render_sarif({r}));
    EXPECT_EQ(doc.at("runs")[0].at("artifacts")[0].at("location").at("uri").s,
              "dir%20with%20space/a%23b.exe");
}

TEST(ScoreLines, OneLinePerTargetWithTopThree) {
    const auto text = binscope::render_score_lines(mixed_reports());
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start < text.size()) {
        const auto nl = text.find('\n', start);
        lines.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
    ASSERT_EQ(lines.size(), 4U);  // packed ELF, two slices, one error
    EXPECT_EQ(lines[0].rfind(
                  "synthetic/elf64_packed_like.elf  ELF64  x86_64  100/100 very high  +30 ", 0),
              0U);
    std::size_t separators = 0;
    for (auto at = lines[0].find(" | "); at != std::string::npos;
         at = lines[0].find(" | ", at + 1)) {
        ++separators;
    }
    EXPECT_EQ(separators, 2U);  // three factors
    EXPECT_EQ(
        lines[1].rfind("macho/hello_universal [x86_64]  Mach-O 64-bit  x86_64  10/100 low", 0), 0U);
    EXPECT_EQ(lines[2],
              "macho/hello_universal [arm64]  Mach-O 64-bit  arm64  0/100 low  no findings");
    EXPECT_EQ(lines[3], "missing.bin  error: cannot open");
}

TEST(TableOutput, SectionsAndImportsAreOptIn) {
    const auto r = report_sample("synthetic/pe64_hardened.exe");
    const auto plain = binscope::render_table({r}, {});
    EXPECT_EQ(plain.find("regions"), std::string::npos);
    EXPECT_EQ(plain.find("imported libraries"), std::string::npos);
    const auto full = binscope::render_table({r}, binscope::TableOptions{true, true});
    EXPECT_NE(full.find("regions"), std::string::npos);
    EXPECT_NE(full.find("KERNEL32.dll: GetStdHandle, WriteFile, ExitProcess, GetLastError"),
              std::string::npos);
}

TEST(FormatsText, MentionsEveryFormat) {
    const auto text = binscope::render_formats();
    for (const char* s : {"ELF", "Mach-O", "PE/COFF", "universal", "not verified"}) {
        EXPECT_NE(text.find(s), std::string::npos) << s;
    }
}
