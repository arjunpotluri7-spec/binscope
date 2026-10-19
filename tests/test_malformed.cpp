// Malformed and hostile inputs must produce findings, never crashes or exceptions.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "binscope/parse.hpp"
#include "binscope/report.hpp"
#include "helpers.hpp"

using namespace bs_test;
using binscope::IssueKind;

namespace {
bool has_issue(const binscope::Target& t, IssueKind kind) {
    for (const auto& i : t.issues) {
        if (i.kind == kind) {
            return true;
        }
    }
    return false;
}
}  // namespace

TEST(Malformed, TruncatedElfHeader) {
    const auto r = report_sample("synthetic/malformed_truncated_header.elf");
    ASSERT_FALSE(r.error.has_value());
    ASSERT_EQ(r.targets.size(), 1U);
    const auto& t = r.targets[0];
    EXPECT_TRUE(t.target.arch.empty());
    EXPECT_TRUE(has(t, "BS010"));
    EXPECT_NE(find(t, "BS010")->summary.find("truncated"), std::string::npos);
}

TEST(Malformed, SectionPastEndOfFileAndOverlap) {
    const auto r = report_sample("synthetic/malformed_section_past_eof.elf");
    const auto& t = r.targets.at(0);
    ASSERT_TRUE(has(t, "BS009"));
    EXPECT_NE(find(t, "BS009")->summary.find(".rodata"), std::string::npos);
    const auto* rodata = section(t.target, ".rodata");
    ASSERT_NE(rodata, nullptr);
    EXPECT_TRUE(rodata->past_eof);
    EXPECT_EQ(rodata->entropy_bytes, 0U);
    ASSERT_TRUE(has(t, "BS008"));
    EXPECT_EQ(find(t, "BS008")->summary, "sections .text and .data overlap in the file");
}

TEST(Malformed, AbsurdElfCounts) {
    const auto r = report_sample("synthetic/malformed_absurd_counts.elf");
    const auto& t = r.targets.at(0);
    EXPECT_TRUE(has(t, "BS011"));  // 32768 program headers > cap
    EXPECT_TRUE(has(t, "BS009"));  // table runs past EOF
    EXPECT_TRUE(has(t, "BS010"));  // e_shentsize 0x1234
    EXPECT_LE(t.target.segments.size(), 4096U);
    EXPECT_TRUE(t.target.sections.empty());
}

TEST(Malformed, AbsurdPeSectionCount) {
    const auto r = report_sample("synthetic/malformed_absurd_counts.exe");
    const auto& t = r.targets.at(0);
    EXPECT_TRUE(has(t, "BS011"));
    ASSERT_TRUE(has(t, "BS009"));
    EXPECT_NE(find(t, "BS009")->summary.find("section table (65535 entries"), std::string::npos);
    EXPECT_LE(find(t, "BS009")->evidence.size(), 9U);  // evidence is capped
}

TEST(Malformed, PeWithBadLfanew) {
    const auto r = report_sample("synthetic/malformed_bad_lfanew.exe");
    const auto& t = r.targets.at(0);
    EXPECT_EQ(t.target.format_name, "MZ");
    ASSERT_TRUE(has(t, "BS009"));
    EXPECT_NE(find(t, "BS009")->summary.find("e_lfanew"), std::string::npos);
}

TEST(Malformed, PeOverlappingRawData) {
    const auto r = report_sample("synthetic/malformed_overlap.exe");
    const auto& t = r.targets.at(0);
    ASSERT_TRUE(has(t, "BS008"));
    EXPECT_EQ(find(t, "BS008")->summary, "sections .text and .data overlap in the file");
    EXPECT_FALSE(has(t, "BS009"));
}

TEST(Malformed, MachOAbsurdLoadCommandCount) {
    const auto r = report_sample("synthetic/malformed_ncmds.macho");
    const auto& t = r.targets.at(0);
    EXPECT_TRUE(has(t, "BS011"));
    EXPECT_TRUE(has(t, "BS009"));
    EXPECT_TRUE(has(t, "BS010"));
}

TEST(Malformed, UniversalSlicePastEndKeepsValidSlice) {
    const auto r = report_sample("synthetic/malformed_fat_past_eof");
    ASSERT_EQ(r.targets.size(), 1U);
    const auto& t = r.targets[0];
    EXPECT_EQ(t.target.arch, "arm64");
    ASSERT_TRUE(has(t, "BS009"));
    EXPECT_NE(find(t, "BS009")->summary.find("universal header: slice 1 (x86_64)"),
              std::string::npos);
    EXPECT_EQ(find(t, "BS009")->evidence.front().offset, 0x100000U);  // absolute offset
    EXPECT_TRUE(has(t, "BS001"));  // the surviving slice is still analysed
}

TEST(Malformed, ZeroCmdsizeStopsLoadCommandWalk) {
    auto bytes = read_sample("synthetic/macho64_wx_synthetic");
    put(bytes, 32 + 4, 0, 4);  // first load command's cmdsize = 0
    const auto r = binscope::parse(view(bytes));
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(has_issue(r->targets[0], IssueKind::malformed));
    EXPECT_TRUE(r->targets[0].segments.empty());
}

TEST(Malformed, UnrecognisedInputIsAnErrorNotACrash) {
    const std::vector<std::uint8_t> empty;
    EXPECT_FALSE(binscope::parse(view(empty)).ok());
    const std::vector<std::uint8_t> text = {'h', 'e', 'l', 'l', 'o', '\n'};
    const auto r = binscope::parse(view(text));
    ASSERT_FALSE(r.ok());
    EXPECT_NE(r.error().message.find("not a recognised"), std::string::npos);
}

TEST(Malformed, BareMagicNumbers) {
    for (const std::vector<std::uint8_t>& b :
         {std::vector<std::uint8_t>{0x7F, 'E', 'L', 'F'}, std::vector<std::uint8_t>{'M', 'Z'},
          std::vector<std::uint8_t>{0xCF, 0xFA, 0xED, 0xFE},
          std::vector<std::uint8_t>{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2}}) {
        const auto r = binscope::analyze_bytes("magic", view(b), binscope::Config{});
        ASSERT_FALSE(r.error.has_value());
        ASSERT_FALSE(r.targets.empty());
        EXPECT_FALSE(r.targets[0].target.issues.empty());
        EXPECT_FALSE(r.targets[0].findings.empty());
    }
}

TEST(Malformed, FileSizeCap) {
    binscope::Limits limits;
    limits.max_file_size = 1000;
    const auto bytes = read_sample("synthetic/elf64_hardened.so");
    const auto r = binscope::parse(view(bytes), limits);
    ASSERT_FALSE(r.ok());
    EXPECT_NE(r.error().message.find("limit"), std::string::npos);
}

TEST(Malformed, SectionCountCap) {
    binscope::Config cfg;
    cfg.limits.max_sections = 2;
    const auto r = report_sample("synthetic/elf64_hardened.so", cfg);
    const auto& t = r.targets.at(0);
    EXPECT_LE(t.target.sections.size(), 2U);
    EXPECT_LE(t.target.segments.size(), 2U);
    EXPECT_TRUE(has(t, "BS011"));
}

TEST(Malformed, LoadCommandCap) {
    binscope::Config cfg;
    cfg.limits.max_load_commands = 3;
    const auto r = report_sample("macho/hello_arm64", cfg);
    const auto& t = r.targets.at(0);
    EXPECT_EQ(t.target.segments.size(), 3U);
    EXPECT_TRUE(has(t, "BS011"));
}

TEST(Malformed, TruncatedCopiesOfSamplesAreHandled) {
    const std::vector<std::string> samples = {
        "synthetic/elf64_hardened.so",    "synthetic/elf32_be_ppc.elf",
        "synthetic/pe64_hardened.exe",    "synthetic/pe32_ordinal.dll",
        "synthetic/macho64_wx_synthetic", "macho/hello_universal"};
    for (const auto& name : samples) {
        const auto full = read_sample(name);
        ASSERT_FALSE(full.empty()) << name;
        const std::size_t step = full.size() > 4096 ? 61 : 7;
        for (std::size_t len = 0; len < full.size(); len += step) {
            const std::vector<std::uint8_t> cut(full.begin(),
                                                full.begin() + static_cast<std::ptrdiff_t>(len));
            const auto r = binscope::analyze_bytes(name, view(cut), binscope::Config{});
            if (!r.error) {
                (void)binscope::render_json({r});
                (void)binscope::render_table({r}, binscope::TableOptions{true, true});
            }
        }
    }
    SUCCEED();
}
