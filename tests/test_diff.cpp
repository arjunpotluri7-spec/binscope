#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "binscope/diff.hpp"
#include "helpers.hpp"
#include "mini_json.hpp"

using namespace bs_test;
using binscope::diff_reports;
using binscope::Severity;

namespace {
bool contains(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}
}  // namespace

TEST(Diff, IdenticalBuildsHaveNoChanges) {
    const auto a = report_sample("macho/hello_universal");
    const auto d = diff_reports(a, a, 0.5, Severity::high);
    ASSERT_EQ(d.targets.size(), 2U);
    for (const auto& t : d.targets) {
        EXPECT_TRUE(t.imports_added.empty());
        EXPECT_TRUE(t.hardening_removed.empty());
        EXPECT_TRUE(t.entropy_changes.empty());
        EXPECT_TRUE(t.findings_new.empty());
    }
    EXPECT_FALSE(d.regression());
}

TEST(Diff, LostHardeningIsARegression) {
    const auto before = report_sample("synthetic/pe64_hardened.exe");
    const auto after = report_sample("synthetic/pe64_packed_like.exe");
    const auto d = diff_reports(before, after, 0.5, Severity::high);
    ASSERT_EQ(d.targets.size(), 1U);
    const auto& t = d.targets[0];
    for (const char* key : {"aslr", "high_entropy_va", "dep", "cfg", "certificate"}) {
        EXPECT_TRUE(contains(t.hardening_removed, key)) << key;
    }
    EXPECT_TRUE(contains(t.libraries_added, "KERNEL32.DLL"));
    EXPECT_TRUE(contains(t.libraries_removed, "USER32.dll"));
    EXPECT_TRUE(contains(t.imports_added, "KERNEL32.DLL!LoadLibraryA"));
    EXPECT_TRUE(contains(t.imports_removed, "USER32.dll!MessageBoxW"));
    EXPECT_TRUE(contains(t.sections_added, "UPX1"));
    EXPECT_TRUE(contains(t.sections_removed, ".text"));
    EXPECT_EQ(t.score_before, 0);
    EXPECT_EQ(t.score_after, 100);
    EXPECT_TRUE(d.regression());
}

TEST(Diff, GainedHardeningIsNotARegression) {
    const auto before = report_sample("macho/hello_x86_64_nopie");
    const auto after = report_sample("macho/hello_arm64");
    const auto d = diff_reports(before, after, 0.5, Severity::high);
    ASSERT_EQ(d.targets.size(), 1U);  // thin-to-thin across architectures still compares
    const auto& t = d.targets[0];
    EXPECT_TRUE(contains(t.hardening_added, "pie"));
    EXPECT_TRUE(contains(t.hardening_added, "code_signature"));
    EXPECT_TRUE(t.hardening_removed.empty());
    EXPECT_TRUE(contains(t.imports_removed, "/usr/lib/libSystem.B.dylib!_exit"));
    EXPECT_TRUE(contains(t.findings_resolved, "BS012"));
    EXPECT_FALSE(d.regression());
}

TEST(Diff, EntropyChangesUseTheDelta) {
    const auto before = report_sample("synthetic/pe64_hardened.exe");
    auto bytes = read_sample("synthetic/pe64_hardened.exe");
    for (std::size_t i = 0; i < 0x200; ++i) {
        bytes[0xa00 + i] = static_cast<std::uint8_t>((i * 167U + 13U) & 0xFFU);
    }
    const auto after = binscope::analyze_bytes("after", view(bytes), binscope::Config{});
    auto d = diff_reports(before, after, 0.5, Severity::high);
    ASSERT_EQ(d.targets[0].entropy_changes.size(), 1U);
    EXPECT_EQ(d.targets[0].entropy_changes[0].region, ".data");
    EXPECT_NEAR(d.targets[0].entropy_changes[0].before, 0.9934, 0.001);  // 128 data + 384 pad bytes
    EXPECT_DOUBLE_EQ(d.targets[0].entropy_changes[0].after, 8.0);
    d = diff_reports(before, after, 7.5, Severity::high);
    EXPECT_TRUE(d.targets[0].entropy_changes.empty());
}

TEST(Diff, NewFindingsRespectFailOn) {
    const auto before = report_sample("synthetic/pe64_hardened.exe");
    auto bytes = read_sample("synthetic/pe64_hardened.exe");
    put(bytes, 0x80 + 24 + 70, 0xC160 & ~0x4000U, 2);  // drop GUARD_CF
    const auto after = binscope::analyze_bytes("after", view(bytes), binscope::Config{});
    auto d = diff_reports(before, after, 0.5, Severity::high);
    ASSERT_EQ(d.targets[0].findings_new.size(), 1U);
    EXPECT_EQ(d.targets[0].findings_new[0].id, "BS018");
    EXPECT_TRUE(d.regression());  // cfg was lost
    EXPECT_EQ(d.targets[0].hardening_removed, (std::vector<std::string>{"cfg"}));
}

TEST(Diff, RendersTableAndJson) {
    const auto before = report_sample("synthetic/pe64_hardened.exe");
    const auto after = report_sample("synthetic/pe64_packed_like.exe");
    const auto d = diff_reports(before, after, 0.5, Severity::high);
    const auto table = binscope::render_diff_table(d);
    EXPECT_NE(table.find("hardening removed (5)"), std::string::npos);
    EXPECT_NE(table.find("result: REGRESSION"), std::string::npos);
    const auto doc = mini_json::parse(binscope::render_diff_json(d));
    EXPECT_TRUE(doc.at("regression").b);
    EXPECT_EQ(doc.at("targets")[0].at("score_after").n, 100.0);
    EXPECT_EQ(doc.at("targets")[0].at("hardening_removed").items.size(), 5U);
}
