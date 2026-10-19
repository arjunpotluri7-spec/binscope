// Each rule is shown firing on a sample built to trigger it, and staying quiet on a
// clean sample.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "binscope/findings.hpp"
#include "binscope/report.hpp"
#include "helpers.hpp"

using namespace bs_test;
using binscope::Config;
using binscope::FileReport;

namespace {

const FileReport& packed_elf() {
    static const FileReport r = report_sample("synthetic/elf64_packed_like.elf");
    return r;
}
const FileReport& packed_pe() {
    static const FileReport r = report_sample("synthetic/pe64_packed_like.exe");
    return r;
}
const FileReport& macho_wx() {
    static const FileReport r = report_sample("synthetic/macho64_wx_synthetic");
    return r;
}
const FileReport& clean_elf() {
    static const FileReport r = report_sample("synthetic/elf64_hardened.so");
    return r;
}
const FileReport& clean_pe() {
    static const FileReport r = report_sample("synthetic/pe64_hardened.exe");
    return r;
}
const FileReport& clean_macho() {
    static const FileReport r = report_sample("macho/hello_arm64");
    return r;
}

std::vector<std::uint8_t> pseudo_random(std::size_t n, std::uint64_t seed) {
    std::vector<std::uint8_t> out(n);
    for (auto& b : out) {
        seed ^= seed << 13U;
        seed ^= seed >> 7U;
        seed ^= seed << 17U;
        b = static_cast<std::uint8_t>(seed >> 24U);
    }
    return out;
}

/// pe64_hardened.exe with its .data raw bytes (0xa00..0xc00) replaced by noise.
std::vector<std::uint8_t> pe_with_noisy_data() {
    auto bytes = read_sample("synthetic/pe64_hardened.exe");
    const auto noise = pseudo_random(0x200, 0x1234567);
    std::copy(noise.begin(), noise.end(), bytes.begin() + 0xa00);
    return bytes;
}

FileReport report_bytes(const std::vector<std::uint8_t>& bytes, const Config& cfg = {}) {
    return binscope::analyze_bytes("test", view(bytes), cfg);
}

}  // namespace

TEST(Findings, CleanSamplesHaveNoScoredFindings) {
    EXPECT_TRUE(clean_elf().targets[0].findings.empty());
    EXPECT_TRUE(clean_pe().targets[0].findings.empty());
    EXPECT_TRUE(clean_macho().targets[0].findings.empty());
}

TEST(Findings, BS001WritableExecutable) {
    ASSERT_TRUE(has(macho_wx().targets[0], "BS001"));
    EXPECT_EQ(find(macho_wx().targets[0], "BS001")->summary, "W+X segment __DATA_EXEC");
    EXPECT_EQ(find(macho_wx().targets[0], "BS001")->evidence[0].offset, 0x2000U);
    EXPECT_EQ(find(packed_pe().targets[0], "BS001")->summary, "W+X sections UPX0, UPX1");
    EXPECT_EQ(find(packed_elf().targets[0], "BS001")->summary,
              "W+X segment LOAD[0]; sections UPX0, UPX1");
    EXPECT_FALSE(has(clean_elf().targets[0], "BS001"));
}

TEST(Findings, BS002HighEntropyExecutable) {
    ASSERT_TRUE(has(packed_pe().targets[0], "BS002"));
    EXPECT_EQ(find(packed_pe().targets[0], "BS002")
                  ->summary.rfind("high-entropy executable section UPX1 (7.9", 0),
              0U);
    EXPECT_TRUE(has(packed_elf().targets[0], "BS002"));
    EXPECT_FALSE(has(clean_pe().targets[0], "BS002"));
}

TEST(Findings, BS002ThresholdIsConfigurable) {
    Config cfg;
    cfg.entropy_threshold = 7.99;
    const auto r = report_sample("synthetic/pe64_packed_like.exe", cfg);
    EXPECT_FALSE(has(r.targets[0], "BS002"));
}

TEST(Findings, BS003LargeHighEntropySection) {
    const auto bytes = pe_with_noisy_data();
    EXPECT_FALSE(has(report_bytes(bytes).targets[0], "BS003"));  // 512 bytes < 64 KiB
    Config cfg;
    cfg.large_section_bytes = 256;
    cfg.min_entropy_bytes = 256;
    const auto r = report_bytes(bytes, cfg);
    ASSERT_TRUE(has(r.targets[0], "BS003"));
    EXPECT_NE(find(r.targets[0], "BS003")->summary.find("section .data"), std::string::npos);
}

TEST(Findings, BS004EntryOutsideCode) {
    auto bytes = read_sample("synthetic/pe64_hardened.exe");
    put(bytes, 0x80 + 24 + 16, 0x9000, 4);  // AddressOfEntryPoint -> unmapped
    auto r = report_bytes(bytes);
    ASSERT_TRUE(has(r.targets[0], "BS004"));
    EXPECT_EQ(find(r.targets[0], "BS004")->summary, "entry point 0x9000 is outside every section");
    put(bytes, 0x80 + 24 + 16, 0x3010, 4);  // inside .data
    r = report_bytes(bytes);
    ASSERT_TRUE(has(r.targets[0], "BS004"));
    EXPECT_EQ(find(r.targets[0], "BS004")->summary,
              "entry point 0x3010 is in non-executable section .data");
    EXPECT_FALSE(has(clean_pe().targets[0], "BS004"));
}

TEST(Findings, BS005EntryInLastSection) {
    ASSERT_TRUE(has(packed_elf().targets[0], "BS005"));
    EXPECT_EQ(find(packed_elf().targets[0], "BS005")->summary,
              "entry point is in the last section UPX1");
    EXPECT_FALSE(has(clean_elf().targets[0], "BS005"));
}

TEST(Findings, BS006PackerSectionNames) {
    ASSERT_TRUE(has(packed_pe().targets[0], "BS006"));
    EXPECT_EQ(find(packed_pe().targets[0], "BS006")->summary,
              "packer-associated sections UPX0, UPX1 (UPX)");
    EXPECT_FALSE(has(clean_pe().targets[0], "BS006"));
    bool listed = false;
    for (const auto& p : binscope::packer_names()) {
        listed = listed || std::string(p.section) == ".aspack";
    }
    EXPECT_TRUE(listed);
}

TEST(Findings, BS007FewImportsWithHighEntropy) {
    ASSERT_TRUE(has(packed_pe().targets[0], "BS007"));
    EXPECT_EQ(find(packed_pe().targets[0], "BS007")->summary,
              "2 imports alongside high-entropy section UPX1");
    EXPECT_FALSE(has(clean_pe().targets[0], "BS007"));  // 5 imports but no entropy
    Config cfg;
    cfg.few_imports = 1;
    EXPECT_FALSE(has(report_sample("synthetic/pe64_packed_like.exe", cfg).targets[0], "BS007"));
}

TEST(Findings, BS008AndBS009NotOnCleanFiles) {
    for (const auto* r : {&clean_elf(), &clean_pe(), &clean_macho(), &packed_pe()}) {
        EXPECT_FALSE(has(r->targets[0], "BS008"));
        EXPECT_FALSE(has(r->targets[0], "BS009"));
        EXPECT_FALSE(has(r->targets[0], "BS010"));
        EXPECT_FALSE(has(r->targets[0], "BS011"));
    }
}

TEST(Findings, ElfHardeningRules) {
    const auto& t = packed_elf().targets[0];
    EXPECT_TRUE(has(t, "BS012"));
    EXPECT_TRUE(has(t, "BS013"));
    EXPECT_TRUE(has(t, "BS014"));
    ASSERT_TRUE(has(t, "BS015"));
    EXPECT_NE(find(t, "BS015")->summary.find("no PT_GNU_STACK"), std::string::npos);
    for (const char* id : {"BS012", "BS013", "BS014", "BS015"}) {
        EXPECT_FALSE(has(clean_elf().targets[0], id)) << id;
    }
}

TEST(Findings, MachOHardeningRules) {
    const auto& t = macho_wx().targets[0];
    EXPECT_TRUE(has(t, "BS012"));
    ASSERT_TRUE(has(t, "BS015"));
    EXPECT_NE(find(t, "BS015")->summary.find("MH_ALLOW_STACK_EXECUTION"), std::string::npos);
    EXPECT_FALSE(has(clean_macho().targets[0], "BS012"));
    EXPECT_FALSE(has(clean_macho().targets[0], "BS015"));
}

TEST(Findings, PeHardeningRules) {
    const auto& t = packed_pe().targets[0];
    for (const char* id : {"BS016", "BS017", "BS018", "BS023"}) {
        EXPECT_TRUE(has(t, id)) << id;
        EXPECT_FALSE(has(clean_pe().targets[0], id)) << id;
    }
    const auto dll = report_sample("synthetic/pe32_ordinal.dll");
    EXPECT_TRUE(has(dll.targets[0], "BS018"));
    EXPECT_FALSE(has(dll.targets[0], "BS023"));  // HIGH_ENTROPY_VA does not apply to PE32
}

TEST(Findings, BS019UnsignedIsInformational) {
    const auto* f = find(macho_wx().targets[0], "BS019");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->severity, binscope::Severity::info);
    EXPECT_EQ(f->points, 0);
    EXPECT_TRUE(has(packed_pe().targets[0], "BS019"));
    EXPECT_FALSE(has(clean_pe().targets[0], "BS019"));
    EXPECT_FALSE(has(clean_macho().targets[0], "BS019"));
}

TEST(Findings, BS020EncryptedMachO) {
    EXPECT_EQ(find(macho_wx().targets[0], "BS020")->summary, "encrypted content (cryptid 1)");
    EXPECT_FALSE(has(clean_macho().targets[0], "BS020"));
}

TEST(Findings, BS021RelativeSearchPath) {
    EXPECT_EQ(find(macho_wx().targets[0], "BS021")->summary,
              "relative library search path lib/plugins");
    EXPECT_EQ(find(packed_elf().targets[0], "BS021")->summary,
              "relative library search path ./lib");
    EXPECT_FALSE(has(clean_elf().targets[0], "BS021"));  // $ORIGIN-relative is anchored
}

TEST(Findings, BS022NoSectionHeaders) {
    auto bytes = read_sample("synthetic/elf64_hardened.so");
    put(bytes, 0x28, 0, 8);
    put(bytes, 0x3C, 0, 2);
    put(bytes, 0x3E, 0, 2);
    EXPECT_TRUE(has(report_bytes(bytes).targets[0], "BS022"));
    EXPECT_FALSE(has(clean_elf().targets[0], "BS022"));
}

TEST(Findings, EachRuleFiresAtMostOncePerTarget) {
    for (const auto* r : {&packed_elf(), &packed_pe(), &macho_wx()}) {
        std::vector<std::string> ids;
        for (const auto& f : r->targets[0].findings) {
            ids.push_back(f.id);
        }
        auto sorted = ids;
        std::sort(sorted.begin(), sorted.end());
        EXPECT_EQ(std::adjacent_find(sorted.begin(), sorted.end()), sorted.end());
        EXPECT_EQ(ids, sorted);  // reported in id order
    }
}

TEST(Findings, ConfigDisablesAndOverridesRules) {
    Config cfg;
    cfg.disabled.insert("BS001");
    cfg.points["BS015"] = 1;
    cfg.severities["BS015"] = binscope::Severity::low;
    const auto r = report_sample("synthetic/macho64_wx_synthetic", cfg);
    EXPECT_FALSE(has(r.targets[0], "BS001"));
    ASSERT_TRUE(has(r.targets[0], "BS015"));
    EXPECT_EQ(find(r.targets[0], "BS015")->points, 1);
    EXPECT_EQ(find(r.targets[0], "BS015")->severity, binscope::Severity::low);
    EXPECT_EQ(r.targets[0].score.total, 70 - 30 - 20 + 1);
}

TEST(Findings, CatalogIsCompleteAndOrdered) {
    const auto& rules = binscope::rule_catalog();
    ASSERT_EQ(rules.size(), 23U);
    for (std::size_t i = 0; i < rules.size(); ++i) {
        char id[8];
        std::snprintf(id, sizeof id, "BS%03zu", i + 1);
        EXPECT_STREQ(rules[i].id, id);
        EXPECT_GE(rules[i].points, 0);
        EXPECT_GT(std::string(rules[i].explanation).size(), 20U);
    }
    EXPECT_EQ(binscope::find_rule("BS999"), nullptr);
}
