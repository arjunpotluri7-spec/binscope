// Snapshot of every committed sample: architecture, score and the exact set of rules
// that fire. A change here means analysis behaviour changed and must be deliberate.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "binscope/report.hpp"
#include "helpers.hpp"

namespace {

struct Expected {
    const char* path;
    const char* arch;
    int score;
    const char* rules;
};

const std::vector<Expected> kSnapshot = {
    {"synthetic/elf32_be_ppc.elf", "ppc", 15, "BS012 BS013"},
    {"synthetic/elf64_hardened.so", "x86_64", 0, ""},
    {"synthetic/elf64_packed_like.elf", "x86_64", 100,
     "BS001 BS002 BS005 BS006 BS007 BS012 BS013 BS014 BS015 BS021"},
    {"synthetic/macho64_wx_synthetic", "arm64", 70, "BS001 BS012 BS015 BS019 BS020 BS021"},
    {"synthetic/malformed_absurd_counts.elf", "x86_64", 45, "BS009 BS010 BS011"},
    {"synthetic/malformed_absurd_counts.exe", "x86_64", 53, "BS008 BS009 BS011 BS018 BS019 BS023"},
    {"synthetic/malformed_bad_lfanew.exe", "", 20, "BS009"},
    {"synthetic/malformed_fat_past_eof", "arm64", 90, "BS001 BS009 BS012 BS015 BS019 BS020 BS021"},
    {"synthetic/malformed_ncmds.macho", "arm64", 45, "BS009 BS010 BS011 BS019"},
    {"synthetic/malformed_overlap.exe", "x86_64", 20, "BS008 BS018 BS019"},
    {"synthetic/malformed_section_past_eof.elf", "x86_64", 35, "BS008 BS009"},
    {"synthetic/malformed_truncated_header.elf", "", 15, "BS010"},
    {"synthetic/pe32_ordinal.dll", "i386", 5, "BS018 BS019"},
    {"synthetic/pe64_hardened.exe", "x86_64", 0, ""},
    {"synthetic/pe64_packed_like.exe", "x86_64", 100,
     "BS001 BS002 BS006 BS007 BS016 BS017 BS018 BS019 BS023"},
    {"macho/hello_arm64", "arm64", 0, ""},
    {"macho/hello_universal", "x86_64", 10, "BS012 BS019"},
    {"macho/hello_universal", "arm64", 0, ""},
    {"macho/hello_x86_64_nopie", "x86_64", 10, "BS012 BS019"},
};

}  // namespace

TEST(Regression, EverySampleMatchesSnapshot) {
    std::string last;
    std::size_t slice = 0;
    for (const auto& e : kSnapshot) {
        slice = (last == e.path) ? slice + 1 : 0;
        last = e.path;
        const auto r = bs_test::report_sample(e.path);
        ASSERT_FALSE(r.error.has_value()) << e.path;
        ASSERT_LT(slice, r.targets.size()) << e.path;
        const auto& t = r.targets[slice];
        std::string rules;
        for (const auto& f : t.findings) {
            rules += (rules.empty() ? "" : " ") + f.id;
        }
        EXPECT_EQ(t.target.arch, e.arch) << e.path;
        EXPECT_EQ(t.score.total, e.score) << e.path;
        EXPECT_EQ(rules, e.rules) << e.path;
    }
}

TEST(Regression, SyntheticScriptOutputIsCommitted) {
    // Every file make_synthetic.py writes must be present (and non-empty) in the repository.
    for (const char* name :
         {"elf64_hardened.so", "elf64_packed_like.elf", "elf32_be_ppc.elf", "pe64_hardened.exe",
          "pe64_packed_like.exe", "pe32_ordinal.dll", "macho64_wx_synthetic",
          "malformed_truncated_header.elf", "malformed_section_past_eof.elf",
          "malformed_absurd_counts.elf", "malformed_absurd_counts.exe", "malformed_bad_lfanew.exe",
          "malformed_overlap.exe", "malformed_ncmds.macho", "malformed_fat_past_eof"}) {
        EXPECT_FALSE(bs_test::read_sample(std::string("synthetic/") + name).empty()) << name;
    }
}
