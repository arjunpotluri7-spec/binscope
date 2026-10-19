#include <gtest/gtest.h>

#include <string>
#include <variant>
#include <vector>

#include "binscope/parse.hpp"
#include "helpers.hpp"

using namespace bs_test;
using binscope::Format;

TEST(Pe, HardenedHeaderFields) {
    const auto p = parse_sample("synthetic/pe64_hardened.exe");
    ASSERT_EQ(p.info.container, Format::pe);
    const auto& t = p.target();
    EXPECT_EQ(t.format_name, "PE32+");
    EXPECT_EQ(t.arch, "x86_64");
    EXPECT_EQ(t.bits, 64U);
    EXPECT_EQ(t.file_type, "executable");
    EXPECT_EQ(*t.entry, 0x1020U);
    EXPECT_EQ(std::get<std::uint64_t>(t.property("timestamp")->value), 0x5F5E1000U);
    EXPECT_EQ(std::get<std::string>(t.property("timestamp_utc")->value), "2020-09-13T12:26:40Z");
    EXPECT_EQ(std::get<std::string>(t.property("image_base")->value), "0x140000000");
    EXPECT_EQ(std::get<std::string>(t.property("dll_characteristics")->value), "0xc160");
    EXPECT_TRUE(t.issues.empty());
}

TEST(Pe, HardenedSectionTable) {
    const auto p = parse_sample("synthetic/pe64_hardened.exe");
    const auto& t = p.target();
    ASSERT_EQ(t.sections.size(), 3U);
    EXPECT_EQ(t.sections[0].name, ".text");
    EXPECT_EQ(t.sections[0].type, "code");
    EXPECT_EQ(t.sections[0].offset, 0x200U);
    EXPECT_EQ(t.sections[0].file_size, 0x600U);
    EXPECT_EQ(t.sections[0].vaddr, 0x1000U);
    EXPECT_TRUE(t.sections[0].executable);
    EXPECT_FALSE(t.sections[0].writable);
    EXPECT_EQ(t.sections[1].name, ".rdata");
    EXPECT_EQ(t.sections[2].name, ".data");
    EXPECT_TRUE(t.sections[2].writable);
}

TEST(Pe, ImportsByName) {
    const auto p = parse_sample("synthetic/pe64_hardened.exe");
    const auto& t = p.target();
    ASSERT_EQ(t.libraries.size(), 2U);
    EXPECT_EQ(t.libraries[0].name, "KERNEL32.dll");
    EXPECT_EQ(t.libraries[0].functions, (std::vector<std::string>{"GetStdHandle", "WriteFile",
                                                                  "ExitProcess", "GetLastError"}));
    EXPECT_EQ(t.libraries[1].name, "USER32.dll");
    EXPECT_EQ(t.libraries[1].functions, (std::vector<std::string>{"MessageBoxW"}));
    EXPECT_EQ(t.import_count, 5U);
}

TEST(Pe, HardenedFlagsAndCertificatePresence) {
    const auto p = parse_sample("synthetic/pe64_hardened.exe");
    const auto& t = p.target();
    EXPECT_EQ(flag(t, "aslr"), true);
    EXPECT_EQ(flag(t, "high_entropy_va"), true);
    EXPECT_EQ(flag(t, "dep"), true);
    EXPECT_EQ(flag(t, "cfg"), true);
    EXPECT_EQ(flag(t, "certificate"), true);
    EXPECT_NE(t.flag("certificate")->detail.find("not verified"), std::string::npos);
    EXPECT_EQ(std::get<std::uint64_t>(t.property("overlay_bytes")->value), 0U);
}

TEST(Pe, Pe32DllWithOrdinalImports) {
    const auto p = parse_sample("synthetic/pe32_ordinal.dll");
    const auto& t = p.target();
    EXPECT_EQ(t.format_name, "PE32");
    EXPECT_EQ(t.arch, "i386");
    EXPECT_EQ(t.bits, 32U);
    EXPECT_EQ(t.file_type, "DLL");
    EXPECT_FALSE(t.expects_entry);
    EXPECT_FALSE(t.entry.has_value());  // AddressOfEntryPoint 0 is legal for a DLL
    ASSERT_EQ(t.libraries.size(), 2U);
    EXPECT_EQ(t.libraries[0].name, "WS2_32.dll");
    EXPECT_EQ(t.libraries[0].functions, (std::vector<std::string>{"#23", "#115", "inet_pton"}));
    EXPECT_EQ(t.libraries[1].functions, (std::vector<std::string>{"Sleep"}));
    EXPECT_EQ(flag(t, "high_entropy_va"), std::nullopt);  // not applicable to PE32
    EXPECT_EQ(flag(t, "aslr"), true);
}

TEST(Pe, PackedLikeFlags) {
    const auto p = parse_sample("synthetic/pe64_packed_like.exe");
    const auto& t = p.target();
    EXPECT_EQ(flag(t, "aslr"), false);
    EXPECT_EQ(flag(t, "dep"), false);
    EXPECT_EQ(flag(t, "cfg"), false);
    EXPECT_EQ(flag(t, "certificate"), false);
    ASSERT_EQ(t.sections.size(), 3U);
    EXPECT_EQ(t.sections[0].name, "UPX0");
    EXPECT_FALSE(t.sections[0].has_file_data);
    EXPECT_EQ(t.sections[0].mem_size, 0x10000U);
    EXPECT_GT(t.sections[1].entropy, 7.9);
    EXPECT_EQ(*t.entry, 0x13f00U);
    ASSERT_EQ(t.libraries.size(), 1U);
    EXPECT_EQ(t.libraries[0].functions,
              (std::vector<std::string>{"LoadLibraryA", "GetProcAddress"}));
}

TEST(Pe, DynamicBaseWithStrippedRelocsIsNotAslr) {
    auto bytes = read_sample("synthetic/pe64_hardened.exe");
    put(bytes, 0x80 + 4 + 18, 0x0023, 2);  // COFF Characteristics |= RELOCS_STRIPPED
    const auto r = binscope::parse(view(bytes));
    ASSERT_TRUE(r.ok());
    const auto& t = r->targets.front();
    EXPECT_EQ(flag(t, "aslr"), false);
    EXPECT_NE(t.flag("aslr")->detail.find("stripped"), std::string::npos);
}

TEST(Pe, ImportCapStopsEarly) {
    binscope::Limits limits;
    limits.max_imports = 3;
    const auto p = parse_sample("synthetic/pe64_hardened.exe", limits);
    const auto& t = p.target();
    EXPECT_EQ(t.import_count, 3U);
    bool limit_issue = false;
    for (const auto& i : t.issues) {
        limit_issue = limit_issue || i.kind == binscope::IssueKind::limit;
    }
    EXPECT_TRUE(limit_issue);
}
