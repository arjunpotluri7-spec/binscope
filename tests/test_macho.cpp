#include <gtest/gtest.h>

#include <string>
#include <variant>
#include <vector>

#include "binscope/parse.hpp"
#include "helpers.hpp"

using namespace bs_test;
using binscope::Endian;
using binscope::Format;

TEST(MachO, SyntheticThinFields) {
    const auto p = parse_sample("synthetic/macho64_wx_synthetic");
    ASSERT_EQ(p.info.container, Format::macho);
    const auto& t = p.target();
    EXPECT_EQ(t.format_name, "Mach-O 64-bit");
    EXPECT_EQ(t.arch, "arm64");
    EXPECT_EQ(t.file_type, "executable");
    EXPECT_EQ(*t.entry, 0x100001010U);  // LC_MAIN entryoff 0x1010 mapped through __TEXT
    ASSERT_EQ(t.segments.size(), 4U);
    EXPECT_EQ(t.segments[2].name, "__DATA_EXEC");
    EXPECT_TRUE(t.segments[2].writable);
    EXPECT_TRUE(t.segments[2].executable);
    ASSERT_EQ(t.sections.size(), 2U);
    EXPECT_EQ(t.sections[0].name, "__TEXT,__text");
    EXPECT_TRUE(t.sections[0].executable);
    EXPECT_EQ(t.sections[0].offset, 0x1000U);
    EXPECT_EQ(t.sections[0].file_size, 0x800U);
    EXPECT_EQ(t.sections[1].name, "__DATA_EXEC,__data_exec");
    EXPECT_FALSE(t.sections[1].executable);  // no instruction attributes
    EXPECT_EQ(t.rpaths, (std::vector<std::string>{"lib/plugins"}));
    EXPECT_EQ(std::get<std::uint64_t>(t.property("cryptid")->value), 1U);
    EXPECT_EQ(flag(t, "pie"), false);
    EXPECT_EQ(flag(t, "nx_stack"), false);
    EXPECT_EQ(flag(t, "code_signature"), false);
    EXPECT_TRUE(t.issues.empty());
}

TEST(MachO, UndefinedSymbolsBindToTheirDylib) {
    const auto p = parse_sample("synthetic/macho64_wx_synthetic");
    const auto& t = p.target();
    ASSERT_EQ(t.libraries.size(), 1U);
    EXPECT_EQ(t.libraries[0].name, "/usr/lib/libSystem.B.dylib");
    EXPECT_EQ(t.libraries[0].functions, (std::vector<std::string>{"_puts", "_exit"}));
    EXPECT_EQ(t.import_count, 2U);
}

TEST(MachO, NativeArm64Sample) {
    const auto p = parse_sample("macho/hello_arm64");
    const auto& t = p.target();
    EXPECT_EQ(t.arch, "arm64");
    EXPECT_EQ(*t.entry, 0x100000460U);
    EXPECT_EQ(flag(t, "pie"), true);
    EXPECT_EQ(flag(t, "nx_stack"), true);
    EXPECT_EQ(flag(t, "code_signature"), true);
    ASSERT_EQ(t.libraries.size(), 1U);
    EXPECT_EQ(t.libraries[0].functions, (std::vector<std::string>{"_puts"}));
    ASSERT_NE(section(t, "__TEXT,__text"), nullptr);
    EXPECT_TRUE(section(t, "__TEXT,__text")->executable);
    EXPECT_EQ(std::get<std::string>(t.property("dylinker")->value), "/usr/lib/dyld");
    EXPECT_TRUE(t.issues.empty());
}

TEST(MachO, UnixThreadEntryOnX86_64) {
    const auto p = parse_sample("macho/hello_x86_64_nopie");
    const auto& t = p.target();
    EXPECT_EQ(t.arch, "x86_64");
    EXPECT_EQ(*t.entry, 0x1000006d0U);  // rip from LC_UNIXTHREAD
    EXPECT_EQ(flag(t, "pie"), false);
    EXPECT_EQ(flag(t, "code_signature"), false);
    EXPECT_EQ(std::get<std::string>(t.property("min_os")->value), "10.6.0");
}

TEST(MachO, UniversalBinarySlices) {
    const auto bytes = read_sample("macho/hello_universal");
    EXPECT_EQ(binscope::detect_format(view(bytes)), Format::macho_fat);
    const auto p = parse_sample("macho/hello_universal");
    EXPECT_EQ(p.info.container, Format::macho_fat);
    ASSERT_EQ(p.info.targets.size(), 2U);
    EXPECT_EQ(p.target(0).arch, "x86_64");
    EXPECT_EQ(p.target(0).slice_offset, 0x1000U);
    EXPECT_EQ(p.target(0).size, 8720U);
    EXPECT_EQ(p.target(1).arch, "arm64");
    EXPECT_EQ(p.target(1).slice_offset, 0x4000U);
    EXPECT_EQ(p.target(1).size, 33432U);
    EXPECT_EQ(flag(p.target(0), "pie"), false);
    EXPECT_EQ(flag(p.target(1), "pie"), true);
}

TEST(MachO, Fat64Header) {
    const auto thin = read_sample("synthetic/macho64_wx_synthetic");
    std::vector<std::uint8_t> fat;
    put(fat, 0, 0xCAFEBABF, 4, false);
    put(fat, 4, 1, 4, false);
    put(fat, 8, 0x0100000C, 4, false);  // cputype arm64
    put(fat, 12, 0, 4, false);
    put(fat, 16, 0x4000, 8, false);  // offset
    put(fat, 24, thin.size(), 8, false);
    put(fat, 32, 14, 4, false);
    fat.resize(0x4000);
    fat.insert(fat.end(), thin.begin(), thin.end());
    const auto r = binscope::parse(view(fat));
    ASSERT_TRUE(r.ok());
    ASSERT_EQ(r->targets.size(), 1U);
    EXPECT_EQ(r->targets[0].arch, "arm64");
    EXPECT_EQ(r->targets[0].slice_offset, 0x4000U);
    EXPECT_TRUE(r->targets[0].issues.empty());
}

TEST(MachO, BigEndian32BitThin) {
    std::vector<std::uint8_t> b(84, 0);
    put(b, 0, 0xFEEDFACE, 4, false);
    put(b, 4, 18, 4, false);  // CPU_TYPE_POWERPC
    put(b, 8, 0, 4, false);
    put(b, 12, 2, 4, false);  // MH_EXECUTE
    put(b, 16, 1, 4, false);  // ncmds
    put(b, 20, 56, 4, false);
    put(b, 24, 0x200000, 4, false);  // MH_PIE
    put(b, 28, 1, 4, false);         // LC_SEGMENT
    put(b, 32, 56, 4, false);
    const std::string seg = "__TEXT";
    for (std::size_t i = 0; i < seg.size(); ++i) {
        b[36 + i] = static_cast<std::uint8_t>(seg[i]);
    }
    put(b, 52, 0x1000, 4, false);  // vmaddr
    put(b, 56, 0x1000, 4, false);  // vmsize
    put(b, 60, 0, 4, false);       // fileoff
    put(b, 64, 84, 4, false);      // filesize
    put(b, 68, 5, 4, false);       // maxprot
    put(b, 72, 5, 4, false);       // initprot
    put(b, 76, 0, 4, false);       // nsects
    put(b, 80, 0, 4, false);       // flags
    const auto r = binscope::parse(view(b));
    ASSERT_TRUE(r.ok());
    const auto& t = r->targets.front();
    EXPECT_EQ(t.format_name, "Mach-O 32-bit");
    EXPECT_EQ(t.endian, Endian::big);
    EXPECT_EQ(t.arch, "ppc");
    ASSERT_EQ(t.segments.size(), 1U);
    EXPECT_EQ(t.segments[0].name, "__TEXT");
    EXPECT_EQ(t.segments[0].vaddr, 0x1000U);
    EXPECT_EQ(t.segments[0].file_size, 84U);
    EXPECT_EQ(flag(t, "pie"), true);
    EXPECT_TRUE(t.issues.empty());
}

TEST(MachO, JavaClassMagicIsNotUniversal) {
    std::vector<std::uint8_t> b;
    put(b, 0, 0xCAFEBABE, 4, false);
    put(b, 4, 0x00000034, 4, false);  // Java 8 class file: minor 0, major 52
    b.resize(64);
    EXPECT_FALSE(binscope::detect_format(view(b)).has_value());
}
