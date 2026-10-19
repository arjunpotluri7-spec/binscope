#include <gtest/gtest.h>

#include <string>
#include <variant>
#include <vector>

#include "binscope/parse.hpp"
#include "helpers.hpp"

using namespace bs_test;
using binscope::Endian;
using binscope::Format;

namespace {
std::string prop_str(const binscope::Target& t, const std::string& key) {
    const auto* p = t.property(key);
    return p ? std::get<std::string>(p->value) : std::string("<missing>");
}
}  // namespace

TEST(Elf, DetectsFormat) {
    const auto bytes = read_sample("synthetic/elf64_hardened.so");
    EXPECT_EQ(binscope::detect_format(view(bytes)), Format::elf);
}

TEST(Elf, HardenedHeaderFields) {
    const auto p = parse_sample("synthetic/elf64_hardened.so");
    ASSERT_EQ(p.info.targets.size(), 1U);
    const auto& t = p.target();
    EXPECT_EQ(t.format_name, "ELF64");
    EXPECT_EQ(t.arch, "x86_64");
    EXPECT_EQ(t.bits, 64U);
    EXPECT_EQ(t.endian, Endian::little);
    EXPECT_EQ(t.file_type, "PIE executable");
    ASSERT_TRUE(t.entry.has_value());
    EXPECT_EQ(*t.entry, 0x310U);
    EXPECT_EQ(t.size, 2824U);
    EXPECT_TRUE(t.issues.empty());
}

TEST(Elf, HardenedSectionsAndSegments) {
    const auto p = parse_sample("synthetic/elf64_hardened.so");
    const auto& t = p.target();
    ASSERT_EQ(t.sections.size(), 10U);
    const std::vector<std::string> names = {
        ".interp", ".note.gnu.build-id", ".dynsym", ".dynstr", ".text",
        ".rodata", ".dynamic",           ".data",   ".bss",    ".shstrtab"};
    for (std::size_t i = 0; i < names.size(); ++i) {
        EXPECT_EQ(t.sections[i].name, names[i]);
    }
    const auto* text = section(t, ".text");
    ASSERT_NE(text, nullptr);
    EXPECT_EQ(text->offset, 0x2d0U);
    EXPECT_EQ(text->file_size, 0x400U);
    EXPECT_EQ(text->vaddr, 0x2d0U);
    EXPECT_TRUE(text->executable);
    EXPECT_FALSE(text->writable);
    EXPECT_GT(text->entropy, 0.0);
    const auto* bss = section(t, ".bss");
    ASSERT_NE(bss, nullptr);
    EXPECT_FALSE(bss->has_file_data);
    EXPECT_EQ(bss->mem_size, 256U);
    ASSERT_EQ(t.segments.size(), 7U);
    EXPECT_EQ(t.segments[0].name, "LOAD[0]");
    EXPECT_EQ(t.segments[0].type, "PT_LOAD");
    EXPECT_TRUE(t.segments[0].executable);
    EXPECT_EQ(t.segments[5].type, "PT_GNU_STACK");
    EXPECT_FALSE(t.segments[5].executable);
}

TEST(Elf, HardenedDynamicSection) {
    const auto p = parse_sample("synthetic/elf64_hardened.so");
    const auto& t = p.target();
    ASSERT_EQ(t.libraries.size(), 2U);
    EXPECT_EQ(t.libraries[0].name, "libc.so.6");
    EXPECT_EQ(t.libraries[1].name, "libm.so.6");
    EXPECT_EQ(t.unbound_imports,
              (std::vector<std::string>{"puts", "printf", "__libc_start_main", "cos"}));
    EXPECT_EQ(t.import_count, 4U);
    EXPECT_EQ(t.rpaths, (std::vector<std::string>{"$ORIGIN/../lib"}));
    EXPECT_EQ(prop_str(t, "runpath"), "$ORIGIN/../lib");
    EXPECT_EQ(prop_str(t, "interpreter"), "/lib64/ld-linux-x86-64.so.2");
    EXPECT_EQ(prop_str(t, "build_id"), "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
    EXPECT_EQ(prop_str(t, "relro"), "full");
    EXPECT_EQ(std::get<std::uint64_t>(t.property("dynsym_symbols")->value), 5U);
    EXPECT_TRUE(std::get<bool>(t.property("build_id_section")->value));
}

TEST(Elf, HardenedFlags) {
    const auto p = parse_sample("synthetic/elf64_hardened.so");
    const auto& t = p.target();
    EXPECT_EQ(flag(t, "pie"), true);
    EXPECT_EQ(flag(t, "nx_stack"), true);
    EXPECT_EQ(flag(t, "relro"), true);
    EXPECT_EQ(flag(t, "bind_now"), true);
}

TEST(Elf, PackedLikeFlagsAndSections) {
    const auto p = parse_sample("synthetic/elf64_packed_like.elf");
    const auto& t = p.target();
    EXPECT_EQ(t.file_type, "executable");
    EXPECT_EQ(*t.entry, 0x400240U);
    EXPECT_EQ(flag(t, "pie"), false);
    EXPECT_EQ(flag(t, "nx_stack"), false);
    EXPECT_EQ(flag(t, "relro"), false);
    EXPECT_EQ(flag(t, "bind_now"), false);
    EXPECT_EQ(t.rpaths, (std::vector<std::string>{"./lib"}));
    ASSERT_EQ(t.libraries.size(), 1U);
    EXPECT_EQ(t.unbound_imports, (std::vector<std::string>{"mmap"}));
    const auto* upx1 = section(t, "UPX1");
    ASSERT_NE(upx1, nullptr);
    EXPECT_TRUE(upx1->writable);
    EXPECT_TRUE(upx1->executable);
    EXPECT_EQ(upx1->file_size, 8192U);
    EXPECT_GT(upx1->entropy, 7.9);
    const auto* upx0 = section(t, "UPX0");
    ASSERT_NE(upx0, nullptr);
    EXPECT_FALSE(upx0->has_file_data);
}

TEST(Elf, BigEndian32Bit) {
    const auto p = parse_sample("synthetic/elf32_be_ppc.elf");
    const auto& t = p.target();
    EXPECT_EQ(t.format_name, "ELF32");
    EXPECT_EQ(t.arch, "ppc");
    EXPECT_EQ(t.bits, 32U);
    EXPECT_EQ(t.endian, Endian::big);
    EXPECT_EQ(*t.entry, 0x100000a4U);
    ASSERT_EQ(t.sections.size(), 3U);
    EXPECT_EQ(t.sections[0].name, ".text");
    EXPECT_EQ(t.sections[0].offset, 0x94U);
    EXPECT_EQ(t.sections[0].file_size, 0x200U);
    EXPECT_EQ(t.sections[1].name, ".data");
    EXPECT_DOUBLE_EQ(t.sections[1].entropy, 2.0);  // DE AD BE EF repeated
    ASSERT_EQ(t.segments.size(), 3U);
    EXPECT_EQ(flag(t, "pie"), false);
    EXPECT_EQ(flag(t, "nx_stack"), true);
    EXPECT_EQ(flag(t, "bind_now"), std::nullopt);  // static: no dynamic section
    EXPECT_TRUE(t.issues.empty());
}

TEST(Elf, WithoutSectionHeadersFallsBackToSegments) {
    auto bytes = read_sample("synthetic/elf64_hardened.so");
    put(bytes, 0x28, 0, 8);  // e_shoff
    put(bytes, 0x3C, 0, 2);  // e_shnum
    put(bytes, 0x3E, 0, 2);  // e_shstrndx
    const auto r = binscope::parse(view(bytes));
    ASSERT_TRUE(r.ok());
    const auto& t = r->targets.front();
    EXPECT_TRUE(t.sections.empty());
    // DT_NEEDED is still found by mapping DT_STRTAB through PT_LOAD.
    ASSERT_EQ(t.libraries.size(), 2U);
    EXPECT_EQ(t.libraries[1].name, "libm.so.6");
    EXPECT_FALSE(std::get<bool>(t.property("section_headers")->value));
    EXPECT_EQ(std::get<std::string>(t.property("build_id")->value),
              "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");  // from PT_NOTE
}
