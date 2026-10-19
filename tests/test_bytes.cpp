#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <vector>

#include "binscope/bytes.hpp"
#include "helpers.hpp"

using binscope::ByteView;
using binscope::checked_add;
using binscope::checked_mul;
using binscope::Endian;
using binscope::range_ok;
using binscope::StructReader;

namespace {
constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
const std::vector<std::uint8_t> kBytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                          0x08, 'a',  'b',  0x00, 'c',  'd'};
}  // namespace

TEST(CheckedMath, AddDetectsOverflow) {
    EXPECT_EQ(checked_add(1, 2), 3U);
    EXPECT_EQ(checked_add(kMax - 1, 1), kMax);
    EXPECT_FALSE(checked_add(kMax, 1).has_value());
    EXPECT_FALSE(checked_add(kMax / 2 + 1, kMax / 2 + 1).has_value());
}

TEST(CheckedMath, MulDetectsOverflow) {
    EXPECT_EQ(checked_mul(0, kMax), 0U);
    EXPECT_EQ(checked_mul(1ULL << 32U, (1ULL << 32U) - 1), (1ULL << 32U) * ((1ULL << 32U) - 1));
    EXPECT_FALSE(checked_mul(1ULL << 32U, 1ULL << 32U).has_value());
    EXPECT_FALSE(checked_mul(kMax, 2).has_value());
}

TEST(CheckedMath, RangeOkHandlesWrapAround) {
    EXPECT_TRUE(range_ok(0, 10, 10));
    EXPECT_TRUE(range_ok(10, 0, 10));
    EXPECT_FALSE(range_ok(5, 6, 10));
    EXPECT_FALSE(range_ok(11, 0, 10));
    EXPECT_FALSE(range_ok(kMax, 2, 10));  // offset + length would wrap to 1
}

TEST(ByteView, ReadsBothEndiannesses) {
    const ByteView v = bs_test::view(kBytes);
    EXPECT_EQ(*v.u16(0, Endian::little), 0x0201U);
    EXPECT_EQ(*v.u16(0, Endian::big), 0x0102U);
    EXPECT_EQ(*v.u32(0, Endian::little), 0x04030201U);
    EXPECT_EQ(*v.u32(0, Endian::big), 0x01020304U);
    EXPECT_EQ(*v.u64(0, Endian::little), 0x0807060504030201ULL);
    EXPECT_EQ(*v.u64(0, Endian::big), 0x0102030405060708ULL);
    EXPECT_EQ(*v.u32(1, Endian::little), 0x05040302U);  // unaligned is fine
}

TEST(ByteView, OutOfRangeReadsFailWithOffset) {
    const ByteView v = bs_test::view(kBytes);
    EXPECT_TRUE(v.u8(12).ok());
    EXPECT_FALSE(v.u8(13).ok());
    EXPECT_FALSE(v.u32(10, Endian::little).ok());
    const auto r = v.u64(kMax - 3, Endian::little);
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.error().offset, kMax - 3);
    EXPECT_NE(r.error().message.find("outside"), std::string::npos);
}

TEST(ByteView, EmptyViewRejectsEverything) {
    const ByteView v;
    EXPECT_EQ(v.size(), 0U);
    EXPECT_FALSE(v.u8(0).ok());
    EXPECT_FALSE(v.cstring(0, 10).ok());
    EXPECT_TRUE(v.sub(0, 0).ok());
    EXPECT_FALSE(v.sub(0, 1).ok());
}

TEST(ByteView, SubAndClamp) {
    const ByteView v = bs_test::view(kBytes);
    const auto s = v.sub(2, 4);
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(s->size(), 4U);
    EXPECT_EQ(*s->u8(0), 0x03);
    EXPECT_FALSE(v.sub(10, 4).ok());
    EXPECT_FALSE(v.sub(kMax, 2).ok());
    EXPECT_EQ(v.clamp(10, 100).size(), 3U);
    EXPECT_EQ(v.clamp(100, 1).size(), 0U);
    EXPECT_EQ(v.clamp(0, kMax).size(), kBytes.size());
}

TEST(ByteView, Strings) {
    const ByteView v = bs_test::view(kBytes);
    EXPECT_EQ(*v.cstring(8, 16), "ab");
    EXPECT_FALSE(v.cstring(11, 16).ok());  // "cd" runs off the end without a NUL
    EXPECT_FALSE(v.cstring(8, 1).ok());    // limit reached before the NUL
    EXPECT_EQ(*v.fixed_string(8, 4), "ab");
    EXPECT_EQ(*v.fixed_string(11, 2), "cd");
    EXPECT_FALSE(v.fixed_string(11, 3).ok());
}

TEST(StructReader, LatchesFirstError) {
    const ByteView v = bs_test::view(kBytes);
    StructReader r(v, 8, Endian::little);
    EXPECT_EQ(r.u32(), 0x63006261U);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(r.u32(), 0U);  // only one byte left
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.u8(), 0U);  // stays failed even though one byte would fit
    EXPECT_EQ(r.error().offset, 12U);
}

TEST(StructReader, WordSizeAndSkip) {
    const ByteView v = bs_test::view(kBytes);
    StructReader r(v, 0, Endian::big);
    EXPECT_EQ(r.word(false), 0x01020304U);
    r.skip(2);
    EXPECT_EQ(r.u16(), 0x0708U);
    EXPECT_EQ(r.position(), 8U);
    r.skip(100);
    EXPECT_FALSE(r.ok());
}
