#include <gtest/gtest.h>

#include <string>

#include "binscope/config.hpp"
#include "helpers.hpp"

using binscope::parse_config;

TEST(Config, ExampleFileLoadsWithDefaults) {
    const auto r =
        binscope::load_config(std::string(BINSCOPE_SAMPLES_DIR) + "/../config.example.toml");
    ASSERT_TRUE(r.ok()) << r.error().message;
    const binscope::Config defaults;
    EXPECT_DOUBLE_EQ(r->entropy_threshold, defaults.entropy_threshold);
    EXPECT_EQ(r->limits.max_file_size, defaults.limits.max_file_size);
    EXPECT_EQ(r->limits.max_sections, defaults.limits.max_sections);
    EXPECT_TRUE(r->disabled.empty());
    EXPECT_TRUE(r->points.empty());
}

TEST(Config, ParsesEveryValueKind) {
    const auto r = parse_config(R"(
[thresholds]
entropy_high = 6.5   # comment
few_imports = 3
[limits]
max_file_size_mib = 8
max_sections = 100
[points]
BS001 = 50
[severity]
BS019 = "low"
[rules]
disabled = ["BS003", "BS023"]
)",
                                "test.toml");
    ASSERT_TRUE(r.ok()) << r.error().message;
    EXPECT_DOUBLE_EQ(r->entropy_threshold, 6.5);
    EXPECT_EQ(r->few_imports, 3U);
    EXPECT_EQ(r->limits.max_file_size, 8ULL * 1024 * 1024);
    EXPECT_EQ(r->limits.max_sections, 100U);
    EXPECT_EQ(r->points.at("BS001"), 50);
    EXPECT_EQ(r->severities.at("BS019"), binscope::Severity::low);
    EXPECT_EQ(r->disabled.size(), 2U);
    EXPECT_EQ(r->points_for(*binscope::find_rule("BS001")), 50);
    EXPECT_EQ(r->points_for(*binscope::find_rule("BS002")), 25);
}

TEST(Config, ErrorsNameFileAndLine) {
    const auto r = parse_config("[thresholds]\nentropy_high = 9.5\n", "my.toml");
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.error().message.rfind("my.toml:2: ", 0), 0U);
    EXPECT_NE(r.error().message.find("outside the range"), std::string::npos);
}

TEST(Config, RejectsUnknownKeysSectionsAndRules) {
    EXPECT_FALSE(parse_config("[thresholds]\nbogus = 1\n", "c").ok());
    EXPECT_FALSE(parse_config("[nonsense]\n", "c").ok());
    EXPECT_FALSE(parse_config("[points]\nBS999 = 4\n", "c").ok());
    EXPECT_FALSE(parse_config("[rules]\ndisabled = [\"BS777\"]\n", "c").ok());
    EXPECT_FALSE(parse_config("entropy_high = 1\n", "c").ok());  // outside a section
}

TEST(Config, RejectsBadValues) {
    EXPECT_FALSE(parse_config("[points]\nBS001 = 101\n", "c").ok());
    EXPECT_FALSE(parse_config("[points]\nBS001 = -1\n", "c").ok());
    EXPECT_FALSE(parse_config("[limits]\nmax_sections = 0\n", "c").ok());
    EXPECT_FALSE(parse_config("[limits]\nmax_sections = ten\n", "c").ok());
    EXPECT_FALSE(parse_config("[severity]\nBS001 = \"extreme\"\n", "c").ok());
    EXPECT_FALSE(parse_config("[severity]\nBS001 = high\n", "c").ok());
    EXPECT_FALSE(parse_config("[thresholds\n", "c").ok());
    EXPECT_FALSE(parse_config("[thresholds]\nentropy_high 7\n", "c").ok());
}

TEST(Config, MissingFileIsAnError) {
    const auto r = binscope::load_config("/nonexistent/binscope.toml");
    ASSERT_FALSE(r.ok());
    EXPECT_NE(r.error().message.find("cannot open"), std::string::npos);
}
