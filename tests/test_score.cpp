#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "binscope/findings.hpp"
#include "binscope/report.hpp"
#include "helpers.hpp"

using namespace bs_test;
using binscope::compute_score;
using binscope::Finding;
using binscope::score_label;

namespace {
std::vector<Finding> with_points(const std::vector<int>& points) {
    std::vector<Finding> out;
    for (const int p : points) {
        Finding f;
        f.points = p;
        out.push_back(f);
    }
    return out;
}
}  // namespace

TEST(Score, SumsPoints) {
    EXPECT_EQ(compute_score({}).total, 0);
    EXPECT_EQ(compute_score(with_points({10, 5, 3})).total, 18);
    EXPECT_EQ(compute_score(with_points({10, 5, 3})).raw, 18);
}

TEST(Score, ClampsToHundred) {
    const auto s = compute_score(with_points({30, 25, 20, 15, 15, 10}));
    EXPECT_EQ(s.raw, 115);
    EXPECT_EQ(s.total, 100);
    EXPECT_EQ(s.label, "very high");
}

TEST(Score, LabelBoundaries) {
    EXPECT_EQ(score_label(0), "low");
    EXPECT_EQ(score_label(19), "low");
    EXPECT_EQ(score_label(20), "moderate");
    EXPECT_EQ(score_label(49), "moderate");
    EXPECT_EQ(score_label(50), "high");
    EXPECT_EQ(score_label(79), "high");
    EXPECT_EQ(score_label(80), "very high");
    EXPECT_EQ(score_label(100), "very high");
}

TEST(Score, MachOSyntheticWorkingIsExact) {
    const auto r = report_sample("synthetic/macho64_wx_synthetic");
    const auto& t = r.targets.at(0);
    int sum = 0;
    for (const auto& f : t.findings) {
        sum += f.points;
    }
    EXPECT_EQ(sum, 70);  // 30 W+X + 20 exec stack + 10 no PIE + 5 rpath + 5 crypt + 0 unsigned
    EXPECT_EQ(t.score.total, 70);
    EXPECT_EQ(t.score.label, "high");
}

TEST(Score, UniversalFileTakesWorstSlice) {
    const auto r = report_sample("macho/hello_universal");
    ASSERT_EQ(r.targets.size(), 2U);
    EXPECT_EQ(r.targets[0].score.total, 10);
    EXPECT_EQ(r.targets[1].score.total, 0);
    EXPECT_EQ(r.score(), 10);
}

TEST(Score, TableListsEveryFactorWithPoints) {
    const auto r = report_sample("synthetic/macho64_wx_synthetic");
    const auto text = binscope::render_table({r}, {});
    EXPECT_NE(text.find("score      70/100 (high)"), std::string::npos);
    EXPECT_NE(text.find("+30  W+X segment __DATA_EXEC"), std::string::npos);
    EXPECT_NE(text.find("+20  executable stack (MH_ALLOW_STACK_EXECUTION set)"), std::string::npos);
    EXPECT_NE(text.find(" +0  no code signature"), std::string::npos);
    // Factors are ordered by points, largest first.
    EXPECT_LT(text.find("+30  W+X"), text.find("+20  executable stack"));
}

TEST(Score, TableShowsCapWhenRawExceedsHundred) {
    const auto r = report_sample("synthetic/elf64_packed_like.elf");
    EXPECT_EQ(r.targets[0].score.total, 100);
    EXPECT_GT(r.targets[0].score.raw, 100);
    const auto text = binscope::render_table({r}, {});
    EXPECT_NE(text.find("capped at 100"), std::string::npos);
}
