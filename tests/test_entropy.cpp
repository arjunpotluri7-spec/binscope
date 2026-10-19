#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "binscope/entropy.hpp"

using binscope::shannon_entropy;

TEST(Entropy, EmptyAndConstantAreZero) {
    EXPECT_DOUBLE_EQ(shannon_entropy({}), 0.0);
    const std::vector<std::uint8_t> zeros(4096, 0);
    EXPECT_DOUBLE_EQ(shannon_entropy(zeros), 0.0);
    const std::vector<std::uint8_t> sevens(10, 7);
    EXPECT_DOUBLE_EQ(shannon_entropy(sevens), 0.0);
}

TEST(Entropy, UniformDistributionIsEight) {
    std::vector<std::uint8_t> all;
    for (int rep = 0; rep < 4; ++rep) {
        for (int b = 0; b < 256; ++b) {
            all.push_back(static_cast<std::uint8_t>(b));
        }
    }
    EXPECT_DOUBLE_EQ(shannon_entropy(all), 8.0);
}

TEST(Entropy, KnownIntermediateValues) {
    const std::vector<std::uint8_t> two = {0, 1, 0, 1, 0, 1, 0, 1};
    EXPECT_DOUBLE_EQ(shannon_entropy(two), 1.0);
    const std::vector<std::uint8_t> four = {0, 1, 2, 3};
    EXPECT_DOUBLE_EQ(shannon_entropy(four), 2.0);
    const std::vector<std::uint8_t> skew = {0, 0, 0, 1};  // -(.75 log .75 + .25 log .25)
    EXPECT_NEAR(shannon_entropy(skew), 0.8112781244591328, 1e-12);
}
