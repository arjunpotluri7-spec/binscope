#include "binscope/entropy.hpp"

#include <array>
#include <cmath>

namespace binscope {

double shannon_entropy(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return 0.0;
    }
    std::array<std::uint64_t, 256> counts{};
    for (const auto b : bytes) {
        ++counts[b];
    }
    const auto total = static_cast<double>(bytes.size());
    double entropy = 0.0;
    for (const auto count : counts) {
        if (count == 0) {
            continue;
        }
        const double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }
    // Guard against -0.0 and tiny floating-point excursions past the bounds.
    if (entropy < 0.0) {
        return 0.0;
    }
    return entropy > 8.0 ? 8.0 : entropy;
}

}  // namespace binscope
