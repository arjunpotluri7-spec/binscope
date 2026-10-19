#pragma once

#include <cstdint>
#include <span>

namespace binscope {

/// Shannon entropy in bits per byte: 0.0 for constant (or empty) data, 8.0 for a
/// perfectly uniform byte distribution.
[[nodiscard]] double shannon_entropy(std::span<const std::uint8_t> bytes) noexcept;

}  // namespace binscope
