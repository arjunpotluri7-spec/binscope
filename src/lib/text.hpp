// Locale-independent number formatting shared by the parsers and renderers.
#pragma once

#include <cstdint>
#include <string>

namespace binscope::detail {

/// "0x1f3"
[[nodiscard]] std::string hex(std::uint64_t value);
/// Two lowercase hex digits per byte appended to `out`.
void append_hex_byte(std::string& out, std::uint8_t byte, bool upper = false);
/// Decimal with exactly `decimals` digits after the point, rounded half up.
[[nodiscard]] std::string fixed(double value, int decimals);
/// Decimal padded with leading zeros to at least `width` digits.
[[nodiscard]] std::string zero_pad(std::uint64_t value, std::size_t width);

}  // namespace binscope::detail
