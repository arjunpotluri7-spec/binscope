#include "text.hpp"

#include <cmath>

namespace binscope::detail {

std::string hex(std::uint64_t value) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string digits(1, kDigits[value & 0xFU]);
    value >>= 4U;
    while (value != 0) {
        digits.insert(digits.begin(), kDigits[value & 0xFU]);
        value >>= 4U;
    }
    return "0x" + digits;
}

void append_hex_byte(std::string& out, std::uint8_t byte, bool upper) {
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    out.push_back(digits[byte >> 4U]);
    out.push_back(digits[byte & 0xFU]);
}

std::string fixed(double value, int decimals) {
    if (!std::isfinite(value)) {
        return "0";
    }
    std::string sign;
    if (value < 0) {
        sign = "-";
        value = -value;
    }
    std::uint64_t scale = 1;
    for (int i = 0; i < decimals; ++i) {
        scale *= 10;
    }
    const auto scaled =
        static_cast<std::uint64_t>(std::llround(value * static_cast<double>(scale)));
    std::string out = sign + std::to_string(scaled / scale);
    if (decimals > 0) {
        out += '.';
        out += zero_pad(scaled % scale, static_cast<std::size_t>(decimals));
    }
    return out;
}

std::string zero_pad(std::uint64_t value, std::size_t width) {
    std::string digits = std::to_string(value);
    if (digits.size() < width) {
        digits.insert(0, width - digits.size(), '0');
    }
    return digits;
}

}  // namespace binscope::detail
