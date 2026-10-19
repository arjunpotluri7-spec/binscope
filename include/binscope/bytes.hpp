// Bounds-checked, endian-explicit access to untrusted file bytes.
//
// Every offset and size that comes from a file is treated as hostile: all reads go
// through ByteView, which checks ranges with overflow-safe arithmetic and returns a
// Result instead of touching memory out of range. Fields are assembled byte by byte,
// so there is no reinterpret_cast over the input and no alignment or aliasing hazard.
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>

#include "binscope/result.hpp"

namespace binscope {

enum class Endian : std::uint8_t { little, big };

/// a + b, or nullopt if the sum does not fit in 64 bits.
[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add(std::uint64_t a,
                                                                 std::uint64_t b) noexcept {
    if (a > std::numeric_limits<std::uint64_t>::max() - b) {
        return std::nullopt;
    }
    return a + b;
}

/// a * b, or nullopt if the product does not fit in 64 bits.
[[nodiscard]] constexpr std::optional<std::uint64_t> checked_mul(std::uint64_t a,
                                                                 std::uint64_t b) noexcept {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
        return std::nullopt;
    }
    return a * b;
}

/// True when [offset, offset + length) lies inside a buffer of `size` bytes.
[[nodiscard]] constexpr bool range_ok(std::uint64_t offset, std::uint64_t length,
                                      std::uint64_t size) noexcept {
    const auto end = checked_add(offset, length);
    return end.has_value() && *end <= size;
}

class ByteView {
public:
    ByteView() = default;
    explicit ByteView(std::span<const std::uint8_t> bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] std::uint64_t size() const noexcept { return bytes_.size(); }
    [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }
    [[nodiscard]] std::span<const std::uint8_t> span() const noexcept { return bytes_; }

    [[nodiscard]] bool contains(std::uint64_t offset, std::uint64_t length) const noexcept {
        return range_ok(offset, length, size());
    }

    /// A view of [offset, offset + length); fails if any byte is outside this view.
    [[nodiscard]] Result<ByteView> sub(std::uint64_t offset, std::uint64_t length) const;

    /// The in-range part of [offset, offset + length), possibly empty. Used for
    /// statistics (entropy) over regions that a malformed header claims extend past EOF.
    [[nodiscard]] ByteView clamp(std::uint64_t offset, std::uint64_t length) const noexcept;

    [[nodiscard]] Result<std::uint8_t> u8(std::uint64_t offset) const;
    [[nodiscard]] Result<std::uint16_t> u16(std::uint64_t offset, Endian endian) const;
    [[nodiscard]] Result<std::uint32_t> u32(std::uint64_t offset, Endian endian) const;
    [[nodiscard]] Result<std::uint64_t> u64(std::uint64_t offset, Endian endian) const;

    /// NUL-terminated string starting at `offset`, at most `max_len` bytes long.
    /// Fails if no terminator is found within the limit or the view.
    [[nodiscard]] Result<std::string> cstring(std::uint64_t offset, std::uint64_t max_len) const;

    /// Fixed-width, NUL-padded name field (e.g. a 16-byte Mach-O segname).
    [[nodiscard]] Result<std::string> fixed_string(std::uint64_t offset, std::uint64_t width) const;

private:
    [[nodiscard]] Result<std::uint64_t> read_uint(std::uint64_t offset, unsigned width,
                                                  Endian endian) const;

    std::span<const std::uint8_t> bytes_;
};

/// Sequential reader for fixed-layout records. Each field read delegates to the
/// Result-returning ByteView primitives; the first failure is latched and every later
/// read returns 0, so callers read a whole record and then check ok() once before
/// trusting any of the values.
class StructReader {
public:
    StructReader(ByteView view, std::uint64_t offset, Endian endian) noexcept
        : view_(view), pos_(offset), endian_(endian) {}

    std::uint8_t u8();
    std::uint16_t u16();
    std::uint32_t u32();
    std::uint64_t u64();
    /// 32- or 64-bit field depending on the record's word size.
    std::uint64_t word(bool is64) { return is64 ? u64() : u32(); }
    std::string fixed_string(std::uint64_t width);
    void skip(std::uint64_t count);

    [[nodiscard]] bool ok() const noexcept { return !error_.has_value(); }
    /// The latched error; only meaningful after ok() returned false.
    [[nodiscard]] const Error& error() const {
        static const Error kNoError{"no error", 0};
        return error_ ? *error_ : kNoError;
    }
    [[nodiscard]] std::uint64_t position() const noexcept { return pos_; }

private:
    template <typename T>
    T take(Result<T> result, std::uint64_t width);

    ByteView view_;
    std::uint64_t pos_;
    Endian endian_;
    std::optional<Error> error_;
};

}  // namespace binscope
