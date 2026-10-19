#include "binscope/bytes.hpp"

#include <string>

namespace binscope {

namespace {

Error out_of_range(std::uint64_t offset, std::uint64_t length, std::uint64_t size) {
    return make_error("read of " + std::to_string(length) + " bytes at offset " +
                          std::to_string(offset) + " is outside the " + std::to_string(size) +
                          "-byte buffer",
                      offset);
}

}  // namespace

Result<ByteView> ByteView::sub(std::uint64_t offset, std::uint64_t length) const {
    if (!contains(offset, length)) {
        return out_of_range(offset, length, size());
    }
    return ByteView(
        bytes_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length)));
}

ByteView ByteView::clamp(std::uint64_t offset, std::uint64_t length) const noexcept {
    if (offset >= size()) {
        return {};
    }
    const std::uint64_t available = size() - offset;
    const std::uint64_t take = length < available ? length : available;
    return ByteView(
        bytes_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(take)));
}

Result<std::uint64_t> ByteView::read_uint(std::uint64_t offset, unsigned width,
                                          Endian endian) const {
    if (!contains(offset, width)) {
        return out_of_range(offset, width, size());
    }
    const auto base = static_cast<std::size_t>(offset);
    std::uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i) {
        const unsigned index = endian == Endian::little ? width - 1 - i : i;
        value = (value << 8U) | bytes_[base + index];
    }
    return value;
}

Result<std::uint8_t> ByteView::u8(std::uint64_t offset) const {
    if (!contains(offset, 1)) {
        return out_of_range(offset, 1, size());
    }
    return bytes_[static_cast<std::size_t>(offset)];
}

Result<std::uint16_t> ByteView::u16(std::uint64_t offset, Endian endian) const {
    auto r = read_uint(offset, 2, endian);
    if (!r) {
        return r.error();
    }
    return static_cast<std::uint16_t>(*r);
}

Result<std::uint32_t> ByteView::u32(std::uint64_t offset, Endian endian) const {
    auto r = read_uint(offset, 4, endian);
    if (!r) {
        return r.error();
    }
    return static_cast<std::uint32_t>(*r);
}

Result<std::uint64_t> ByteView::u64(std::uint64_t offset, Endian endian) const {
    return read_uint(offset, 8, endian);
}

Result<std::string> ByteView::cstring(std::uint64_t offset, std::uint64_t max_len) const {
    if (offset >= size()) {
        return out_of_range(offset, 1, size());
    }
    const std::uint64_t available = size() - offset;
    const std::uint64_t limit = max_len < available ? max_len : available;
    std::string text;
    for (std::uint64_t i = 0; i < limit; ++i) {
        const auto c = bytes_[static_cast<std::size_t>(offset + i)];
        if (c == 0) {
            return text;
        }
        text.push_back(static_cast<char>(c));
    }
    return make_error("unterminated string at offset " + std::to_string(offset), offset);
}

Result<std::string> ByteView::fixed_string(std::uint64_t offset, std::uint64_t width) const {
    if (!contains(offset, width)) {
        return out_of_range(offset, width, size());
    }
    std::string text;
    for (std::uint64_t i = 0; i < width; ++i) {
        const auto c = bytes_[static_cast<std::size_t>(offset + i)];
        if (c == 0) {
            break;
        }
        text.push_back(static_cast<char>(c));
    }
    return text;
}

template <typename T>
T StructReader::take(Result<T> result, std::uint64_t width) {
    if (error_) {
        return T{};
    }
    if (!result) {
        error_ = result.error();
        return T{};
    }
    pos_ += width;  // cannot overflow: the read succeeded, so pos_ + width <= view size
    return *result;
}

std::uint8_t StructReader::u8() {
    return take(view_.u8(pos_), 1);
}
std::uint16_t StructReader::u16() {
    return take(view_.u16(pos_, endian_), 2);
}
std::uint32_t StructReader::u32() {
    return take(view_.u32(pos_, endian_), 4);
}
std::uint64_t StructReader::u64() {
    return take(view_.u64(pos_, endian_), 8);
}

std::string StructReader::fixed_string(std::uint64_t width) {
    return take(view_.fixed_string(pos_, width), width);
}

void StructReader::skip(std::uint64_t count) {
    if (error_) {
        return;
    }
    if (!view_.contains(pos_, count)) {
        error_ =
            make_error("record field at offset " + std::to_string(pos_) + " is truncated", pos_);
        return;
    }
    pos_ += count;
}

}  // namespace binscope
