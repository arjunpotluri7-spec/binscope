#include "json.hpp"

#include "text.hpp"

#include <cmath>

namespace binscope::detail {

namespace {

/// Length of the valid UTF-8 sequence starting at text[i], or 0 if invalid.
std::size_t utf8_length(std::string_view text, std::size_t i) {
    const auto c = static_cast<unsigned char>(text[i]);
    std::size_t len = 0;
    std::uint32_t min = 0;
    if (c < 0x80) {
        return 1;
    }
    if ((c & 0xE0U) == 0xC0U) {
        len = 2;
        min = 0x80;
    } else if ((c & 0xF0U) == 0xE0U) {
        len = 3;
        min = 0x800;
    } else if ((c & 0xF8U) == 0xF0U) {
        len = 4;
        min = 0x10000;
    } else {
        return 0;
    }
    if (i + len > text.size()) {
        return 0;
    }
    std::uint32_t cp = c & (0x7FU >> len);
    for (std::size_t k = 1; k < len; ++k) {
        const auto cc = static_cast<unsigned char>(text[i + k]);
        if ((cc & 0xC0U) != 0x80U) {
            return 0;
        }
        cp = (cp << 6U) | (cc & 0x3FU);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        return 0;
    }
    return len;
}

}  // namespace

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 2);
    out.push_back('"');
    for (std::size_t i = 0; i < text.size();) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c >= 0x80) {
            const std::size_t len = utf8_length(text, i);
            if (len == 0) {
                out += "\\ufffd";
                ++i;
            } else {
                out.append(text.substr(i, len));
                i += len;
            }
            continue;
        }
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    out += "\\u00";
                    append_hex_byte(out, c);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
        ++i;
    }
    out.push_back('"');
    return out;
}

void JsonWriter::newline() {
    out_.push_back('\n');
    out_.append(has_items_.size() * 2, ' ');
}

void JsonWriter::before_value() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!has_items_.empty()) {
        if (has_items_.back()) {
            out_.push_back(',');
        }
        has_items_.back() = true;
        newline();
    }
}

void JsonWriter::begin_object() {
    before_value();
    out_.push_back('{');
    has_items_.push_back(false);
}

void JsonWriter::end_object() {
    const bool items = has_items_.back();
    has_items_.pop_back();
    if (items) {
        newline();
    }
    out_.push_back('}');
}

void JsonWriter::begin_array() {
    before_value();
    out_.push_back('[');
    has_items_.push_back(false);
}

void JsonWriter::end_array() {
    const bool items = has_items_.back();
    has_items_.pop_back();
    if (items) {
        newline();
    }
    out_.push_back(']');
}

void JsonWriter::key(std::string_view name) {
    before_value();
    out_ += json_escape(name);
    out_ += ": ";
    after_key_ = true;
}

void JsonWriter::value(std::string_view text) {
    before_value();
    out_ += json_escape(text);
}

void JsonWriter::value(std::uint64_t number) {
    before_value();
    out_ += std::to_string(number);
}

void JsonWriter::value(std::int64_t number) {
    before_value();
    out_ += std::to_string(number);
}

void JsonWriter::value(bool flag) {
    before_value();
    out_ += flag ? "true" : "false";
}

void JsonWriter::fixed(double number, int decimals) {
    before_value();
    if (!std::isfinite(number)) {
        out_ += "null";
        return;
    }
    out_ += detail::fixed(number, decimals);
}

void JsonWriter::null() {
    before_value();
    out_ += "null";
}

}  // namespace binscope::detail
