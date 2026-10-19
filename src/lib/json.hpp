// Small streaming JSON writer with deterministic, pretty-printed output.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace binscope::detail {

class JsonWriter {
public:
    void begin_object();
    void end_object();
    void begin_array();
    void end_array();
    void key(std::string_view name);

    void value(std::string_view text);
    void value(const char* text) { value(std::string_view(text)); }
    void value(std::uint64_t number);
    void value(std::int64_t number);
    void value(int number) { value(static_cast<std::int64_t>(number)); }
    void value(unsigned number) { value(static_cast<std::uint64_t>(number)); }
    void value(bool flag);
    void fixed(double number, int decimals);
    void null();

    template <typename T>
    void field(std::string_view name, const T& v) {
        key(name);
        value(v);
    }

    [[nodiscard]] std::string str() const { return out_ + "\n"; }

private:
    void before_value();
    void newline();

    std::string out_;
    std::vector<bool> has_items_;
    bool after_key_ = false;
};

/// JSON string escaping; invalid UTF-8 is replaced with U+FFFD so output is always valid.
[[nodiscard]] std::string json_escape(std::string_view text);

}  // namespace binscope::detail
