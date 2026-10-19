// Tiny strict JSON parser used only by the tests to validate emitted documents.
#pragma once

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mini_json {

struct Value {
    enum class Type { null, boolean, number, string, array, object } type = Type::null;
    bool b = false;
    double n = 0.0;
    std::string s;
    std::vector<Value> items;
    std::vector<std::pair<std::string, Value>> members;

    [[nodiscard]] bool has(const std::string& key) const {
        for (const auto& [k, v] : members) {
            if (k == key) {
                return true;
            }
        }
        return false;
    }
    [[nodiscard]] const Value& at(const std::string& key) const {
        for (const auto& [k, v] : members) {
            if (k == key) {
                return v;
            }
        }
        throw std::runtime_error("missing key: " + key);
    }
    [[nodiscard]] const Value& operator[](std::size_t i) const { return items.at(i); }
    [[nodiscard]] bool is(Type t) const { return type == t; }
};

class Parser {
public:
    explicit Parser(const std::string& text) : t_(text) {}

    Value parse() {
        Value v = value();
        ws();
        if (i_ != t_.size()) {
            fail("trailing characters");
        }
        return v;
    }

private:
    [[noreturn]] void fail(const std::string& what) const {
        throw std::runtime_error("JSON error at " + std::to_string(i_) + ": " + what);
    }
    void ws() {
        while (i_ < t_.size() &&
               (t_[i_] == ' ' || t_[i_] == '\n' || t_[i_] == '\r' || t_[i_] == '\t')) {
            ++i_;
        }
    }
    void expect(char c) {
        ws();
        if (i_ >= t_.size() || t_[i_] != c) {
            fail(std::string("expected '") + c + "'");
        }
        ++i_;
    }
    std::string str() {
        expect('"');
        std::string out;
        while (true) {
            if (i_ >= t_.size()) {
                fail("unterminated string");
            }
            const char c = t_[i_++];
            if (c == '"') {
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20) {
                fail("raw control character in string");
            }
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (i_ >= t_.size()) {
                fail("bad escape");
            }
            const char e = t_[i_++];
            switch (e) {
                case '"':
                case '\\':
                case '/':
                    out.push_back(e);
                    break;
                case 'n':
                    out.push_back('\n');
                    break;
                case 't':
                    out.push_back('\t');
                    break;
                case 'r':
                    out.push_back('\r');
                    break;
                case 'b':
                    out.push_back('\b');
                    break;
                case 'f':
                    out.push_back('\f');
                    break;
                case 'u': {
                    if (i_ + 4 > t_.size()) {
                        fail("short \\u escape");
                    }
                    const auto cp = std::strtoul(t_.substr(i_, 4).c_str(), nullptr, 16);
                    i_ += 4;
                    out.push_back(cp < 0x80 ? static_cast<char>(cp) : '?');
                    break;
                }
                default:
                    fail("bad escape");
            }
        }
    }
    Value value() {
        ws();
        if (i_ >= t_.size()) {
            fail("unexpected end");
        }
        Value v;
        const char c = t_[i_];
        if (c == '{') {
            v.type = Value::Type::object;
            ++i_;
            ws();
            if (i_ < t_.size() && t_[i_] == '}') {
                ++i_;
                return v;
            }
            while (true) {
                std::string k = str();
                expect(':');
                v.members.emplace_back(std::move(k), value());
                ws();
                if (i_ < t_.size() && t_[i_] == ',') {
                    ++i_;
                    continue;
                }
                expect('}');
                return v;
            }
        }
        if (c == '[') {
            v.type = Value::Type::array;
            ++i_;
            ws();
            if (i_ < t_.size() && t_[i_] == ']') {
                ++i_;
                return v;
            }
            while (true) {
                v.items.push_back(value());
                ws();
                if (i_ < t_.size() && t_[i_] == ',') {
                    ++i_;
                    continue;
                }
                expect(']');
                return v;
            }
        }
        if (c == '"') {
            v.type = Value::Type::string;
            v.s = str();
            return v;
        }
        if (t_.compare(i_, 4, "true") == 0) {
            v.type = Value::Type::boolean;
            v.b = true;
            i_ += 4;
            return v;
        }
        if (t_.compare(i_, 5, "false") == 0) {
            v.type = Value::Type::boolean;
            i_ += 5;
            return v;
        }
        if (t_.compare(i_, 4, "null") == 0) {
            i_ += 4;
            return v;
        }
        const std::size_t start = i_;
        while (i_ < t_.size() &&
               (std::string("+-0123456789.eE").find(t_[i_]) != std::string::npos)) {
            ++i_;
        }
        if (start == i_) {
            fail("unexpected character");
        }
        v.type = Value::Type::number;
        v.n = std::strtod(t_.substr(start, i_ - start).c_str(), nullptr);
        return v;
    }

    const std::string& t_;
    std::size_t i_ = 0;
};

inline Value parse(const std::string& text) {
    return Parser(text).parse();
}

}  // namespace mini_json
