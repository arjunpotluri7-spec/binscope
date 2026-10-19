#include "log.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>

namespace binscope::cli {

namespace {

const char* level_name(LogLevel level) {
    switch (level) {
        case LogLevel::debug:
            return "debug";
        case LogLevel::info:
            return "info";
        case LogLevel::warn:
            return "warn";
        case LogLevel::error:
            return "error";
    }
    return "info";
}

std::string escape(std::string_view text) {
    std::string out;
    for (const char ch : text) {
        const auto c = static_cast<unsigned char>(ch);
        if (ch == '"' || ch == '\\') {
            out.push_back('\\');
            out.push_back(ch);
        } else if (c < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

}  // namespace

std::optional<LogLevel> parse_log_level(std::string_view text) {
    if (text == "debug") {
        return LogLevel::debug;
    }
    if (text == "info") {
        return LogLevel::info;
    }
    if (text == "warn" || text == "warning") {
        return LogLevel::warn;
    }
    if (text == "error") {
        return LogLevel::error;
    }
    return std::nullopt;
}

void Logger::log(LogLevel level, std::string_view message, const Fields& fields) {
    if (static_cast<int>(level) < static_cast<int>(level_)) {
        return;
    }
    if (format_ == LogFormat::json) {
        std::string line = "{\"time\":\"" + utc_now() + "\",\"level\":\"" + level_name(level) +
                           "\",\"logger\":\"binscope\",\"message\":\"" + escape(message) + "\"";
        for (const auto& [k, v] : fields) {
            line += ",\"" + escape(k) + "\":\"" + escape(v) + "\"";
        }
        line += "}\n";
        sink_ << line;
    } else {
        std::string line =
            std::string("binscope: ") + level_name(level) + ": " + std::string(message);
        for (const auto& [k, v] : fields) {
            line += " " + k + "=" + v;
        }
        line += "\n";
        sink_ << line;
    }
    sink_.flush();
}

}  // namespace binscope::cli
