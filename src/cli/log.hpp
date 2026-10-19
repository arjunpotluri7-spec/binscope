// Structured diagnostics on stderr. Reports never go through the logger.
#pragma once

#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binscope::cli {

enum class LogLevel : int { debug = 0, info = 1, warn = 2, error = 3 };
enum class LogFormat : int { text, json };

[[nodiscard]] std::optional<LogLevel> parse_log_level(std::string_view text);

class Logger {
public:
    using Fields = std::vector<std::pair<std::string, std::string>>;

    explicit Logger(std::ostream& sink) : sink_(sink) {}
    void configure(LogLevel level, LogFormat format) {
        level_ = level;
        format_ = format;
    }

    void log(LogLevel level, std::string_view message, const Fields& fields = {});
    void debug(std::string_view m, const Fields& f = {}) { log(LogLevel::debug, m, f); }
    void info(std::string_view m, const Fields& f = {}) { log(LogLevel::info, m, f); }
    void warn(std::string_view m, const Fields& f = {}) { log(LogLevel::warn, m, f); }
    void error(std::string_view m, const Fields& f = {}) { log(LogLevel::error, m, f); }

private:
    std::ostream& sink_;
    LogLevel level_ = LogLevel::warn;
    LogFormat format_ = LogFormat::text;
};

}  // namespace binscope::cli
