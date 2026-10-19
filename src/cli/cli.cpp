#include "cli.hpp"

#include <charconv>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "binscope/config.hpp"
#include "binscope/diff.hpp"
#include "binscope/findings.hpp"
#include "binscope/report.hpp"
#include "binscope/version.hpp"
#include "io.hpp"
#include "log.hpp"

namespace binscope::cli {

namespace {

constexpr const char* kMainHelp = R"(binscope - static triage for ELF, Mach-O and PE executables

Reads executable files as plain bytes, parses their headers defensively and explains
red flags with a 0-100 suspicion score that lists every factor. Files are never run,
loaded or modified, and nothing is sent over the network.

Usage:
  binscope inspect FILE... [--format table|json|sarif] [--sections] [--imports]
                           [--output FILE] [--force] [--fail-on SEVERITY]
  binscope score FILE...   [--output FILE] [--force] [--fail-on SEVERITY]
  binscope diff OLD NEW    [--format table|json] [--entropy-delta N]
                           [--fail-on SEVERITY] [--output FILE] [--force]
  binscope formats         list supported formats and what is parsed
  binscope rules           list rule ids, severities and points (after --config)

Common options:
  --config FILE            settings file (see config.example.toml)
  --max-size-mib N         refuse files larger than N MiB (default 256)
  --follow-symlinks        read input paths that are symbolic links
  --log-level LEVEL        debug, info, warn (default) or error
  --log-format FORMAT      text (default) or json; diagnostics go to stderr
  -h, --help               show help (also: binscope COMMAND --help)
  -V, --version            show the version

Exit codes:
  0  ran fine and no finding at or above --fail-on (or diff: no regression)
  1  at least one finding at or above --fail-on (or diff: regression found)
  2  usage, configuration or input error (a file could not be read or recognised)
)";

constexpr const char* kInspectHelp = R"(Usage: binscope inspect FILE... [options]

Parse each file and report its structure, hardening, findings and suspicion score.

Options:
  --format FORMAT       table (default), json or sarif
  --sections            include the full section/segment table (table format)
  --imports             include imported libraries and functions (table format)
  --output FILE         write the report to FILE (mode 0600) instead of stdout
  --force               allow --output to replace an existing file
  --fail-on SEVERITY    exit 1 if any finding is at or above info|low|medium|high
  plus the common options shown by `binscope --help`
)";

constexpr const char* kScoreHelp = R"(Usage: binscope score FILE... [options]

One line per file (per slice for universal binaries): format, architecture, score,
label and the three largest score factors.

Options:
  --output FILE         write to FILE (mode 0600) instead of stdout
  --force               allow --output to replace an existing file
  --fail-on SEVERITY    exit 1 if any finding is at or above info|low|medium|high
  plus the common options shown by `binscope --help`
)";

constexpr const char* kDiffHelp = R"(Usage: binscope diff OLD NEW [options]

Compare two builds of the same program: new or removed libraries and imports,
hardening flags that were lost or gained, added or removed sections, sections whose
entropy moved by more than the threshold, and new or resolved findings.

Options:
  --format FORMAT       table (default) or json
  --entropy-delta N     report entropy changes larger than N bits/byte (default 0.5,
                        or diff_entropy_delta from --config)
  --fail-on SEVERITY    new findings at or above this count as a regression
                        (default high); any lost hardening flag always does
  --output FILE         write to FILE (mode 0600) instead of stdout
  --force               allow --output to replace an existing file
  plus the common options shown by `binscope --help`
)";

struct Options {
    std::string command;
    std::vector<std::string> files;
    std::string format = "table";
    bool format_given = false;
    std::optional<std::string> output;
    bool force = false;
    std::optional<Severity> fail_on;
    bool sections = false;
    bool imports = false;
    std::optional<std::string> config;
    std::optional<std::uint64_t> max_size_mib;
    bool follow_symlinks = false;
    std::optional<double> entropy_delta;
    LogLevel log_level = LogLevel::warn;
    LogFormat log_format = LogFormat::text;
    bool help = false;
    bool version = false;
};

struct UsageError {
    std::string message;
};

bool takes_value(const std::string& name) {
    static const std::set<std::string> kValued = {"--format",    "--output",     "-o",
                                                  "--fail-on",   "--config",     "--max-size-mib",
                                                  "--log-level", "--log-format", "--entropy-delta"};
    return kValued.count(name) != 0;
}

std::optional<double> parse_decimal(const std::string& text) {
    double whole = 0.0;
    double scale = 0.0;
    bool any = false;
    for (const char c : text) {
        if (c >= '0' && c <= '9') {
            any = true;
            if (scale == 0.0) {
                whole = whole * 10.0 + (c - '0');
            } else {
                whole += (c - '0') * scale;
                scale /= 10.0;
            }
        } else if (c == '.' && scale == 0.0) {
            scale = 0.1;
        } else {
            return std::nullopt;
        }
    }
    return any ? std::optional<double>(whole) : std::nullopt;
}

/// Parses arguments; returns an error message for usage problems.
std::optional<UsageError> parse_args(const std::vector<std::string>& args, Options& o) {
    bool options_done = false;
    for (std::size_t i = 0; i < args.size(); ++i) {
        std::string arg = args[i];
        if (options_done || arg.empty() || arg[0] != '-' || arg == "-") {
            if (o.command.empty()) {
                o.command = arg;
            } else {
                o.files.push_back(arg);
            }
            continue;
        }
        if (arg == "--") {
            options_done = true;
            continue;
        }
        std::optional<std::string> inline_value;
        const auto eq = arg.find('=');
        if (arg.rfind("--", 0) == 0 && eq != std::string::npos) {
            inline_value = arg.substr(eq + 1);
            arg = arg.substr(0, eq);
        }
        std::string value;
        if (takes_value(arg)) {
            if (inline_value) {
                value = *inline_value;
            } else if (i + 1 < args.size()) {
                value = args[++i];
            } else {
                return UsageError{"option " + arg + " needs a value"};
            }
        } else if (inline_value) {
            return UsageError{"option " + arg + " does not take a value"};
        }

        if (arg == "-h" || arg == "--help") {
            o.help = true;
        } else if (arg == "-V" || arg == "--version") {
            o.version = true;
        } else if (arg == "--format") {
            o.format = value;
            o.format_given = true;
        } else if (arg == "--output" || arg == "-o") {
            o.output = value;
        } else if (arg == "--force") {
            o.force = true;
        } else if (arg == "--fail-on") {
            if (value == "none") {
                o.fail_on.reset();
            } else {
                const auto sev = parse_severity(value);
                if (!sev) {
                    return UsageError{"--fail-on must be info, low, medium, high or none, got '" +
                                      value + "'"};
                }
                o.fail_on = sev;
            }
        } else if (arg == "--sections") {
            o.sections = true;
        } else if (arg == "--imports") {
            o.imports = true;
        } else if (arg == "--config") {
            o.config = value;
        } else if (arg == "--max-size-mib") {
            std::uint64_t n = 0;
            const auto* end = value.data() + value.size();
            const auto [ptr, ec] = std::from_chars(value.data(), end, n);
            if (ec != std::errc() || ptr != end || n == 0 || n > 4096) {
                return UsageError{"--max-size-mib must be a whole number from 1 to 4096, got '" +
                                  value + "'"};
            }
            o.max_size_mib = n;
        } else if (arg == "--follow-symlinks") {
            o.follow_symlinks = true;
        } else if (arg == "--entropy-delta") {
            const auto d = parse_decimal(value);
            if (!d || *d > 8.0) {
                return UsageError{"--entropy-delta must be a number from 0 to 8, got '" + value +
                                  "'"};
            }
            o.entropy_delta = d;
        } else if (arg == "--log-level") {
            const auto level = parse_log_level(value);
            if (!level) {
                return UsageError{"--log-level must be debug, info, warn or error, got '" + value +
                                  "'"};
            }
            o.log_level = *level;
        } else if (arg == "--log-format") {
            if (value == "text") {
                o.log_format = LogFormat::text;
            } else if (value == "json") {
                o.log_format = LogFormat::json;
            } else {
                return UsageError{"--log-format must be text or json, got '" + value + "'"};
            }
        } else {
            return UsageError{"unknown option " + arg};
        }
    }
    return std::nullopt;
}

std::optional<UsageError> validate(const Options& o) {
    const std::string& c = o.command;
    if (c != "inspect" && c != "score" && c != "diff" && c != "formats" && c != "rules") {
        return UsageError{"unknown command '" + c +
                          "' (expected inspect, score, diff, formats or rules)"};
    }
    if (c == "inspect") {
        if (o.format != "table" && o.format != "json" && o.format != "sarif") {
            return UsageError{"--format must be table, json or sarif, got '" + o.format + "'"};
        }
    } else if (c == "diff") {
        if (o.format != "table" && o.format != "json") {
            return UsageError{"diff --format must be table or json, got '" + o.format + "'"};
        }
    } else if (o.format_given) {
        return UsageError{"--format is not valid for '" + c + "'"};
    }
    if ((o.sections || o.imports) && c != "inspect") {
        return UsageError{std::string(o.sections ? "--sections" : "--imports") +
                          " is only valid for 'inspect'"};
    }
    if (o.entropy_delta && c != "diff") {
        return UsageError{"--entropy-delta is only valid for 'diff'"};
    }
    if ((c == "formats" || c == "rules") && (o.output || o.fail_on || !o.files.empty())) {
        return UsageError{"'" + c + "' takes no files or report options"};
    }
    if ((c == "inspect" || c == "score") && o.files.empty()) {
        return UsageError{"'" + c + "' needs at least one FILE"};
    }
    if (c == "diff" && o.files.size() != 2) {
        return UsageError{"'diff' needs exactly two files: OLD NEW"};
    }
    if (o.force && !o.output) {
        return UsageError{"--force only applies together with --output"};
    }
    return std::nullopt;
}

int emit(const std::string& text, const Options& o, std::ostream& out, Logger& log) {
    if (!o.output) {
        out << text;
        out.flush();
        return kExitOk;
    }
    auto written = write_output(*o.output, text, o.force);
    if (!written) {
        log.error(written.error().message);
        return kExitError;
    }
    log.info("report written", {{"path", *o.output}});
    return kExitOk;
}

FileReport load_one(const std::string& path, const Config& cfg, const Options& o, Logger& log) {
    auto data = read_input(path, cfg.limits.max_file_size, o.follow_symlinks);
    if (!data) {
        log.error(data.error().message);
        return error_report(path, data.error().message);
    }
    auto report = analyze_bytes(path, ByteView(std::span<const std::uint8_t>(*data)), cfg);
    if (report.error) {
        log.error(path + ": " + *report.error);
        return report;
    }
    std::size_t issues = 0;
    for (const auto& t : report.targets) {
        issues += t.target.issues.size();
    }
    if (issues > 0) {
        log.warn(path + ": malformed or truncated structures found; reported as findings",
                 {{"issues", std::to_string(issues)}});
    }
    log.debug("analysed", {{"path", path},
                           {"container", format_id(report.container)},
                           {"targets", std::to_string(report.targets.size())},
                           {"score", std::to_string(report.score())}});
    return report;
}

std::string render_rules(const Config& cfg) {
    std::string out = "id     severity  points  title\n";
    for (const auto& r : rule_catalog()) {
        std::string sev = severity_name(cfg.severity_for(r));
        sev.append(10 - sev.size(), ' ');
        std::string pts = std::to_string(cfg.points_for(r));
        pts.insert(0, 6 - pts.size(), ' ');
        out += std::string(r.id) + "  " + sev + pts + "  " + r.title +
               (cfg.enabled(r) ? "" : "  (disabled)") + "\n";
    }
    return out;
}

}  // namespace

int run(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    Logger log(err);
    Options o;
    if (auto e = parse_args(args, o)) {
        log.error(e->message + " (see binscope --help)");
        return kExitError;
    }
    log.configure(o.log_level, o.log_format);
    if (o.version) {
        out << "binscope " << kVersion << "\n";
        return kExitOk;
    }
    if (o.command.empty()) {
        if (o.help) {
            out << kMainHelp;
            return kExitOk;
        }
        err << kMainHelp;
        return kExitError;
    }
    if (o.help) {
        if (o.command == "inspect") {
            out << kInspectHelp;
        } else if (o.command == "score") {
            out << kScoreHelp;
        } else if (o.command == "diff") {
            out << kDiffHelp;
        } else {
            out << kMainHelp;
        }
        return kExitOk;
    }
    if (auto e = validate(o)) {
        log.error(e->message + " (see binscope --help)");
        return kExitError;
    }

    Config cfg;
    if (o.config) {
        auto loaded = load_config(*o.config);
        if (!loaded) {
            log.error(loaded.error().message);
            return kExitError;
        }
        cfg = *loaded;
        log.debug("config loaded", {{"path", *o.config}});
    }
    if (o.max_size_mib) {
        cfg.limits.max_file_size = *o.max_size_mib * 1024 * 1024;
    }

    if (o.command == "formats") {
        out << render_formats();
        return kExitOk;
    }
    if (o.command == "rules") {
        out << render_rules(cfg);
        return kExitOk;
    }

    if (o.command == "diff") {
        const auto before = load_one(o.files[0], cfg, o, log);
        const auto after = load_one(o.files[1], cfg, o, log);
        if (before.error || after.error) {
            return kExitError;
        }
        const auto d = diff_reports(before, after, o.entropy_delta.value_or(cfg.diff_entropy_delta),
                                    o.fail_on.value_or(Severity::high));
        const std::string text = o.format == "json" ? render_diff_json(d) : render_diff_table(d);
        if (emit(text, o, out, log) != kExitOk) {
            return kExitError;
        }
        return d.regression() ? kExitFindings : kExitOk;
    }

    std::vector<FileReport> reports;
    bool input_error = false;
    for (const auto& path : o.files) {
        reports.push_back(load_one(path, cfg, o, log));
        input_error = input_error || reports.back().error.has_value();
    }
    std::string text;
    if (o.command == "score") {
        text = render_score_lines(reports);
    } else if (o.format == "json") {
        text = render_json(reports);
    } else if (o.format == "sarif") {
        text = render_sarif(reports);
    } else {
        text = render_table(reports, TableOptions{o.sections, o.imports});
    }
    if (emit(text, o, out, log) != kExitOk || input_error) {
        return kExitError;
    }
    if (o.fail_on) {
        for (const auto& r : reports) {
            if (r.has_finding_at_or_above(*o.fail_on)) {
                return kExitFindings;
            }
        }
    }
    return kExitOk;
}

}  // namespace binscope::cli
