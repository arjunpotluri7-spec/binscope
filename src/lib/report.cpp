#include "binscope/report.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <variant>
#include <vector>

#include "binscope/parse.hpp"
#include "binscope/version.hpp"
#include "json.hpp"
#include "text.hpp"

namespace binscope {

namespace {

using detail::hex;

std::string fixed2(double value) {
    return detail::fixed(value, 2);
}

std::string pad(std::string text, std::size_t width) {
    if (text.size() < width) {
        text.append(width - text.size(), ' ');
    }
    return text;
}

std::string rpad(const std::string& text, std::size_t width) {
    return text.size() < width ? std::string(width - text.size(), ' ') + text : text;
}

std::string perms(const Region& r) {
    std::string p = "---";
    if (r.readable) {
        p[0] = 'r';
    }
    if (r.writable) {
        p[1] = 'w';
    }
    if (r.executable) {
        p[2] = 'x';
    }
    return p;
}

std::string property_text(const PropertyValue& v) {
    if (const auto* s = std::get_if<std::string>(&v)) {
        return *s;
    }
    if (const auto* n = std::get_if<std::uint64_t>(&v)) {
        return std::to_string(*n);
    }
    return std::get<bool>(v) ? "yes" : "no";
}

std::string flag_text(const HardeningFlag& f) {
    if (!f.enabled) {
        return "n/a";
    }
    return *f.enabled ? "yes" : "no";
}

/// Findings ordered as score factors: most points first, then by rule id.
std::vector<const Finding*> factors(const std::vector<Finding>& findings) {
    std::vector<std::size_t> order(findings.size());
    for (std::size_t i = 0; i < order.size(); ++i) {
        order[i] = i;
    }
    std::stable_sort(order.begin(), order.end(), [&findings](std::size_t a, std::size_t b) {
        const Finding& fa = findings[a];
        const Finding& fb = findings[b];
        return fa.points != fb.points ? fa.points > fb.points : fa.id < fb.id;
    });
    std::vector<const Finding*> out;
    out.reserve(order.size());
    for (const auto i : order) {
        out.push_back(&findings[i]);
    }
    return out;
}

const Region* entry_region(const Target& t) {
    if (!t.entry) {
        return nullptr;
    }
    const Region* best = nullptr;
    for (const auto& s : t.sections) {
        const std::uint64_t size = s.mem_size > 0 ? s.mem_size : s.file_size;
        if (s.allocated && size > 0 && *t.entry >= s.vaddr && *t.entry - s.vaddr < size &&
            (best == nullptr || (!best->has_file_data && s.has_file_data))) {
            best = &s;
        }
    }
    return best;
}

std::string target_label(const FileReport& file, const TargetReport& tr) {
    if (file.targets.size() > 1 || file.container == Format::macho_fat) {
        return file.path + " [" + (tr.target.arch.empty() ? "?" : tr.target.arch) + "]";
    }
    return file.path;
}

void wrap_pairs(std::string& out, const std::string& label, const std::vector<std::string>& items) {
    std::string indent = label;
    std::string line;
    for (const auto& item : items) {
        if (!line.empty() && line.size() + item.size() + 2 > 88) {
            out += indent + line + "\n";
            indent.assign(label.size(), ' ');
            line.clear();
        }
        line += (line.empty() ? "" : "  ") + item;
    }
    if (!line.empty()) {
        out += indent + line + "\n";
    }
}

void table_target(std::string& out, const TargetReport& tr, const TableOptions& opt) {
    const Target& t = tr.target;
    out += "  " + t.format_name;
    if (!t.arch.empty()) {
        out += " | " + t.arch;
    }
    if (!t.file_type.empty()) {
        out += " | " + t.file_type;
    }
    out += " | " + std::to_string(t.size) + " bytes | entropy " + fixed2(t.entropy) + "\n";
    if (t.entry) {
        const Region* home = entry_region(t);
        out +=
            "  entry      " + hex(*t.entry) + (home ? " in " + home->name : std::string()) + "\n";
    }
    if (!t.hardening.empty()) {
        std::vector<std::string> items;
        items.reserve(t.hardening.size());
        for (const auto& f : t.hardening) {
            items.push_back(f.key + "=" + flag_text(f));
        }
        wrap_pairs(out, "  hardening  ", items);
    }
    out += "  imports    " + std::to_string(t.libraries.size()) + " libraries, " +
           std::to_string(t.import_count) + " imported symbols";
    if (!t.rpaths.empty()) {
        out += "; search paths:";
        for (const auto& p : t.rpaths) {
            out += " " + (p.empty() ? std::string("(empty)") : p);
        }
    }
    out += '\n';
    out += "  layout     " + std::to_string(t.sections.size()) + " sections, " +
           std::to_string(t.segments.size()) + " segments\n";
    if (!t.properties.empty()) {
        std::vector<std::string> items;
        items.reserve(t.properties.size());
        for (const auto& p : t.properties) {
            items.push_back(p.key + "=" + property_text(p.value));
        }
        wrap_pairs(out, "  details    ", items);
    }

    if (opt.sections && (!t.sections.empty() || !t.segments.empty())) {
        out += "  regions\n";
        out += "    " + pad("name", 28) + pad("kind", 9) + pad("offset", 12) + rpad("size", 10) +
               "  " + pad("vaddr", 20) + pad("perm", 6) + "entropy\n";
        auto row = [&](const Region& r) {
            out += "    " + pad(r.name, 28) + pad(r.kind, 9) + pad(hex(r.offset), 12) +
                   rpad(std::to_string(r.has_file_data ? r.file_size : r.mem_size), 10) + "  " +
                   pad(hex(r.vaddr), 20) + pad(perms(r), 6) +
                   (r.entropy_bytes > 0 ? fixed2(r.entropy) : std::string("-")) +
                   (r.past_eof ? "  PAST EOF" : "") + (!r.has_file_data ? "  (no file data)" : "") +
                   "\n";
        };
        for (const auto& r : t.segments) {
            row(r);
        }
        for (const auto& r : t.sections) {
            row(r);
        }
    }
    if (opt.imports) {
        out += "  imported libraries\n";
        if (t.libraries.empty() && t.unbound_imports.empty()) {
            out += "    (none)\n";
        }
        for (const auto& lib : t.libraries) {
            out += "    " + lib.name;
            if (!lib.functions.empty()) {
                out += ':';
                for (std::size_t i = 0; i < lib.functions.size(); ++i) {
                    out += (i == 0 ? " " : ", ") + lib.functions[i];
                }
            }
            out += '\n';
        }
        if (!t.unbound_imports.empty()) {
            out += "    (symbols not bound to a library):";
            for (std::size_t i = 0; i < t.unbound_imports.size(); ++i) {
                out += (i == 0 ? " " : ", ") + t.unbound_imports[i];
            }
            out += '\n';
        }
    }

    out += "  score      " + std::to_string(tr.score.total) + "/100 (" + tr.score.label + ")";
    if (tr.score.raw > 100) {
        out += ", raw sum " + std::to_string(tr.score.raw) + " capped at 100";
    }
    out += '\n';
    for (const auto* f : factors(tr.findings)) {
        out += "    " + rpad("+" + std::to_string(f->points), 4) + "  " + f->summary + "\n";
    }
    if (tr.findings.empty()) {
        out += "    no findings\n";
        return;
    }
    out += "  findings\n";
    for (const auto& f : tr.findings) {
        out += "    " + f.id + "  " + pad(severity_name(f.severity), 7) + f.title + "\n";
        for (const auto& e : f.evidence) {
            out += "           - " + e.location;
            if (e.offset) {
                out += " @ " + hex(*e.offset);
            }
            if (!e.detail.empty()) {
                out += ": " + e.detail;
            }
            out += '\n';
        }
        out += "           why: " + f.explanation + "\n";
    }
}

void json_region(detail::JsonWriter& w, const Region& r) {
    w.begin_object();
    w.field("name", r.name);
    w.field("kind", r.kind);
    w.field("type", r.type);
    w.field("offset", r.offset);
    w.field("file_size", r.file_size);
    w.field("vaddr", r.vaddr);
    w.field("mem_size", r.mem_size);
    w.field("flags", r.raw_flags);
    w.field("readable", r.readable);
    w.field("writable", r.writable);
    w.field("executable", r.executable);
    w.field("has_file_data", r.has_file_data);
    w.field("past_eof", r.past_eof);
    w.key("entropy");
    w.fixed(r.entropy, 3);
    w.field("entropy_bytes", r.entropy_bytes);
    w.end_object();
}

void json_finding(detail::JsonWriter& w, const Finding& f) {
    w.begin_object();
    w.field("id", f.id);
    w.field("severity", severity_name(f.severity));
    w.field("title", f.title);
    w.field("summary", f.summary);
    w.field("explanation", f.explanation);
    w.field("points", f.points);
    w.key("evidence");
    w.begin_array();
    for (const auto& e : f.evidence) {
        w.begin_object();
        w.field("location", e.location);
        w.key("offset");
        if (e.offset) {
            w.value(*e.offset);
        } else {
            w.null();
        }
        w.field("detail", e.detail);
        w.end_object();
    }
    w.end_array();
    w.end_object();
}

const char* issue_kind(IssueKind k) {
    switch (k) {
        case IssueKind::malformed:
            return "malformed";
        case IssueKind::out_of_bounds:
            return "out_of_bounds";
        case IssueKind::limit:
            return "limit";
    }
    return "malformed";
}

void json_target(detail::JsonWriter& w, const TargetReport& tr) {
    const Target& t = tr.target;
    w.begin_object();
    w.field("format", format_id(t.format));
    w.field("format_name", t.format_name);
    w.field("arch", t.arch);
    w.field("bits", t.bits);
    w.field("endian", t.endian == Endian::little ? "little" : "big");
    w.field("file_type", t.file_type);
    w.field("slice_offset", t.slice_offset);
    w.field("size", t.size);
    w.key("entropy");
    w.fixed(t.entropy, 3);
    w.key("entry");
    if (t.entry) {
        w.value(*t.entry);
    } else {
        w.null();
    }
    w.key("hardening");
    w.begin_array();
    for (const auto& f : t.hardening) {
        w.begin_object();
        w.field("key", f.key);
        w.field("label", f.label);
        w.key("enabled");
        if (f.enabled) {
            w.value(*f.enabled);
        } else {
            w.null();
        }
        w.field("detail", f.detail);
        w.end_object();
    }
    w.end_array();
    w.key("properties");
    w.begin_object();
    for (const auto& p : t.properties) {
        w.key(p.key);
        if (const auto* s = std::get_if<std::string>(&p.value)) {
            w.value(*s);
        } else if (const auto* n = std::get_if<std::uint64_t>(&p.value)) {
            w.value(*n);
        } else {
            w.value(std::get<bool>(p.value));
        }
    }
    w.end_object();
    w.key("segments");
    w.begin_array();
    for (const auto& r : t.segments) {
        json_region(w, r);
    }
    w.end_array();
    w.key("sections");
    w.begin_array();
    for (const auto& r : t.sections) {
        json_region(w, r);
    }
    w.end_array();
    w.key("libraries");
    w.begin_array();
    for (const auto& lib : t.libraries) {
        w.begin_object();
        w.field("name", lib.name);
        w.key("functions");
        w.begin_array();
        for (const auto& fn : lib.functions) {
            w.value(fn);
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.key("unbound_imports");
    w.begin_array();
    for (const auto& s : t.unbound_imports) {
        w.value(s);
    }
    w.end_array();
    w.field("import_count", t.import_count);
    w.key("rpaths");
    w.begin_array();
    for (const auto& s : t.rpaths) {
        w.value(s);
    }
    w.end_array();
    w.key("issues");
    w.begin_array();
    for (const auto& i : t.issues) {
        w.begin_object();
        w.field("kind", issue_kind(i.kind));
        w.field("message", i.message);
        w.field("offset", i.absolute ? i.offset : t.slice_offset + i.offset);
        w.end_object();
    }
    w.end_array();
    w.key("findings");
    w.begin_array();
    for (const auto& f : tr.findings) {
        json_finding(w, f);
    }
    w.end_array();
    w.key("score");
    w.begin_object();
    w.field("total", tr.score.total);
    w.field("raw", tr.score.raw);
    w.field("label", tr.score.label);
    w.key("factors");
    w.begin_array();
    for (const auto* f : factors(tr.findings)) {
        w.begin_object();
        w.field("id", f->id);
        w.field("points", f->points);
        w.field("summary", f->summary);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.end_object();
}

std::string sarif_level(Severity s) {
    switch (s) {
        case Severity::high:
            return "error";
        case Severity::medium:
            return "warning";
        case Severity::low:
        case Severity::info:
            return "note";
    }
    return "note";
}

/// Percent-encodes a path for use as a SARIF artifact URI.
std::string uri_encode(const std::string& path) {
    static constexpr char kDigits[] = "0123456789ABCDEF";
    std::string out;
    for (const char ch : path) {
        const auto c = static_cast<unsigned char>(ch);
        const bool safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' ||
                          c == '/';
        if (safe) {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(kDigits[c >> 4U]);
            out.push_back(kDigits[c & 0xFU]);
        }
    }
    return out;
}

}  // namespace

int FileReport::score() const {
    int best = 0;
    for (const auto& t : targets) {
        best = std::max(best, t.score.total);
    }
    return best;
}

bool FileReport::has_finding_at_or_above(Severity severity) const {
    for (const auto& t : targets) {
        for (const auto& f : t.findings) {
            if (f.severity >= severity) {
                return true;
            }
        }
    }
    return false;
}

FileReport analyze_bytes(const std::string& path, ByteView data, const Config& config) {
    FileReport report;
    report.path = path;
    auto parsed = parse(data, config.limits);
    if (!parsed) {
        report.error = parsed.error().message;
        report.size = data.size();
        return report;
    }
    report.container = parsed->container;
    report.size = parsed->size;
    report.entropy = parsed->entropy;
    for (auto& t : parsed->targets) {
        TargetReport tr;
        tr.findings = analyze(t, config);
        tr.score = compute_score(tr.findings);
        tr.target = std::move(t);
        report.targets.push_back(std::move(tr));
    }
    return report;
}

FileReport error_report(const std::string& path, std::string message) {
    FileReport report;
    report.path = path;
    report.error = std::move(message);
    return report;
}

std::string render_table(const std::vector<FileReport>& reports, const TableOptions& options) {
    std::string out;
    bool first = true;
    for (const auto& file : reports) {
        if (!first) {
            out += '\n';
        }
        first = false;
        out += "== " + file.path;
        if (file.error) {
            out += " ==\n  error: " + *file.error + "\n";
            continue;
        }
        if (file.container == Format::macho_fat) {
            out += " (Mach-O universal, " + std::to_string(file.targets.size()) + " slice" +
                   (file.targets.size() == 1 ? "" : "s") + ", " + std::to_string(file.size) +
                   " bytes, entropy " + fixed2(file.entropy) + ")";
        }
        out += " ==\n";
        for (const auto& tr : file.targets) {
            if (file.container == Format::macho_fat) {
                out += "-- slice " + (tr.target.arch.empty() ? std::string("?") : tr.target.arch) +
                       " at offset " + hex(tr.target.slice_offset) +
                       " (region offsets are relative to the slice; finding offsets are "
                       "file offsets)\n";
            }
            table_target(out, tr, options);
        }
    }
    return out;
}

std::string render_json(const std::vector<FileReport>& reports) {
    detail::JsonWriter w;
    w.begin_object();
    w.field("schema_version", kJsonSchemaVersion);
    w.key("tool");
    w.begin_object();
    w.field("name", "binscope");
    w.field("version", kVersion);
    w.end_object();
    std::map<std::string, std::uint64_t> by_severity = {
        {"info", 0}, {"low", 0}, {"medium", 0}, {"high", 0}};
    std::uint64_t errors = 0;
    w.key("files");
    w.begin_array();
    for (const auto& file : reports) {
        w.begin_object();
        w.field("path", file.path);
        w.key("error");
        if (file.error) {
            ++errors;
            w.value(*file.error);
        } else {
            w.null();
        }
        w.field("container", file.error ? "" : format_id(file.container));
        w.field("size", file.size);
        w.key("entropy");
        w.fixed(file.entropy, 3);
        w.field("score", file.score());
        w.field("label", score_label(file.score()));
        w.key("targets");
        w.begin_array();
        for (const auto& tr : file.targets) {
            for (const auto& f : tr.findings) {
                ++by_severity[severity_name(f.severity)];
            }
            json_target(w, tr);
        }
        w.end_array();
        w.end_object();
    }
    w.end_array();
    w.key("summary");
    w.begin_object();
    w.field("files", static_cast<std::uint64_t>(reports.size()));
    w.field("errors", errors);
    w.key("findings_by_severity");
    w.begin_object();
    for (const char* s : {"high", "medium", "low", "info"}) {
        w.field(s, by_severity[s]);
    }
    w.end_object();
    w.end_object();
    w.end_object();
    return w.str();
}

std::string render_sarif(const std::vector<FileReport>& reports) {
    detail::JsonWriter w;
    w.begin_object();
    w.field("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
    w.field("version", "2.1.0");
    w.key("runs");
    w.begin_array();
    w.begin_object();
    w.key("tool");
    w.begin_object();
    w.key("driver");
    w.begin_object();
    w.field("name", "Binscope");
    w.field("version", kVersion);
    w.field("semanticVersion", kVersion);
    w.field("informationUri", "https://github.com/arjunpotluri7-spec/binscope");
    w.key("rules");
    w.begin_array();
    const auto& rules = rule_catalog();
    for (const auto& r : rules) {
        w.begin_object();
        w.field("id", r.id);
        w.field("name", r.title);
        w.key("shortDescription");
        w.begin_object();
        w.field("text", r.title);
        w.end_object();
        w.key("fullDescription");
        w.begin_object();
        w.field("text", r.explanation);
        w.end_object();
        w.key("defaultConfiguration");
        w.begin_object();
        w.field("level", sarif_level(r.severity));
        w.end_object();
        w.key("properties");
        w.begin_object();
        w.field("severity", severity_name(r.severity));
        w.field("points", r.points);
        w.end_object();
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.end_object();

    w.key("artifacts");
    w.begin_array();
    for (const auto& file : reports) {
        w.begin_object();
        w.key("location");
        w.begin_object();
        w.field("uri", uri_encode(file.path));
        w.end_object();
        w.field("length", file.size);
        w.end_object();
    }
    w.end_array();

    w.key("results");
    w.begin_array();
    for (std::size_t a = 0; a < reports.size(); ++a) {
        const auto& file = reports[a];
        for (const auto& tr : file.targets) {
            for (const auto& f : tr.findings) {
                std::size_t rule_index = 0;
                for (std::size_t i = 0; i < rules.size(); ++i) {
                    if (f.id == rules[i].id) {
                        rule_index = i;
                    }
                }
                w.begin_object();
                w.field("ruleId", f.id);
                w.field("ruleIndex", static_cast<std::uint64_t>(rule_index));
                w.field("level", sarif_level(f.severity));
                w.key("message");
                w.begin_object();
                std::string text = f.summary;
                if (file.targets.size() > 1) {
                    text.insert(0, "[" + tr.target.arch + "] ");
                }
                w.field("text", text + ". " + f.explanation);
                w.end_object();
                w.key("locations");
                w.begin_array();
                w.begin_object();
                w.key("physicalLocation");
                w.begin_object();
                w.key("artifactLocation");
                w.begin_object();
                w.field("uri", uri_encode(file.path));
                w.field("index", static_cast<std::uint64_t>(a));
                w.end_object();
                std::optional<std::uint64_t> offset;
                for (const auto& e : f.evidence) {
                    if (e.offset) {
                        offset = e.offset;
                        break;
                    }
                }
                if (offset) {
                    w.key("region");
                    w.begin_object();
                    w.field("byteOffset", *offset);
                    w.end_object();
                }
                w.end_object();
                if (!f.evidence.empty()) {
                    w.key("logicalLocations");
                    w.begin_array();
                    w.begin_object();
                    w.field("name", f.evidence.front().location);
                    w.field("kind", "module");
                    w.end_object();
                    w.end_array();
                }
                w.end_object();
                w.end_array();
                w.key("properties");
                w.begin_object();
                w.field("severity", severity_name(f.severity));
                w.field("points", f.points);
                w.field("arch", tr.target.arch);
                w.field("targetScore", tr.score.total);
                w.end_object();
                w.end_object();
            }
        }
    }
    w.end_array();
    w.key("invocations");
    w.begin_array();
    w.begin_object();
    w.field("executionSuccessful", true);
    w.key("toolExecutionNotifications");
    w.begin_array();
    for (const auto& file : reports) {
        if (!file.error) {
            continue;
        }
        w.begin_object();
        w.field("level", "error");
        w.key("message");
        w.begin_object();
        w.field("text", file.path + ": " + *file.error);
        w.end_object();
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.end_array();
    w.end_object();
    w.end_array();
    w.end_object();
    return w.str();
}

std::string render_score_lines(const std::vector<FileReport>& reports) {
    std::string out;
    for (const auto& file : reports) {
        if (file.error) {
            out += file.path + "  error: " + *file.error + "\n";
            continue;
        }
        for (const auto& tr : file.targets) {
            const Target& t = tr.target;
            out += target_label(file, tr) + "  " + t.format_name + "  " +
                   (t.arch.empty() ? "?" : t.arch) + "  " + std::to_string(tr.score.total) +
                   "/100 " + tr.score.label;
            const auto fs = factors(tr.findings);
            std::size_t shown = 0;
            for (const auto* f : fs) {
                if (shown == 3) {
                    break;
                }
                out += (shown == 0 ? "  " : " | ") + std::string("+") + std::to_string(f->points) +
                       " " + f->summary;
                ++shown;
            }
            if (fs.empty()) {
                out += "  no findings";
            }
            out += '\n';
        }
    }
    return out;
}

std::string render_formats() {
    return R"(Supported formats (detected from magic bytes, never from the file name):

ELF (32/64-bit, little and big endian)
  ELF header, program headers, section headers and names (incl. extended numbering),
  PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO, dynamic section (DT_NEEDED, DT_RPATH,
  DT_RUNPATH, BIND_NOW, DT_FLAGS, DT_FLAGS_1), .dynsym undefined symbols (imports),
  .symtab/.dynsym counts, .note.gnu.build-id
Mach-O (32/64-bit thin, either byte order) and universal/fat (fat32 and fat64)
  mach header and flags (MH_PIE, MH_ALLOW_STACK_EXECUTION, MH_NO_HEAP_EXECUTION),
  load commands: segments and sections, LC_LOAD_DYLIB (and weak/reexport/lazy/upward),
  LC_ID_DYLIB, LC_MAIN, LC_UNIXTHREAD (x86_64, arm64, i386, arm), LC_CODE_SIGNATURE
  (presence only), LC_ENCRYPTION_INFO(_64) cryptid, LC_RPATH, LC_SYMTAB/LC_DYSYMTAB
  undefined symbols mapped to their dylib, LC_UUID, LC_BUILD_VERSION
PE/COFF (PE32 and PE32+)
  DOS header, PE signature, COFF header, optional header and DllCharacteristics
  (DYNAMIC_BASE, HIGH_ENTROPY_VA, NX_COMPAT, GUARD_CF, NO_SEH, FORCE_INTEGRITY), data
  directories, section table (incl. /N long names), import directory (DLL names,
  function names and ordinals), timestamp, certificate directory (presence only: the
  Authenticode signature is not verified), .NET header presence, overlay size

For every format: per-section/segment file offset, size, permissions and Shannon
entropy, overall file entropy, size and count caps, and malformed-structure findings.
Files are only read, never executed or loaded.
)";
}

}  // namespace binscope
