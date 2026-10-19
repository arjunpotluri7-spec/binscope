#include "binscope/findings.hpp"

#include "text.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace binscope {

namespace {

std::string fmt_entropy(double value) {
    return detail::fixed(value, 2);
}

using detail::hex;

bool starts_with(const std::string& text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

/// "segment LOAD[0]; sections UPX0, UPX1" for a list of (kind, name) pairs.
std::string describe(const std::vector<const Region*>& regions) {
    std::string out;
    for (const char* kind : {"segment", "section"}) {
        std::vector<std::string> names;
        for (const auto* r : regions) {
            if (r->kind == kind) {
                names.push_back(r->name);
            }
        }
        if (names.empty()) {
            continue;
        }
        if (!out.empty()) {
            out += "; ";
        }
        out += kind;
        if (names.size() > 1) {
            out += 's';
        }
        out += ' ';
        const std::size_t shown = names.size() < 3 ? names.size() : 3;
        for (std::size_t i = 0; i < shown; ++i) {
            out += (i == 0 ? "" : ", ") + names[i];
        }
        if (names.size() > shown) {
            out += " (+" + std::to_string(names.size() - shown) + " more)";
        }
    }
    return out;
}

class Analyzer {
public:
    Analyzer(const Target& target, const Config& config) : t_(target), c_(config) {}

    std::vector<Finding> run() {
        wx();
        entropy();
        entry_point();
        packer_names_rule();
        few_imports();
        overlaps();
        past_eof();
        issues(IssueKind::malformed, "BS010");
        issues(IssueKind::limit, "BS011");
        hardening();
        signature();
        encryption();
        rpaths();
        section_headers();
        std::sort(out_.begin(), out_.end(),
                  [](const Finding& a, const Finding& b) { return a.id < b.id; });
        // Hostile files can produce thousands of bogus entries; keep evidence readable.
        constexpr std::size_t kMaxEvidence = 8;
        for (auto& f : out_) {
            if (f.evidence.size() > kMaxEvidence) {
                const std::size_t hidden = f.evidence.size() - kMaxEvidence;
                f.evidence.resize(kMaxEvidence);
                f.evidence.push_back(
                    Evidence{"...", std::nullopt, std::to_string(hidden) + " more not shown"});
            }
        }
        return out_;
    }

private:
    Finding* emit(const char* id, std::string summary) {
        const Rule* rule = find_rule(id);
        if (rule == nullptr || !c_.enabled(*rule)) {
            return nullptr;
        }
        Finding f;
        f.id = rule->id;
        f.severity = c_.severity_for(*rule);
        f.points = c_.points_for(*rule);
        f.title = rule->title;
        f.summary = std::move(summary);
        f.explanation = rule->explanation;
        out_.push_back(std::move(f));
        return &out_.back();
    }

    [[nodiscard]] Evidence region_evidence(const Region& r, std::string detail = {}) const {
        return Evidence{r.kind + " " + r.name, t_.slice_offset + r.offset, std::move(detail)};
    }

    [[nodiscard]] std::uint64_t issue_offset(const ParseIssue& issue) const {
        return issue.absolute ? issue.offset : t_.slice_offset + issue.offset;
    }

    /// Regions whose bytes are judged for entropy: mapped sections when the file has
    /// them, otherwise its segments (packed ELF files often strip section headers).
    [[nodiscard]] std::vector<const Region*> entropy_regions() const {
        std::vector<const Region*> out;
        for (const auto& s : t_.sections) {
            if (s.allocated && s.has_file_data && s.entropy_bytes >= c_.min_entropy_bytes) {
                out.push_back(&s);
            }
        }
        if (out.empty() && t_.sections.empty()) {
            for (const auto& s : t_.segments) {
                if (s.allocated && s.has_file_data && s.entropy_bytes >= c_.min_entropy_bytes) {
                    out.push_back(&s);
                }
            }
        }
        return out;
    }

    void wx() {
        std::vector<const Region*> hits;
        for (const auto& s : t_.segments) {
            if (s.allocated && s.writable && s.executable) {
                hits.push_back(&s);
            }
        }
        for (const auto& s : t_.sections) {
            if (s.allocated && s.writable && s.executable) {
                hits.push_back(&s);
            }
        }
        if (hits.empty()) {
            return;
        }
        if (auto* f = emit("BS001", "W+X " + describe(hits))) {
            for (const auto* r : hits) {
                f->evidence.push_back(region_evidence(*r, "mapped writable and executable"));
            }
        }
    }

    void entropy() {
        std::vector<const Region*> exec;
        std::vector<const Region*> large;
        for (const auto* r : entropy_regions()) {
            if (r->entropy <= c_.entropy_threshold) {
                continue;
            }
            if (r->executable) {
                exec.push_back(r);
            } else if (r->file_size >= c_.large_section_bytes) {
                large.push_back(r);
            }
        }
        auto summary = [](const char* prefix, const std::vector<const Region*>& rs) {
            std::string s = prefix + describe(rs);
            if (rs.size() == 1) {
                s += " (" + fmt_entropy(rs.front()->entropy) + " bits/byte)";
            }
            return s;
        };
        if (!exec.empty()) {
            if (auto* f = emit("BS002", summary("high-entropy executable ", exec))) {
                for (const auto* r : exec) {
                    f->evidence.push_back(
                        region_evidence(*r, "entropy " + fmt_entropy(r->entropy) + " over " +
                                                std::to_string(r->entropy_bytes) + " bytes"));
                }
            }
        }
        if (!large.empty()) {
            if (auto* f = emit("BS003", summary("large high-entropy ", large))) {
                for (const auto* r : large) {
                    f->evidence.push_back(
                        region_evidence(*r, "entropy " + fmt_entropy(r->entropy) + " over " +
                                                std::to_string(r->entropy_bytes) + " bytes"));
                }
            }
        }
    }

    void entry_point() {
        if (!t_.entry || (!t_.expects_entry && *t_.entry == 0)) {
            return;
        }
        const std::uint64_t entry = *t_.entry;
        auto contains = [entry](const Region& r) {
            const std::uint64_t size = r.mem_size > 0 ? r.mem_size : r.file_size;
            return size > 0 && entry >= r.vaddr && entry - r.vaddr < size;
        };
        std::vector<const Region*> mapped;
        for (const auto& s : t_.sections) {
            if (s.allocated && (s.mem_size > 0 || s.file_size > 0)) {
                mapped.push_back(&s);
            }
        }
        if (mapped.empty()) {
            for (const auto& s : t_.segments) {
                if (s.allocated && s.mem_size > 0) {
                    mapped.push_back(&s);
                }
            }
        }
        if (mapped.empty()) {
            return;  // nothing to compare against; malformed-header rules cover this case
        }
        // Prefer a file-backed region: code cannot start in zero-filled memory.
        const Region* home = nullptr;
        for (const auto* r : mapped) {
            if (contains(*r) && (home == nullptr || (!home->has_file_data && r->has_file_data))) {
                home = r;
            }
        }
        if (home == nullptr) {
            if (auto* f = emit("BS004", "entry point " + hex(entry) + " is outside every " +
                                            mapped.front()->kind)) {
                f->evidence.push_back(Evidence{
                    "entry point", std::nullopt,
                    "address " + hex(entry) + " is not mapped by any " + mapped.front()->kind});
            }
            return;
        }
        if (!home->executable) {
            if (auto* f = emit("BS004", "entry point " + hex(entry) + " is in non-executable " +
                                            home->kind + " " + home->name)) {
                f->evidence.push_back(region_evidence(*home, "contains entry " + hex(entry)));
            }
        }
        if (mapped.size() >= 2 && home == mapped.back()) {
            if (auto* f =
                    emit("BS005", "entry point is in the last " + home->kind + " " + home->name)) {
                f->evidence.push_back(region_evidence(*home, "contains entry " + hex(entry)));
            }
        }
    }

    void packer_names_rule() {
        std::vector<std::pair<const Region*, const char*>> hits;
        auto check = [&](const Region& r) {
            for (const auto& p : packer_names()) {
                const std::string& n = r.name;
                // Mach-O section names are "segment,section"; match either half.
                const auto comma = n.find(',');
                const bool match =
                    n == p.section ||
                    (comma != std::string::npos &&
                     (n.substr(0, comma) == p.section || n.substr(comma + 1) == p.section));
                if (match) {
                    hits.emplace_back(&r, p.tool);
                    return;
                }
            }
        };
        for (const auto& s : t_.sections) {
            check(s);
        }
        if (t_.format == Format::macho) {
            for (const auto& s : t_.segments) {
                check(s);
            }
        }
        if (hits.empty()) {
            return;
        }
        std::vector<const Region*> regions;
        regions.reserve(hits.size());
        for (const auto& h : hits) {
            regions.push_back(h.first);
        }
        std::string summary =
            "packer-associated " + describe(regions) + " (" + hits.front().second + ")";
        if (auto* f = emit("BS006", summary)) {
            for (const auto& [r, tool] : hits) {
                f->evidence.push_back(region_evidence(*r, std::string("name used by ") + tool));
            }
        }
    }

    void few_imports() {
        if (t_.file_type == "relocatable object" || t_.file_type == "object") {
            return;
        }
        if (t_.import_count > c_.few_imports) {
            return;
        }
        const Region* hot = nullptr;
        for (const auto* r : entropy_regions()) {
            if (r->entropy > c_.entropy_threshold &&
                (hot == nullptr || r->entropy > hot->entropy)) {
                hot = r;
            }
        }
        if (hot == nullptr) {
            return;
        }
        const std::string count = std::to_string(t_.import_count);
        if (auto* f = emit("BS007", count + (t_.import_count == 1 ? " import" : " imports") +
                                        " alongside high-entropy " + hot->kind + " " + hot->name)) {
            f->evidence.push_back(Evidence{"imports", std::nullopt,
                                           count + " imported functions/symbols (threshold " +
                                               std::to_string(c_.few_imports) + ")"});
            f->evidence.push_back(region_evidence(*hot, "entropy " + fmt_entropy(hot->entropy)));
        }
    }

    void overlaps() {
        // Sort indices rather than pointers so ties keep table order deterministically.
        std::vector<std::size_t> order;
        for (std::size_t i = 0; i < t_.sections.size(); ++i) {
            if (t_.sections[i].has_file_data && t_.sections[i].file_size > 0) {
                order.push_back(i);
            }
        }
        std::stable_sort(order.begin(), order.end(), [this](std::size_t a, std::size_t b) {
            const Region& ra = t_.sections[a];
            const Region& rb = t_.sections[b];
            return ra.offset != rb.offset ? ra.offset < rb.offset : ra.file_size < rb.file_size;
        });
        std::vector<const Region*> rs;
        rs.reserve(order.size());
        for (const auto i : order) {
            rs.push_back(&t_.sections[i]);
        }
        std::vector<std::pair<const Region*, const Region*>> pairs;
        const Region* reach = nullptr;  // region whose end extends furthest so far
        for (const auto* r : rs) {
            if (reach != nullptr && r->offset < reach->offset + reach->file_size) {
                pairs.emplace_back(reach, r);
            }
            if (reach == nullptr || r->offset + r->file_size > reach->offset + reach->file_size) {
                reach = r;
            }
        }
        if (pairs.empty()) {
            return;
        }
        std::string summary = "sections " + pairs.front().first->name + " and " +
                              pairs.front().second->name + " overlap in the file";
        if (pairs.size() > 1) {
            summary += " (+" + std::to_string(pairs.size() - 1) + " more pairs)";
        }
        if (auto* f = emit("BS008", summary)) {
            for (std::size_t i = 0; i < pairs.size() && i < 8; ++i) {
                f->evidence.push_back(region_evidence(
                    *pairs[i].second,
                    "overlaps " + pairs[i].first->kind + " " + pairs[i].first->name));
            }
        }
    }

    void past_eof() {
        std::vector<const Region*> rs;
        for (const auto& s : t_.segments) {
            if (s.past_eof) {
                rs.push_back(&s);
            }
        }
        for (const auto& s : t_.sections) {
            if (s.past_eof) {
                rs.push_back(&s);
            }
        }
        std::vector<const ParseIssue*> is;
        for (const auto& i : t_.issues) {
            if (i.kind == IssueKind::out_of_bounds) {
                is.push_back(&i);
            }
        }
        if (rs.empty() && is.empty()) {
            return;
        }
        // A header-level claim (a whole table past EOF) explains more than the regions it
        // drags along, so it leads the summary when present.
        std::string summary =
            !is.empty() ? is.front()->message : describe(rs) + " extends past the end of the file";
        const std::size_t extra = rs.size() + is.size() - 1;
        if (extra > 0) {
            summary += " (+" + std::to_string(extra) + " more)";
        }
        if (auto* f = emit("BS009", summary)) {
            for (const auto* r : rs) {
                f->evidence.push_back(
                    region_evidence(*r, "ends at " + hex(r->offset + r->file_size) + ", file is " +
                                            std::to_string(t_.size) + " bytes"));
            }
            for (const auto* i : is) {
                f->evidence.push_back(Evidence{"structure", issue_offset(*i), i->message});
            }
        }
    }

    void issues(IssueKind kind, const char* id) {
        std::vector<const ParseIssue*> is;
        for (const auto& i : t_.issues) {
            if (i.kind == kind) {
                is.push_back(&i);
            }
        }
        if (is.empty()) {
            return;
        }
        std::string summary = is.front()->message;
        if (is.size() > 1) {
            summary += " (+" + std::to_string(is.size() - 1) + " more)";
        }
        if (auto* f = emit(id, summary)) {
            for (const auto* i : is) {
                f->evidence.push_back(Evidence{"header", issue_offset(*i), i->message});
            }
        }
    }

    void flag_rule(const char* key, const char* id, const std::string& summary) {
        const HardeningFlag* flag = t_.flag(key);
        if (flag == nullptr || !flag->enabled.has_value() || *flag->enabled) {
            return;
        }
        if (auto* f = emit(id, summary + " (" + flag->detail + ")")) {
            f->evidence.push_back(Evidence{"header", t_.slice_offset, flag->detail});
        }
    }

    void hardening() {
        flag_rule("pie", "BS012", "not position independent");
        flag_rule("relro", "BS013", "no RELRO");
        flag_rule("bind_now", "BS014", "lazy binding");
        flag_rule("nx_stack", "BS015", "executable stack");
        flag_rule("aslr", "BS016", "ASLR not enabled");
        flag_rule("dep", "BS017", "DEP not enabled");
        flag_rule("cfg", "BS018", "Control Flow Guard not enabled");
        flag_rule("high_entropy_va", "BS023", "high-entropy ASLR not enabled");
    }

    void signature() {
        if (t_.format == Format::macho) {
            const bool loadable =
                t_.file_type == "executable" || t_.file_type == "dylib" || t_.file_type == "bundle";
            if (loadable) {
                flag_rule("code_signature", "BS019", "no code signature");
            }
        } else if (t_.format == Format::pe) {
            flag_rule("certificate", "BS019", "no Authenticode certificate table");
        }
    }

    void encryption() {
        const Property* p = t_.property("cryptid");
        if (p == nullptr) {
            return;
        }
        const auto* id = std::get_if<std::uint64_t>(&p->value);
        if (id == nullptr || *id == 0) {
            return;
        }
        if (auto* f = emit("BS020", "encrypted content (cryptid " + std::to_string(*id) + ")")) {
            f->evidence.push_back(
                Evidence{"LC_ENCRYPTION_INFO", std::nullopt, "cryptid " + std::to_string(*id)});
        }
    }

    void rpaths() {
        std::vector<std::string> bad;
        for (const auto& p : t_.rpaths) {
            const bool anchored = starts_with(p, "/") || starts_with(p, "$ORIGIN") ||
                                  starts_with(p, "${ORIGIN}") || starts_with(p, "@loader_path") ||
                                  starts_with(p, "@executable_path") || starts_with(p, "@rpath");
            if (!anchored) {
                bad.push_back(p);
            }
        }
        if (bad.empty()) {
            return;
        }
        auto show = [](const std::string& p) {
            return p.empty() ? std::string("(empty: current directory)") : p;
        };
        if (auto* f = emit("BS021", "relative library search path " + show(bad.front()))) {
            for (const auto& p : bad) {
                f->evidence.push_back(Evidence{"search path", std::nullopt, show(p)});
            }
        }
    }

    void section_headers() {
        if (t_.format != Format::elf) {
            return;
        }
        const Property* p = t_.property("section_headers");
        if (p == nullptr) {
            return;
        }
        const auto* present = std::get_if<bool>(&p->value);
        if (present == nullptr || *present || t_.file_type == "relocatable object" ||
            t_.file_type == "core dump") {
            return;
        }
        if (auto* f = emit("BS022", "no section headers")) {
            f->evidence.push_back(Evidence{"header", t_.slice_offset, "e_shoff is 0 or unusable"});
        }
    }

    const Target& t_;
    const Config& c_;
    std::vector<Finding> out_;
};

}  // namespace

const char* severity_name(Severity severity) noexcept {
    switch (severity) {
        case Severity::info:
            return "info";
        case Severity::low:
            return "low";
        case Severity::medium:
            return "medium";
        case Severity::high:
            return "high";
    }
    return "info";
}

std::optional<Severity> parse_severity(std::string_view text) noexcept {
    if (text == "info") {
        return Severity::info;
    }
    if (text == "low") {
        return Severity::low;
    }
    if (text == "medium") {
        return Severity::medium;
    }
    if (text == "high") {
        return Severity::high;
    }
    return std::nullopt;
}

const std::vector<Rule>& rule_catalog() {
    static const std::vector<Rule> kRules = {
        {"BS001", Severity::high, 30, "Writable and executable memory",
         "A region mapped both writable and executable lets code be written and then run in "
         "place. Normal toolchains never emit it; self-unpacking stubs and JIT-style loaders do."},
        {"BS002", Severity::high, 25, "High-entropy executable section",
         "Machine code is far from random (typically 5-6.5 bits/byte). Executable bytes above "
         "the threshold usually mean compressed or encrypted code that is unpacked at run time."},
        {"BS003", Severity::medium, 10, "Large high-entropy section",
         "A large non-executable region with near-random content can be a packed payload. "
         "Compressed resources (images, archives) also look like this, so treat it as a hint."},
        {"BS004", Severity::high, 25, "Entry point outside executable code",
         "The entry point should land in an executable code section. Pointing elsewhere is a "
         "hallmark of packers, hand-built droppers, or a corrupted header."},
        {"BS005", Severity::medium, 10, "Entry point in the last section",
         "Compilers put code first; packers often append their stub as the last section and "
         "point the entry there."},
        {"BS006", Severity::medium, 20, "Packer-associated section name",
         "The section name matches one commonly produced by a packer or protector. Names are "
         "trivial to change or copy and these tools also ship in legitimate software, so this "
         "only says how the file was likely built."},
        {"BS007", Severity::medium, 15, "Few imports alongside high-entropy content",
         "Real programs import many functions. A handful of imports (often just loader "
         "functions) next to near-random data suggests the real import table is packed."},
        {"BS008", Severity::medium, 15, "Overlapping sections",
         "Two sections claim the same file bytes. Linkers do not produce this; it indicates a "
         "malformed or deliberately confusing file that tools may disagree about."},
        {"BS009", Severity::high, 20, "Structure extends past the end of the file",
         "A header points at data beyond the end of the file. The file is truncated or crafted; "
         "parsers that trust these values can read out of bounds."},
        {"BS010", Severity::medium, 15, "Malformed or inconsistent header",
         "A header field is truncated or contradicts the format specification. Binscope "
         "skipped what it could not trust; other tools may interpret the file differently."},
        {"BS011", Severity::medium, 10, "Parsing limit reached",
         "The file declares more entries than Binscope's safety caps allow, so the listing is "
         "truncated. Absurd counts are a common resource-exhaustion trick."},
        {"BS012", Severity::low, 10, "Not position independent",
         "The executable loads at a fixed address, so ASLR cannot randomise its code location, "
         "which makes memory-corruption exploits easier."},
        {"BS013", Severity::low, 5, "No RELRO",
         "Without PT_GNU_RELRO the relocation tables (including the GOT) stay writable at run "
         "time, a classic target for memory-corruption exploits."},
        {"BS014", Severity::low, 5, "Lazy binding (no BIND_NOW)",
         "Symbols are resolved lazily, so part of the GOT must stay writable after start-up; "
         "with BIND_NOW and RELRO it can be made fully read-only."},
        {"BS015", Severity::high, 20, "Executable stack",
         "An executable stack lets injected data on the stack run as code, removing one of the "
         "most basic exploit mitigations."},
        {"BS016", Severity::medium, 10, "ASLR not enabled",
         "Without DYNAMIC_BASE (and relocations to support it) Windows loads the image at its "
         "preferred base address every time."},
        {"BS017", Severity::medium, 15, "DEP not enabled",
         "Without NX_COMPAT the image opts out of Data Execution Prevention, so data pages may "
         "be executable."},
        {"BS018", Severity::low, 5, "Control Flow Guard not enabled",
         "GUARD_CF is not set, so indirect calls are not checked against valid targets."},
        {"BS019", Severity::info, 0, "No code signature",
         "No code signature structure is present. Binscope only checks presence and never "
         "verifies signatures; unsigned builds are normal in development and open source."},
        {"BS020", Severity::low, 5, "Encrypted Mach-O content",
         "LC_ENCRYPTION_INFO marks part of the image as encrypted (FairPlay or similar), so "
         "its code cannot be inspected statically."},
        {"BS021", Severity::low, 5, "Relative library search path",
         "A library search path that is relative (or empty) is resolved against the current "
         "directory, so running the program from an attacker-controlled directory can load "
         "planted libraries."},
        {"BS022", Severity::low, 10, "No ELF section headers",
         "The ELF file has no section header table. Loaders do not need it, but normal "
         "toolchains keep it; stripping it is common in packed or hand-crafted binaries."},
        {"BS023", Severity::low, 3, "High-entropy ASLR not enabled",
         "A 64-bit image without HIGH_ENTROPY_VA gets less address randomisation than it "
         "could."},
    };
    return kRules;
}

const Rule* find_rule(std::string_view id) {
    for (const auto& r : rule_catalog()) {
        if (id == r.id) {
            return &r;
        }
    }
    return nullptr;
}

int Config::points_for(const Rule& rule) const {
    const auto it = points.find(rule.id);
    return it != points.end() ? it->second : rule.points;
}

Severity Config::severity_for(const Rule& rule) const {
    const auto it = severities.find(rule.id);
    return it != severities.end() ? it->second : rule.severity;
}

bool Config::enabled(const Rule& rule) const {
    return disabled.count(rule.id) == 0;
}

std::vector<Finding> analyze(const Target& target, const Config& config) {
    Analyzer analyzer(target, config);
    return analyzer.run();
}

std::string score_label(int score) {
    if (score >= 80) {
        return "very high";
    }
    if (score >= 50) {
        return "high";
    }
    if (score >= 20) {
        return "moderate";
    }
    return "low";
}

Score compute_score(const std::vector<Finding>& findings) {
    Score s;
    for (const auto& f : findings) {
        s.raw += f.points;
    }
    s.total = std::clamp(s.raw, 0, 100);
    s.label = score_label(s.total);
    return s;
}

const std::vector<PackerName>& packer_names() {
    static const std::vector<PackerName> kNames = {
        {"UPX0", "UPX"},
        {"UPX1", "UPX"},
        {"UPX2", "UPX"},
        {"UPX!", "UPX"},
        {".UPX0", "UPX"},
        {".UPX1", "UPX"},
        {"__XHDR", "UPX (Mach-O)"},
        {".aspack", "ASPack"},
        {".adata", "ASPack"},
        {".ASPack", "ASPack"},
        {".packed", "generic packer"},
        {".petite", "Petite"},
        {".nsp0", "NsPack"},
        {".nsp1", "NsPack"},
        {".nsp2", "NsPack"},
        {".MPRESS1", "MPRESS"},
        {".MPRESS2", "MPRESS"},
        {".themida", "Themida"},
        {".winlice", "WinLicense"},
        {".vmp0", "VMProtect"},
        {".vmp1", "VMProtect"},
        {".vmp2", "VMProtect"},
        {".enigma1", "Enigma Protector"},
        {".enigma2", "Enigma Protector"},
        {"PEBundle", "PEBundle"},
        {"pebundle", "PEBundle"},
        {"PELOCKnt", "PELock"},
        {".perplex", "Perplex PE-Protector"},
        {".yP", "Y0da Protector"},
        {".y0da", "Y0da Protector"},
        {"kkrunchy", "kkrunchy"},
        {"FSG!", "FSG"},
        {"MEW", "MEW"},
        {".spack", "Simple Pack"},
        {".ccg", "CCG"},
    };
    return kNames;
}

}  // namespace binscope
