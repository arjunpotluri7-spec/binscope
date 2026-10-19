#include "binscope/diff.hpp"

#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <string>

#include "binscope/version.hpp"
#include "json.hpp"
#include "text.hpp"

namespace binscope {

namespace {

std::set<std::string> library_set(const Target& t) {
    std::set<std::string> out;
    for (const auto& lib : t.libraries) {
        out.insert(lib.name);
    }
    return out;
}

std::set<std::string> import_set(const Target& t) {
    std::set<std::string> out;
    for (const auto& lib : t.libraries) {
        for (const auto& fn : lib.functions) {
            out.insert(lib.name + "!" + fn);
        }
    }
    for (const auto& s : t.unbound_imports) {
        out.insert(s);
    }
    return out;
}

/// Sections keyed by name; repeated names get a "#n" suffix so each is compared once.
std::map<std::string, const Region*> region_map(const Target& t) {
    std::map<std::string, const Region*> out;
    std::map<std::string, int> seen;
    const auto& list = t.sections.empty() ? t.segments : t.sections;
    for (const auto& r : list) {
        const int n = seen[r.name]++;
        out[n == 0 ? r.name : r.name + "#" + std::to_string(n)] = &r;
    }
    return out;
}

template <typename T>
std::vector<T> minus(const std::set<T>& a, const std::set<T>& b) {
    std::vector<T> out;
    std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(out));
    return out;
}

TargetDiff diff_target(const TargetReport& before, const TargetReport& after, double delta) {
    TargetDiff d;
    const Target& a = before.target;
    const Target& b = after.target;
    d.arch = b.arch;
    d.format_name = b.format_name;
    d.score_before = before.score.total;
    d.score_after = after.score.total;

    const auto la = library_set(a);
    const auto lb = library_set(b);
    d.libraries_added = minus(lb, la);
    d.libraries_removed = minus(la, lb);
    const auto ia = import_set(a);
    const auto ib = import_set(b);
    d.imports_added = minus(ib, ia);
    d.imports_removed = minus(ia, ib);

    for (const auto& f : a.hardening) {
        const HardeningFlag* now = b.flag(f.key);
        const bool was = f.enabled.value_or(false);
        const bool is = now != nullptr && now->enabled.value_or(false);
        if (was && !is) {
            d.hardening_removed.push_back(f.key);
        }
    }
    for (const auto& f : b.hardening) {
        const HardeningFlag* old = a.flag(f.key);
        if (f.enabled.value_or(false) && (old == nullptr || !old->enabled.value_or(false))) {
            d.hardening_added.push_back(f.key);
        }
    }

    const auto ra = region_map(a);
    const auto rb = region_map(b);
    for (const auto& [name, r] : rb) {
        const auto it = ra.find(name);
        if (it == ra.end()) {
            d.sections_added.push_back(name);
            continue;
        }
        const Region* old = it->second;
        if (old->entropy_bytes > 0 && r->entropy_bytes > 0 &&
            std::fabs(r->entropy - old->entropy) > delta) {
            d.entropy_changes.push_back(EntropyChange{name, old->entropy, r->entropy});
        }
    }
    for (const auto& [name, r] : ra) {
        if (rb.find(name) == rb.end()) {
            d.sections_removed.push_back(name);
        }
    }

    std::set<std::string> old_ids;
    for (const auto& f : before.findings) {
        old_ids.insert(f.id);
    }
    std::set<std::string> new_ids;
    for (const auto& f : after.findings) {
        new_ids.insert(f.id);
        if (old_ids.count(f.id) == 0) {
            d.findings_new.push_back(f);
        }
    }
    d.findings_resolved = minus(old_ids, new_ids);
    return d;
}

std::string fixed2(double v) {
    return detail::fixed(v, 2);
}

void list(std::string& out, const char* label, const std::vector<std::string>& items,
          const char* sign) {
    if (items.empty()) {
        return;
    }
    out += std::string("  ") + label + " (" + std::to_string(items.size()) + ")\n";
    for (const auto& i : items) {
        out += std::string("    ") + sign + " " + i + "\n";
    }
}

void json_list(detail::JsonWriter& w, const char* key, const std::vector<std::string>& items) {
    w.key(key);
    w.begin_array();
    for (const auto& i : items) {
        w.value(i);
    }
    w.end_array();
}

}  // namespace

bool DiffReport::regression() const {
    for (const auto& t : targets) {
        if (!t.hardening_removed.empty()) {
            return true;
        }
        for (const auto& f : t.findings_new) {
            if (f.severity >= fail_on) {
                return true;
            }
        }
    }
    return false;
}

DiffReport diff_reports(const FileReport& before, const FileReport& after, double entropy_delta,
                        Severity fail_on) {
    DiffReport d;
    d.old_path = before.path;
    d.new_path = after.path;
    d.entropy_delta = entropy_delta;
    d.fail_on = fail_on;
    std::set<std::string> matched;
    for (const auto& tb : after.targets) {
        const TargetReport* match = nullptr;
        for (const auto& ta : before.targets) {
            if (ta.target.arch == tb.target.arch && ta.target.format == tb.target.format) {
                match = &ta;
                break;
            }
        }
        // Thin-to-thin comparisons across architectures still make sense (a port).
        if (match == nullptr && before.targets.size() == 1 && after.targets.size() == 1) {
            match = &before.targets.front();
        }
        if (match == nullptr) {
            d.only_new.push_back(tb.target.arch);
            continue;
        }
        matched.insert(match->target.arch);
        d.targets.push_back(diff_target(*match, tb, entropy_delta));
    }
    for (const auto& ta : before.targets) {
        if (matched.count(ta.target.arch) == 0) {
            d.only_old.push_back(ta.target.arch);
        }
    }
    return d;
}

std::string render_diff_table(const DiffReport& d) {
    std::string out = "diff " + d.old_path + " -> " + d.new_path + "\n";
    for (const auto& a : d.only_old) {
        out += "  architecture " + a + " removed\n";
    }
    for (const auto& a : d.only_new) {
        out += "  architecture " + a + " added (no counterpart to compare)\n";
    }
    for (const auto& t : d.targets) {
        out += "-- " + t.format_name + " " + t.arch + ": score " + std::to_string(t.score_before) +
               " -> " + std::to_string(t.score_after) + "\n";
        list(out, "hardening removed", t.hardening_removed, "-");
        list(out, "hardening added", t.hardening_added, "+");
        list(out, "libraries added", t.libraries_added, "+");
        list(out, "libraries removed", t.libraries_removed, "-");
        list(out, "imports added", t.imports_added, "+");
        list(out, "imports removed", t.imports_removed, "-");
        list(out, "sections added", t.sections_added, "+");
        list(out, "sections removed", t.sections_removed, "-");
        if (!t.entropy_changes.empty()) {
            out += "  entropy changed by more than " + fixed2(d.entropy_delta) + " (" +
                   std::to_string(t.entropy_changes.size()) + ")\n";
            for (const auto& e : t.entropy_changes) {
                out +=
                    "    ~ " + e.region + " " + fixed2(e.before) + " -> " + fixed2(e.after) + "\n";
            }
        }
        if (!t.findings_new.empty()) {
            out += "  new findings (" + std::to_string(t.findings_new.size()) + ")\n";
            for (const auto& f : t.findings_new) {
                out += "    + " + f.id + " " + severity_name(f.severity) + " +" +
                       std::to_string(f.points) + " " + f.summary + "\n";
            }
        }
        list(out, "resolved findings", t.findings_resolved, "-");
    }
    out += d.regression() ? "result: REGRESSION (hardening lost or new finding at/above " +
                                std::string(severity_name(d.fail_on)) + ")\n"
                          : "result: no regression\n";
    return out;
}

std::string render_diff_json(const DiffReport& d) {
    detail::JsonWriter w;
    w.begin_object();
    w.field("schema_version", 1);
    w.key("tool");
    w.begin_object();
    w.field("name", "binscope");
    w.field("version", kVersion);
    w.end_object();
    w.field("old", d.old_path);
    w.field("new", d.new_path);
    w.key("entropy_delta");
    w.fixed(d.entropy_delta, 3);
    w.field("fail_on", severity_name(d.fail_on));
    w.field("regression", d.regression());
    json_list(w, "architectures_removed", d.only_old);
    json_list(w, "architectures_added", d.only_new);
    w.key("targets");
    w.begin_array();
    for (const auto& t : d.targets) {
        w.begin_object();
        w.field("arch", t.arch);
        w.field("format_name", t.format_name);
        w.field("score_before", t.score_before);
        w.field("score_after", t.score_after);
        json_list(w, "hardening_removed", t.hardening_removed);
        json_list(w, "hardening_added", t.hardening_added);
        json_list(w, "libraries_added", t.libraries_added);
        json_list(w, "libraries_removed", t.libraries_removed);
        json_list(w, "imports_added", t.imports_added);
        json_list(w, "imports_removed", t.imports_removed);
        json_list(w, "sections_added", t.sections_added);
        json_list(w, "sections_removed", t.sections_removed);
        w.key("entropy_changes");
        w.begin_array();
        for (const auto& e : t.entropy_changes) {
            w.begin_object();
            w.field("region", e.region);
            w.key("before");
            w.fixed(e.before, 3);
            w.key("after");
            w.fixed(e.after, 3);
            w.end_object();
        }
        w.end_array();
        w.key("findings_new");
        w.begin_array();
        for (const auto& f : t.findings_new) {
            w.begin_object();
            w.field("id", f.id);
            w.field("severity", severity_name(f.severity));
            w.field("points", f.points);
            w.field("summary", f.summary);
            w.end_object();
        }
        w.end_array();
        json_list(w, "findings_resolved", t.findings_resolved);
        w.end_object();
    }
    w.end_array();
    w.end_object();
    return w.str();
}

}  // namespace binscope
