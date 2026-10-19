// Configuration loading. The file format is a small, strict TOML subset:
// [section] headers, `key = value` lines, integers, decimals, "strings", true/false and
// one-line arrays of strings. Unknown sections or keys are errors, not silently ignored.
#pragma once

#include <string>
#include <string_view>

#include "binscope/findings.hpp"
#include "binscope/result.hpp"

namespace binscope {

/// Parses config text. `source` names the file in error messages ("config.toml:12: ...").
[[nodiscard]] Result<Config> parse_config(std::string_view text, std::string_view source);

/// Reads and parses a config file (at most 1 MiB).
[[nodiscard]] Result<Config> load_config(const std::string& path);

}  // namespace binscope
