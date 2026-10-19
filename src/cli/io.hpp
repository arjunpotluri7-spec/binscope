// Safe file input and report output for the CLI.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "binscope/result.hpp"

namespace binscope::cli {

/// Reads a regular file of at most `max_size` bytes. Symbolic links are refused unless
/// `follow_symlinks` is set; directories, devices and FIFOs are always refused.
[[nodiscard]] Result<std::vector<std::uint8_t>> read_input(const std::string& path,
                                                           std::uint64_t max_size,
                                                           bool follow_symlinks);

/// Writes `content` to `path` with mode 0600 where the platform supports it. An existing
/// file is only replaced when `force` is set, and a symlink at `path` is never followed.
[[nodiscard]] Result<bool> write_output(const std::string& path, const std::string& content,
                                        bool force);

}  // namespace binscope::cli
