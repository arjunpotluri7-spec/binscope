#pragma once

#include <ostream>
#include <string>
#include <vector>

namespace binscope::cli {

inline constexpr int kExitOk = 0;
inline constexpr int kExitFindings = 1;
inline constexpr int kExitError = 2;

/// Runs the command line (arguments without the program name). Reports go to `out`,
/// diagnostics to `err`. Returns the process exit code.
int run(const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

}  // namespace binscope::cli
