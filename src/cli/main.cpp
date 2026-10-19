#include <exception>
#include <iostream>
#include <string>
#include <vector>

#include "cli.hpp"

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args;
        args.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0);
        for (int i = 1; i < argc; ++i) {
            args.emplace_back(argv[i]);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        }
        return binscope::cli::run(args, std::cout, std::cerr);
    } catch (const std::bad_alloc&) {
        std::cerr << "binscope: error: out of memory\n";
    } catch (const std::exception& e) {
        std::cerr << "binscope: error: internal error: " << e.what() << "\n";
    }
    return binscope::cli::kExitError;
}
