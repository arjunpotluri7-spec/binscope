// libFuzzer harness. Built only with ENABLE_FUZZERS=ON on a compiler that ships
// libFuzzer (CI uses clang on Linux; Apple clang does not include it).
//   ./fuzz_parse -max_total_time=60 corpus/ samples/synthetic samples/macho
#include <cstddef>
#include <cstdint>

#include "fuzz_target.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    (void)binscope::fuzz::run_one(data, size);
    return 0;
}
