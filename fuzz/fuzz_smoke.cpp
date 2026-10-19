// Portable fuzz-smoke driver. Replays every seed file, then feeds N deterministic
// mutations of them through the same entry point as the libFuzzer harness. Meant to
// be built with -fsanitize=address,undefined: any memory or UB error aborts the run.
//
//   fuzz_smoke [--iterations N] [--seed S] PATH...   (PATH: files or directories)
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "fuzz_target.hpp"

namespace {

constexpr std::uintmax_t kMaxSeedBytes = 1024 * 1024;

class SplitMix64 {
public:
    explicit SplitMix64(std::uint64_t seed) : state_(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (state_ += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30U)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27U)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31U);
    }
    std::size_t below(std::size_t n) { return n == 0 ? 0 : static_cast<std::size_t>(next() % n); }

private:
    std::uint64_t state_;
};

/// Picks an offset, biased towards the first 4 KiB where headers live.
std::size_t pick_offset(SplitMix64& rng, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    if (rng.below(4) != 0) {
        return rng.below(std::min<std::size_t>(size, 4096));
    }
    return rng.below(size);
}

void mutate(std::vector<std::uint8_t>& d, const std::vector<std::vector<std::uint8_t>>& seeds,
            SplitMix64& rng) {
    static constexpr std::array<std::uint64_t, 12> kInteresting = {
        0,      1,      0x7F,       0x80,       0xFF,       0x100,
        0x7FFF, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFFULL};
    const std::size_t rounds = 1 + rng.below(8);
    for (std::size_t r = 0; r < rounds; ++r) {
        switch (rng.below(7)) {
            case 0:  // flip one bit
                if (!d.empty()) {
                    d[pick_offset(rng, d.size())] ^= static_cast<std::uint8_t>(1U << rng.below(8));
                }
                break;
            case 1:  // random byte
                if (!d.empty()) {
                    d[pick_offset(rng, d.size())] = static_cast<std::uint8_t>(rng.next());
                }
                break;
            case 2: {  // interesting 1/2/4/8-byte value, either byte order
                const std::size_t width = std::size_t{1} << rng.below(4);
                if (d.size() < width) {
                    break;
                }
                const std::size_t at = pick_offset(rng, d.size() - width + 1);
                const std::uint64_t v = kInteresting[rng.below(kInteresting.size())];
                const bool big = rng.below(2) == 1;
                for (std::size_t k = 0; k < width; ++k) {
                    const std::size_t shift = 8 * (big ? width - 1 - k : k);
                    d[at + k] = static_cast<std::uint8_t>(v >> shift);
                }
                break;
            }
            case 3:  // truncate
                if (!d.empty()) {
                    d.resize(rng.below(d.size()));
                }
                break;
            case 4: {  // insert random bytes
                const std::size_t at = d.empty() ? 0 : pick_offset(rng, d.size());
                const std::size_t n = 1 + rng.below(16);
                std::vector<std::uint8_t> extra(n);
                for (auto& b : extra) {
                    b = static_cast<std::uint8_t>(rng.next());
                }
                d.insert(d.begin() + static_cast<std::ptrdiff_t>(at), extra.begin(), extra.end());
                break;
            }
            case 5: {  // erase a range
                if (d.size() < 2) {
                    break;
                }
                const std::size_t at = pick_offset(rng, d.size());
                const std::size_t n = std::min(d.size() - at, 1 + rng.below(64));
                d.erase(d.begin() + static_cast<std::ptrdiff_t>(at),
                        d.begin() + static_cast<std::ptrdiff_t>(at + n));
                break;
            }
            default: {  // splice a chunk of another seed over this one
                const auto& other = seeds[rng.below(seeds.size())];
                if (other.empty() || d.empty()) {
                    break;
                }
                const std::size_t from = rng.below(other.size());
                const std::size_t to = pick_offset(rng, d.size());
                const std::size_t n =
                    std::min({other.size() - from, d.size() - to, std::size_t{1} + rng.below(256)});
                std::copy_n(other.begin() + static_cast<std::ptrdiff_t>(from), n,
                            d.begin() + static_cast<std::ptrdiff_t>(to));
                break;
            }
        }
    }
}

bool read_file(const std::filesystem::path& p, std::vector<std::uint8_t>& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        return false;
    }
    out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::uint64_t iterations = 50000;
    std::uint64_t seed = 0x5EEDB175C0FEULL;
    std::vector<std::string> paths;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        if ((arg == "--iterations" || arg == "--seed") && i + 1 < argc) {
            const std::string v =
                argv[++i];  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            std::uint64_t n = 0;
            const auto [ptr, ec] = std::from_chars(v.data(), v.data() + v.size(), n);
            if (ec != std::errc() || ptr != v.data() + v.size()) {
                std::cerr << "fuzz_smoke: invalid number '" << v << "'\n";
                return 2;
            }
            (arg == "--iterations" ? iterations : seed) = n;
        } else {
            paths.push_back(arg);
        }
    }
    if (paths.empty()) {
        std::cerr << "usage: fuzz_smoke [--iterations N] [--seed S] PATH...\n";
        return 2;
    }

    std::vector<std::filesystem::path> files;
    for (const auto& p : paths) {
        std::error_code ec;
        if (std::filesystem::is_directory(p, ec)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(p, ec)) {
                if (entry.is_regular_file() && !entry.is_symlink()) {
                    files.push_back(entry.path());
                }
            }
        } else if (std::filesystem::is_regular_file(p, ec)) {
            files.emplace_back(p);
        }
    }
    std::sort(files.begin(), files.end());  // deterministic order across platforms
    std::vector<std::vector<std::uint8_t>> seeds;
    for (const auto& f : files) {
        std::error_code ec;
        if (std::filesystem::file_size(f, ec) > kMaxSeedBytes || ec) {
            continue;
        }
        std::vector<std::uint8_t> data;
        if (read_file(f, data)) {
            seeds.push_back(std::move(data));
        }
    }
    if (seeds.empty()) {
        std::cerr << "fuzz_smoke: no seed files found\n";
        return 2;
    }

    const auto start = std::chrono::steady_clock::now();
    std::uint64_t findings = 0;
    std::uint64_t bytes = 0;
    for (const auto& s : seeds) {
        findings += binscope::fuzz::run_one(s.data(), s.size());
        bytes += s.size();
    }
    SplitMix64 rng(seed);
    std::vector<std::uint8_t> buf;
    for (std::uint64_t i = 0; i < iterations; ++i) {
        buf = seeds[rng.below(seeds.size())];
        mutate(buf, seeds, rng);
        findings += binscope::fuzz::run_one(buf.data(), buf.size());
        bytes += buf.size();
    }
    const auto secs =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::printf(
        "fuzz_smoke: %zu seed files replayed, %llu mutated inputs (seed 0x%llx), %llu bytes "
        "parsed, %llu findings produced, %.1f s, no crashes\n",
        seeds.size(), static_cast<unsigned long long>(iterations),
        static_cast<unsigned long long>(seed), static_cast<unsigned long long>(bytes),
        static_cast<unsigned long long>(findings), secs);
    return 0;
}
