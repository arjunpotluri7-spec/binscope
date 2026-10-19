// Internal interface shared by the per-format parsers.
#pragma once

#include <cstdint>
#include <string>

#include "binscope/bytes.hpp"
#include "binscope/model.hpp"
#include "binscope/parse.hpp"
#include "text.hpp"

namespace binscope::detail {

[[nodiscard]] Target parse_elf(ByteView image, const Limits& limits);
[[nodiscard]] Target parse_macho_thin(ByteView image, const Limits& limits);
[[nodiscard]] FileInfo parse_macho_fat(ByteView file, const Limits& limits);
[[nodiscard]] Target parse_pe(ByteView image, const Limits& limits);

/// Computes entropy and the past-EOF flag of a region against the image it came from.
void finish_region(Region& region, ByteView image);

void add_issue(Target& target, IssueKind kind, std::string message, std::uint64_t offset = 0);

void set_property(Target& target, std::string key, PropertyValue value);

/// Number of whole `entry_size` records of a table at `offset` that fit in `size`
/// bytes, capped at `wanted`.
[[nodiscard]] std::uint64_t records_that_fit(std::uint64_t offset, std::uint64_t entry_size,
                                             std::uint64_t wanted, std::uint64_t size);

/// Replaces control and non-ASCII bytes so names from the file are safe to print.
[[nodiscard]] std::string printable(const std::string& raw);

}  // namespace binscope::detail
