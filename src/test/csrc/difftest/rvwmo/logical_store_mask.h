#pragma once
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace rvwmo {
// Sbuffer refills can widen a physical mask with clean cache-line bytes.
// Simultaneous-access ordering concerns only bytes attributed to stores.
// This does not certify publication: complete_group must still audit every
// required byte, group member and writer before any result can be accepted.
inline std::vector<uint8_t> logical_store_mask(const std::vector<uint8_t> &physical,
                                              const std::vector<uint64_t> &writers) {
  if (physical.size() != writers.size())
    throw std::invalid_argument("store mask and byte-writer widths differ");
  auto logical = physical;
  for (size_t byte = 0; byte < logical.size(); ++byte)
    logical[byte] = bool(physical[byte]) && writers[byte] != 0;
  return logical;
}
} // namespace rvwmo
