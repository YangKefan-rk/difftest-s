#ifndef DIFFTEST_BLACKPARROT_CACHE_GEOMETRY_H
#define DIFFTEST_BLACKPARROT_CACHE_GEOMETRY_H

#include <cstdint>

namespace blackparrot::cache_geometry {

// Geometry is pinned to the audited e_bp_multicore_4_cfg profile.
constexpr uint32_t kSetCount = 64;
constexpr uint32_t kWayCount = 8;
constexpr uint32_t kLineOffsetBits = 6;
constexpr uint32_t kWayMask = kWayCount - 1;
constexpr uint32_t kBankSelectMask = (uint32_t{1} << kWayCount) - 1;
constexpr uint32_t kPhysicalEntryCount = kSetCount * kWayCount;

constexpr bool is_one_hot_bank(uint32_t bank_select) {
  return bank_select && !(bank_select & (bank_select - 1)) && !(bank_select & ~kBankSelectMask);
}

constexpr uint32_t bank_index(uint32_t one_hot_bank) {
  for (uint32_t index = 0; index < kWayCount; ++index)
    if (one_hot_bank & (uint32_t{1} << index))
      return index;
  return kWayCount;
}

constexpr uint32_t set_for_address(uint64_t address) {
  return static_cast<uint32_t>((address >> kLineOffsetBits) & (kSetCount - 1));
}

constexpr uint32_t set_for_physical_index(uint32_t physical_index) {
  return physical_index / kWayCount;
}

// Callers validate the bank mask before converting it to a way index.
constexpr uint32_t way_for_location(uint32_t one_hot_bank, uint32_t physical_index) {
  const uint32_t bank_offset = physical_index & kWayMask;
  return (bank_index(one_hot_bank) + kWayCount - bank_offset) & kWayMask;
}

} // namespace blackparrot::cache_geometry

#endif
