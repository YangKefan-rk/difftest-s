#ifndef DIFFTEST_RVWMO_PRODUCER_IDS_H
#define DIFFTEST_RVWMO_PRODUCER_IDS_H

#include <cstdint>

namespace rvwmo {

// Producer IDs name lossless event channels within one Difftest-S session.
constexpr uint32_t kInvalidProducerId = 0;
constexpr uint32_t kFirstHartProducerId = 1;
constexpr uint32_t kMaxHartProducerId = 0x3fffffff;
constexpr uint32_t kMemoryFabricProducerBase = 0x80000000;
constexpr uint32_t kMaxMemoryFabricIndex = 0x7fffffff;

constexpr uint32_t hart_producer_id(uint32_t hart) {
  return hart < kMaxHartProducerId ? kFirstHartProducerId + hart : kInvalidProducerId;
}

constexpr uint32_t memory_fabric_producer_id(uint32_t fabric_index = 0) {
  return fabric_index <= kMaxMemoryFabricIndex ? kMemoryFabricProducerBase + fabric_index : kInvalidProducerId;
}

} // namespace rvwmo

#endif
