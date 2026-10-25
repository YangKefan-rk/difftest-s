#ifndef DIFFTEST_ADAPTERS_BOOM_WORD_BYTES_H
#define DIFFTEST_ADAPTERS_BOOM_WORD_BYTES_H

#include "boom_event_adapter.h"
#include <array>

namespace rvwmo {
namespace boom {

// SRAM/StoreGen words place address bits [2:0] at the corresponding byte lane.
// Independently captured LoadGen retirement values place the result at bit 0.
enum class WordLayout { AlignedMemoryWord, LowBytes };

struct WordBytes {
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
  std::vector<std::optional<OperationId>> writers;
};

CheckResult extract_word_bytes(uint64_t physical_address, uint8_t log2_size, uint64_t word, uint8_t byte_mask,
                               WordLayout layout, uint8_t known_writer_mask,
                               const std::array<OperationId, 8> &writers, WordBytes &result);

// BOOM-private bridge records, matching the information exported by the Scala
// probe. Source is passed separately by the producer transport, never inferred
// from host delivery or converted into a GMO rank here.
struct ProbeIdentity {
  uint64_t epoch = 0;
  uint64_t uid = 0;
  uint64_t rob_generation = 0;
  uint64_t memory_generation = 0;
  uint32_t attempt = 0;
};

struct ProbeInstruction {
  ProbeIdentity identity;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint32_t rob_index = 0;
  uint32_t ldq_index = 0;
  uint32_t stq_index = 0;
  bool uses_ldq = false;
  bool uses_stq = false;
  bool atomic = false;
  bool architectural = true;
  uint8_t log2_size = 0;
  IntegerDestinationType destination_type = IntegerDestinationType::None;
  uint8_t logical_destination = 0;
  uint64_t writeback_value = 0;
};

struct ProbeLoad {
  ProbeIdentity identity;
  uint32_t queue_index = 0;
  uint64_t address = 0;
  uint64_t raw_word = 0;
  uint8_t log2_size = 0;
  uint8_t byte_mask = 0;
  uint8_t known_writer_mask = 0;
  std::array<ProbeIdentity, 8> writers{};
  LoadSamplingPoint sampling_point = LoadSamplingPoint::Unavailable;
  bool source_complete = false;
};

struct ProbeStore {
  ProbeIdentity identity;
  uint32_t queue_index = 0;
  uint64_t address = 0;
  uint64_t word = 0;
  uint8_t log2_size = 0;
  uint8_t byte_mask = 0;
  bool atomic = false;
};

struct ProbeQueueAllocation {
  ProbeIdentity identity;
  uint32_t index = 0;
  bool load = false;
};

struct ProbeLoadRetirement {
  ProbeIdentity identity;
  uint32_t queue_index = 0;
  uint64_t address = 0;
  uint64_t independent_data = 0;
};

// Joins same-dispatch core and queue records, masks the core's circular queue
// wrap bit, and obtains memory_generation from the queue allocation observation.
CheckResult merge_allocation(uint32_t hart, const ProbeInstruction &core,
                              const std::optional<ProbeQueueAllocation> &queue,
                              size_t ldq_entries, size_t stq_entries, const EventSource &source,
                              InstructionAllocation &result);
// Uses the live allocation to reject a reused queue slot or stale retirement.
CheckResult merge_retirement(uint32_t hart, const ProbeInstruction &core,
                              const InstructionAllocation &allocation,
                              const std::optional<ProbeLoadRetirement> &load,
                              size_t ldq_entries, size_t stq_entries, const EventSource &source,
                              Retirement &result);

CheckResult convert_allocation(uint32_t hart, const ProbeInstruction &probe, const EventSource &source,
                                InstructionAllocation &result);
LoadAttempt convert_attempt(uint32_t hart, const ProbeIdentity &identity, uint32_t queue_index);
CheckResult convert_load(uint32_t hart, const ProbeLoad &probe, const EventSource &source, LoadObservation &result);
// Only the LSU architectural local_store output may call this conversion.
CheckResult convert_store(uint32_t hart, const ProbeStore &probe, const EventSource &source, StoreCommit &result);
CheckResult convert_single_store_publication(uint32_t hart, const ProbeStore &probe, const EventSource &source,
                                             uint64_t transaction_id, StorePublicationEvidence evidence,
                                             bool single_writer_complete, StorePublication &result);
CheckResult convert_retirement(uint32_t hart, const ProbeInstruction &probe, const EventSource &source,
                                std::optional<uint64_t> physical_load_address,
                                std::optional<uint64_t> independent_retire_data, Retirement &result);

} // namespace boom
} // namespace rvwmo
#endif
