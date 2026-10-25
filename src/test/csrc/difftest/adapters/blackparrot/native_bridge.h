#ifndef DIFFTEST_BLACKPARROT_NATIVE_BRIDGE_H
#define DIFFTEST_BLACKPARROT_NATIVE_BRIDGE_H

#include "adapter.h"
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace blackparrot {

// These are private native observations, not a replacement public event ABI.
struct NativeMemoryFact {
  rvwmo::OperationId id;
  uint32_t attempt = 0;
  uint64_t source_time = 0;
  uint32_t kind = 0;
  uint64_t address = 0;
  uint64_t aligned_data = 0;
  uint32_t mask = 0;
  uint64_t array_time = 0;
  uint64_t forwarding_time = 0;
  uint32_t forwarded_mask = 0;
  uint32_t flags = 0;
  std::array<std::optional<rvwmo::OperationId>, 8> forwarded_writers;
};

struct NativeRetirementFact {
  rvwmo::OperationId id;
  uint32_t attempt = 0;
  uint64_t source_time = 0;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint32_t instruction_bytes = 0;
  uint32_t rd = 0;
  bool write_enable = false;
  bool fp = false;
  uint64_t write_data = 0;
};

struct NativeTrapFact {
  rvwmo::OperationId id;
  uint32_t attempt = 0;
  uint64_t source_time = 0;
  uint64_t pc = 0;
  uint64_t cause = 0;
  bool interrupt = false;
  uint64_t tval = 0;
  uint64_t target_pc = 0;
  uint32_t privilege = 0;
  uint32_t target_privilege = 0;
};

struct NativeForwardFact {
  rvwmo::OperationId reader;
  uint32_t attempt = 0;
  uint32_t byte_index = 0;
  rvwmo::OperationId writer_candidate;
  uint32_t resolved_writer_attempt = 0;
  uint64_t source_time = 0;
};

struct NativeCancellationFact {
  rvwmo::OperationId id;
  uint32_t attempt = 0;
  uint64_t source_time = 0;
  uint32_t reason = 0;
};

struct NativeSummary {
  uint64_t allocations = 0;
  uint64_t retries = 0;
  uint64_t retirements = 0;
  uint64_t memory_records = 0;
  uint64_t traps = 0;
  uint64_t cancellations = 0;
  uint64_t converted_events = 0;
  bool sink_installed = false;
  bool malformed_transport = false;
  // Capture success and an installed sink do not constitute a semantic verdict.
  bool incomplete = true;
  std::vector<std::string> gaps;
};

struct NativeCapture {
  ConvertedOutput converted;
  std::vector<NativeMemoryFact> memory_facts;
  std::vector<NativeRetirementFact> retirement_facts;
  std::vector<NativeTrapFact> trap_facts;
  std::vector<NativeCancellationFact> cancellation_facts;
  std::vector<NativeForwardFact> forwarding_facts;
  NativeSummary summary;
};

using NativeSink = std::function<ConversionResult(const NativeCapture &)>;

// Install before probe initialization. The coordinator owns the producer roster,
// ObservationStream, source-prefix proof, REF, rank resolver and final verdict.
ConversionResult install_native_sink(Configuration configuration, NativeSink sink);
// An explicit fresh session is allowed only before initialization or after finish.
ConversionResult reset_native_session();
const NativeCapture &last_native_capture();

} // namespace blackparrot

extern "C" {
int bp_difftest_s_probe_init(uint32_t hart, uint32_t hart_count);
int bp_difftest_s_allocate(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                          uint64_t source_time, uint64_t pc, uint32_t raw_instruction,
                          uint32_t instruction_bytes, uint32_t expanded_instruction);
int bp_difftest_s_retire(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                        uint64_t source_time, uint64_t pc, uint32_t raw_instruction,
                        uint32_t instruction_bytes, uint32_t rd, uint32_t write_enable,
                        uint32_t fp, uint64_t write_data);
int bp_difftest_s_trap(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                      uint64_t source_time, uint64_t pc, uint64_t cause, uint32_t is_interrupt,
                      uint64_t tval, uint64_t target_pc, uint32_t privilege, uint32_t target_privilege);
int bp_difftest_s_cancel(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                        uint64_t source_time, uint32_t reason);
int bp_difftest_s_heartbeat(uint32_t hart, uint64_t source_time, uint32_t pending_retirements);
int bp_difftest_s_memory(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                        uint64_t source_time, uint32_t kind, uint64_t address,
                        uint64_t aligned_data, uint32_t mask, uint64_t array_time,
                        uint64_t forwarding_time, uint32_t forwarded_mask, uint32_t flags);
int bp_difftest_s_forward_byte(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                              uint32_t byte_index, uint64_t writer_epoch, uint64_t writer_uid);
int bp_difftest_s_memory_idle(uint32_t hart, uint64_t source_time, uint32_t physically_idle);
int bp_difftest_s_finish();
}

#endif
