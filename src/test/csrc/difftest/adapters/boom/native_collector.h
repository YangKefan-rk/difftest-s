#ifndef DIFFTEST_ADAPTERS_BOOM_NATIVE_COLLECTOR_H
#define DIFFTEST_ADAPTERS_BOOM_NATIVE_COLLECTOR_H

#include "retirement_snapshot.h"
#include "word_bytes.h"
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace rvwmo {
namespace boom {

// Typed BOOM input after lossless transport decoding; not a public wire ABI.
// Emit exactly one complete frame per active source edge, including empty ones.
struct NativeAttempt {
  ProbeIdentity identity;
  uint32_t queue_index = 0;
};
struct NativeLoad {
  ProbeLoad probe;
  SourcePosition sampled_at;
};
struct NativePublication {
  ProbeStore probe;
  EventSource source;
  uint64_t transaction_id = 0;
  StorePublicationEvidence evidence = StorePublicationEvidence::Unavailable;
  bool single_writer_complete = false;
};
struct NativeSquash {
  ProbeIdentity identity;
  uint32_t rob_index = 0;
};
struct NativeCsrPost {
  ProbeIdentity identity;
  uint64_t source_cycle = 0, pc = 0, value = 0;
  uint16_t address = 0;
};
struct NativeFrame {
  uint32_t hart = 0;
  uint64_t epoch = 0;
  uint64_t cycle = 0;
  std::vector<ProbeInstruction> allocations;
  std::vector<ProbeQueueAllocation> queue_allocations;
  std::vector<NativeAttempt> begins;
  // Union of cancel/nack facts. Repeated facts from the two probe outputs are
  // normalized once; an already-cancelled attempt in another frame is invalid.
  std::vector<NativeAttempt> cancellations;
  // Only LSU.complete, not duplicate cache.load or LSU.forward descriptions.
  std::vector<NativeLoad> completions;
  std::vector<ProbeStore> local_stores;
  std::vector<ProbeInstruction> retirements;
  bool csr_probe_available = false;
  std::optional<NativeCsrPost> csr_post;
  bool csr_write_probe_available = false;
  std::optional<NativeCsrPost> csr_write_post;
  std::vector<ProbeLoadRetirement> retired_loads;
  std::vector<NativeAttempt> store_releases;
  std::vector<NativeSquash> squashes;
  std::vector<NativePublication> publications;
  bool trap = false;
  bool queues_empty = false;
  bool cache_idle = false;
  // Optional typed ingress for a producer that proves a complete coalesced
  // cache effect. Current BOOM Scala/native decoders leave this empty.
  std::vector<MergedStorePublication> merged_publications;
};
struct NativeCollectorConfiguration {
  uint32_t hart = 0;
  uint64_t epoch = 0;
  uint64_t initial_cycle = 0;
  AdapterLimits limits;
  size_t staged_events = 65536;
  // Zero size preserves existing scalar-only fixtures; production entrants
  // must supply the bounds of their independently initialized GlobalMem.
  uint64_t checked_ram_base = 0;
  uint64_t checked_ram_size = 0;
  // Enables explicit device-store exclusion only for the opted-in DUT profile.
  bool skip_device_stores = false;
  bool check_csr_post = false;
};
struct CollectedObservations {
  EventBatch batch;
  std::vector<ArchitecturalRetirement> retirements;
};
struct CaptureResult {
  CheckResult check;
  bool accepted = false;
};

// Owns one hart's private lifecycle, while the common session owns REF, fabric
// producer registration, cross-hart ordering and the final verdict. Source-time
// staging releases delayed samples before closing their producer prefix.
class NativeCollector {
public:
  explicit NativeCollector(NativeCollectorConfiguration configuration);
  CaptureResult capture(const NativeFrame &frame);
  CheckResult take_ready(CollectedObservations &output);
  CheckResult audit_reference_store(const ReferenceStoreAudit &reference);
  CheckResult completion() const;

private:
  using AttemptKey = std::pair<OperationId, uint32_t>;
  NativeCollectorConfiguration configuration_;
  BoomEventAdapter adapter_;
  std::map<OperationId, InstructionAllocation> allocations_;
  std::set<OperationId> skipped_device_stores_;
  struct PendingCsr {
    uint64_t pc = 0, retirement_cycle = 0;
    uint16_t address = 0;
    std::optional<uint64_t> after;
    uint64_t rob_generation = 0;
  };
  std::map<OperationId, PendingCsr> pending_csr_;
  std::map<OperationId, NativeCsrPost> pending_counter_writes_;
  std::map<AttemptKey, uint64_t> unresolved_samples_;
  std::vector<RuntimeEvent> staged_events_;
  std::vector<CapturedRetirement> staged_retirements_;
  std::optional<uint64_t> captured_cycle_;
  std::optional<uint64_t> closed_cycle_;
  uint64_t capture_sequence_ = 0;
  uint64_t emitted_sequence_ = 0;
  bool queues_empty_ = false;
  bool cache_idle_ = false;
  CheckResult failure_;

  EventSource capture_source(uint64_t cycle);
  CheckResult capture_frame(const NativeFrame &frame);
  CheckResult capture_allocations(const NativeFrame &frame);
  CheckResult capture_counter_write(const NativeFrame &frame);
  CheckResult capture_attempts(const NativeFrame &frame);
  CheckResult capture_cancellation(const NativeAttempt &cancel, uint64_t cycle);
  CheckResult capture_retirements(const NativeFrame &frame);
  CheckResult capture_terminations(const NativeFrame &frame);
  CheckResult collect_adapter_output();
  CheckResult validate_attempt(const NativeAttempt &attempt) const;
  CheckResult require_checked_ram(uint64_t address, size_t bytes) const;
  OperationId id(const ProbeIdentity &identity) const;
  CheckResult remember_failure(CheckResult result);
};

} // namespace boom
} // namespace rvwmo
#endif
