#ifndef DIFFTEST_RVWMO_CHECKER_H
#define DIFFTEST_RVWMO_CHECKER_H

#include "memory.h"
#include "lrsc.h"
#include "ppo.h"
#include <deque>
#include <set>

namespace rvwmo {

enum class StoreVerification {
  Provisional,
  Verified
};

struct RetiredLoad {
  OperationId id;
  std::vector<uint8_t> bytes;
};

struct CheckMemoryStatistics {
  uint64_t verified_load_operations = 0;
  uint64_t verified_store_operations = 0;
  // One per verified load with any enabled byte from another hart's canonical
  // dynamic writer. Initialization and caller-provided provenance do not count.
  uint64_t cross_hart_reads = 0;
  uint64_t store_audits = 0;
};

// Event transport and REF execution remain outside this class. Provisional
// store bytes may advance candidate memory state, but cannot earn a final pass
// until independently computed REF stores have verified every provisional write.
class Checker {
public:
  explicit Checker(Memory &memory, size_t max_statistics_harts = 4096);
  // Allocates a collision-free MemoryWriter for full epoch/UID/subaccess identity.
  CheckResult memory_writer(const OperationId &operation, MemoryWriter &writer);
  CheckResult record_store(const MemoryStore &store, const MemoryOperation &operation,
                           StoreVerification verification = StoreVerification::Verified);
  CheckResult verify_store(const OperationId &operation, const MemoryStore &reference);
  // Returns canonical expected bytes only after their source stores pass REF
  // verification. This does not consume retirement or certify PPO/actual values.
  CheckResult get_expected_load(const OperationId &operation, uint32_t attempt, std::vector<uint8_t> &bytes);
  // Provisional REF input may contain unaudited store bytes and assume unresolved
  // local stores preserve same-byte program order. It only advances REF execution;
  // source verification, canonical read-value and PPO checks remain mandatory.
  CheckResult get_reference_candidate_load(const OperationId &operation, uint32_t attempt, std::vector<uint8_t> &bytes);
  CheckResult observe_global(uint64_t address, const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
                             const std::vector<MemoryWriter> &writers, const std::vector<MemoryWriter> &completed,
                             ObservationTime time);
  CheckResult observe_global(uint64_t address, const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
                             const std::vector<MemoryWriter> &writers, const std::vector<MemoryWriter> &completed,
                             const std::vector<ObservationTime> &completion_times);
  // ModeledWitness derives read_sources internally from the resolved snapshot;
  // caller-provided identities are ignored in that case. Actual load bytes are
  // still compared independently after PPO succeeds at architectural retirement.
  CheckResult observe_load(const MemoryOperation &operation, uint64_t po,
                           const std::vector<std::optional<MemoryWriter>> &forwarded,
                           bool source_prefix_closed = false);
  CheckResult cancel_load(const OperationId &operation, uint32_t attempt);
  // Caller must prove that caches/observers cannot reference this writer again.
  // Local pending, snapshot and queued-retirement references are checked here.
  CheckResult release_store(const OperationId &operation);
  CheckResult collect_garbage();
  std::vector<OperationId> take_released_stores();
  size_t tracked_stores() const {
    return stores_.size();
  }
  // Retired ordinary stores may retain only their publication/PPO obligation;
  // unrelated loads and their snapshots can complete in the meantime.
  // Enqueues retirement without blocking event acquisition. Pending is not an
  // error: poll after later global-completion or source-store events arrive.
  CheckResult retire(const RetiredInstruction &instruction, const std::vector<RetiredLoad> &loads);
  CheckResult poll();
  CheckResult finalize();
  size_t pending_retirements() const;
  size_t pending_loads() const {
    return loads_.size();
  }
  static OperationId initialization_writer(uint64_t byte_address);
  const std::map<uint32_t, CheckMemoryStatistics> &memory_statistics() const { return memory_statistics_; }

private:
  struct LoadSample {
    MemoryOperation operation;
    MemorySnapshot snapshot;
  };
  struct Retirement {
    RetiredInstruction instruction;
    std::vector<RetiredLoad> loads;
  };
  using LoadKey = std::pair<OperationId, uint32_t>;
  Memory &memory_;
  size_t max_statistics_harts_;
  std::map<uint32_t, CheckMemoryStatistics> memory_statistics_;
  PpoChecker ppo_;
  LrScChecker lrsc_;
  std::map<OperationId, StoreConditionalEvidence> sc_evidence_;
  std::map<uint32_t, OperationId> reserved_lr_;
  std::map<MemoryWriter, OperationId> writers_;
  std::map<OperationId, MemoryWriter> operation_writers_;
  std::map<uint32_t, uint64_t> next_writer_uid_;
  std::set<uint32_t> exhausted_writer_harts_;
  std::map<OperationId, MemoryOperation> stores_;
  std::map<OperationId, MemoryStore> unverified_stores_;
  std::set<OperationId> checked_stores_;
  std::set<OperationId> completed_stores_;
  std::set<OperationId> retired_pending_publication_;
  std::set<MemoryWriter> reclaim_candidates_;
  std::vector<OperationId> released_stores_;
  std::map<LoadKey, LoadSample> loads_;
  std::map<uint32_t, std::deque<Retirement>> retirements_;
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> last_enqueued_;
  CheckResult failure_;
  CheckResult drain(uint32_t hart);
  CheckResult prepare(Retirement &retirement);
  CheckResult require_verified_sources(const MemorySnapshot &snapshot) const;
  CheckResult ensure_statistics_hart(uint32_t hart);
  CheckResult verified_memory_delta(const RetiredInstruction &instruction, CheckMemoryStatistics &delta) const;
  CheckResult remember_failure(CheckResult result);
};

} // namespace rvwmo
#endif
