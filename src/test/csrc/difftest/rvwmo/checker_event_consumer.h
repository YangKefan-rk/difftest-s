#ifndef DIFFTEST_RVWMO_CHECKER_EVENT_CONSUMER_H
#define DIFFTEST_RVWMO_CHECKER_EVENT_CONSUMER_H

#include "checker.h"
#include "dependency.h"
#include "event.h"
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <utility>

namespace rvwmo {

// Applies closed generic events to the existing memory/PPO checker. Passing an
// event means it was accepted by this consumer, not that the RVWMO check passed.
// The architectural REF step and source-order proof remain caller-owned.
class CheckerEventConsumer {
public:
  using RankResolver = std::function<std::optional<ObservationTime>(const RuntimeEvent &)>;

  CheckerEventConsumer(Memory::ReadGlobal read_global, Memory::WriteGlobal write_global, RankResolver rank_resolver,
                      size_t max_live_instructions = 65536, size_t max_pending_retirements = 65536);

  // Only call after the transport has closed the event's source prefix. Pass
  // means accepted by the consumer, not a verdict. Pending means not consumed
  // and the caller must retain/retry the event. A retired instruction may be
  // accepted into Checker's queue; poll() reports its later semantic progress.
  // The resolver must provide a strictly ordered, hardware-justified GMO rank.
  CheckResult consume_closed(const RuntimeEvent &event);
  CheckResult candidate_load(const OperationId &id, uint32_t attempt, std::vector<uint8_t> &bytes);
  // An audit that precedes LocalStore returns Pending and must be retried.
  CheckResult audit_store(const OperationId &id, uint64_t address, const std::vector<uint8_t> &bytes,
                          const std::vector<uint8_t> &mask);
  CheckResult poll();
  CheckResult finalize();

private:
  using LoadKey = std::pair<OperationId, uint32_t>;
  struct Allocation {
    uint64_t pc = 0;
    uint32_t instruction = 0;
    uint8_t length = 0;
  };
  struct StoreRecord {
    MemoryOperation operation;
    MemoryStore store;
    bool audited = false;
    bool published = false;
    bool retired = false;
  };
  struct LoadRecord {
    MemoryOperation operation;
    std::vector<uint8_t> actual_bytes;
  };

  Memory memory_;
  Checker checker_;
  RankResolver rank_resolver_;
  size_t max_live_instructions_;
  size_t max_pending_retirements_;
  std::map<OperationId, Allocation> allocations_;
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> hart_epoch_and_uid_;
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> last_retired_;
  std::map<OperationId, StoreRecord> stores_;
  std::map<LoadKey, LoadRecord> loads_;
  std::set<LoadKey> cancelled_loads_;
  std::optional<uint64_t> last_memory_rank_;
  CheckResult failure_;

  static OperationId instruction_id(const OperationId &operation);
  CheckResult require_rank(const RuntimeEvent &event, ObservationTime &time) const;
  CheckResult consume_allocate(const InstructionAllocateEvent &event);
  CheckResult consume_local_store(const LocalStoreEvent &event);
  CheckResult consume_load_sample(const RuntimeEvent &event, const LoadSampleEvent &sample);
  CheckResult consume_store_publish(const RuntimeEvent &event, const StorePublishEvent &publish);
  CheckResult consume_cancel(const InstructionCancelAttemptEvent &event);
  CheckResult consume_retire(const InstructionRetireEvent &event);
  void collect_store_metadata();
  CheckResult remember_failure(CheckResult result);
};

} // namespace rvwmo
#endif
