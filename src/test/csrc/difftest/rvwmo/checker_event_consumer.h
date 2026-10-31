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
  // source_prefix_closed additionally certifies that every earlier memory
  // effect has been consumed; ordinary direct callers must leave it false.
  CheckResult consume_closed(const RuntimeEvent &event, bool source_prefix_closed = false);
  CheckResult candidate_load(const OperationId &id, uint32_t attempt, std::vector<uint8_t> &bytes);
  // An audit that precedes LocalStore returns Pending and must be retried.
  CheckResult audit_store(const OperationId &id, uint64_t address, const std::vector<uint8_t> &bytes,
                          const std::vector<uint8_t> &mask);
  CheckResult poll();
  CheckResult finalize();
  const std::map<uint32_t, CheckMemoryStatistics> &memory_statistics() const { return checker_.memory_statistics(); }

private:
  friend class ObservationSession;
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
  // One in-flight architectural atomic (AMO, LR or SC) per hart. The adapter
  // supplies the actual read/write observation points through
  // AtomicLifecycleEvent; this record only holds the semantic lifecycle.
  struct AtomicRecord {
    OperationId id;
    uint32_t attempt = 0;
    bool lr = false;
    bool sc = false;
    bool rmw = false;
    uint64_t address = 0;
    uint8_t mask = 0;
    bool request_seen = false;
    bool read_seen = false;
    bool write_seen = false;
    bool response_seen = false;
    bool awaiting_retry = false;
    bool success = false;
    bool error = false;
    uint64_t old_data = 0;
    uint64_t new_data = 0;
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
  std::map<uint32_t, AtomicRecord> atomic_inflight_;
  std::map<OperationId, AtomicRecord> atomics_;
  std::optional<uint64_t> last_memory_rank_;
  enum class RankCertificate { None, ReadOnly, IndependentEffects };
  struct GroupReceipt {
    uint64_t rank = 0;
    uint64_t cycle = 0;
    RankCertificate certificate = RankCertificate::None;
    std::set<LoadKey> members;
    std::set<uint32_t> harts;
    std::set<uint32_t> producers;
  };
  std::optional<GroupReceipt> last_group_;
  CheckResult failure_;

  static OperationId instruction_id(const OperationId &operation);
  CheckResult require_rank(const RuntimeEvent &event, ObservationTime &time,
                            RankCertificate certificate = RankCertificate::None) const;
  void remember_rank(const RuntimeEvent &event, ObservationTime time, RankCertificate certificate,
                     const OperationId &id, uint32_t attempt);
  // Only ObservationSession certifies a complete, source-closed group. Public
  // consume_closed remains strictly ranked. A certified read-prefix group may
  // contain multiple same-hart members, but never duplicate operation attempts.
  CheckResult consume_read_group_member(const RuntimeEvent &event, bool source_prefix_closed);
  CheckResult consume_independent_group_member(const RuntimeEvent &event, bool source_prefix_closed);
  CheckResult consume_allocate(const InstructionAllocateEvent &event);
  CheckResult consume_local_store(const LocalStoreEvent &event);
  CheckResult consume_load_sample(const RuntimeEvent &event, const LoadSampleEvent &sample,
                                  RankCertificate certificate = RankCertificate::None,
                                  bool source_prefix_closed = false);
  CheckResult consume_atomic(const RuntimeEvent &event, const AtomicLifecycleEvent &atomic,
                             RankCertificate certificate = RankCertificate::None);
  CheckResult consume_store_publish(const RuntimeEvent &event, const StorePublishEvent &publish,
                                    RankCertificate certificate = RankCertificate::None);
  CheckResult consume_coalesced_store_publish(const RuntimeEvent &event, const StorePublishEvent &publish);
  CheckResult audit_physical_write(const StorePublishEvent &publish);
  CheckResult consume_cancel(const InstructionCancelAttemptEvent &event);
  CheckResult consume_squash(const InstructionSquashEvent &event);
  CheckResult consume_retire(const InstructionRetireEvent &event);
  void collect_store_metadata();
  CheckResult remember_failure(CheckResult result);
};

} // namespace rvwmo
#endif
