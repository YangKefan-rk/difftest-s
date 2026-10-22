#ifndef DIFFTEST_RVWMO_LRSC_H
#define DIFFTEST_RVWMO_LRSC_H

#include "event.h"
#include <array>
#include <map>

namespace rvwmo {

// Captured before the SC's own global write, never reconstructed at retirement.
struct StoreConditionalEvidence {
  MemoryOperation operation;
  std::vector<uint64_t> remote_writes;
};

// Retirements arrive in hart program order; global writes and evidence capture
// arrive in global-rank order. Only byte frontiers and one reservation per hart
// survive: no instruction graph or unbounded store history is retained.
class LrScChecker {
public:
  CheckResult observe_store(const MemoryOperation &operation);
  CheckResult capture_sc(const MemoryOperation &operation, StoreConditionalEvidence &evidence) const;
  // Source ranks come from the final, resolved read-value witness (initial=0).
  // A same-hart forwarded source may have a rank later than the LR itself.
  CheckResult retire_lr(const MemoryOperation &operation, const std::vector<uint64_t> &source_ranks);
  // Failure consumes a reservation but requires no global-memory operation.
  // Success returns its paired LR identity for PPO rule 8.
  CheckResult retire_sc(const MemoryOperation &operation, const StoreConditionalEvidence *evidence,
                        bool success, OperationId &paired_lr);
  size_t address_count() const { return writes_.size(); }
  size_t reservation_count() const { return reservations_.size(); }

private:
  struct Reservation {
    MemoryOperation operation;
    std::vector<uint64_t> source_ranks;
  };
  struct WriterTime {
    uint32_t hart = 0;
    uint64_t rank = 0;
  };
  // The two newest distinct harts suffice when a query excludes just one hart.
  uint64_t frontier_ = 0;
  std::map<uint64_t, std::array<WriterTime, 2>> writes_;
  std::map<uint32_t, Reservation> reservations_;
};

} // namespace rvwmo
#endif
