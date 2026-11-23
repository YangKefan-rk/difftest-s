#ifndef DIFFTEST_RVWMO_FEEDBACK_OBSERVER_H
#define DIFFTEST_RVWMO_FEEDBACK_OBSERVER_H

#include "event.h"
#include <cstddef>
#include <vector>

namespace rvwmo {

// Read-only, provisional source facts. These records neither certify a final
// checker verdict nor identify a physical cache-data source for a load.
struct FeedbackRetirement {
  RetiredInstruction instruction;
  uint32_t producer_id = 0;
  SourcePosition source;
};

struct FeedbackMemoryEffect {
  MemoryOperation operation;
  uint64_t pc = 0;
  uint32_t producer_id = 0;
  SourcePosition source;
  uint32_t retirement_producer_id = 0;
  SourcePosition retirement_source;
  ObservationTime order;
  // A store member retains its complete logical footprint above. The physical
  // group below may overwrite bytes of older members. Member rank offsets are
  // the checker's program-order witness, not separate physical write times.
  uint64_t publication_transaction = 0;
  uint64_t publication_generation = 0;
  bool coalesced_program_order = false;
  uint64_t publication_address = 0;
  std::vector<uint8_t> publication_byte_mask;
  std::vector<OperationId> publication_byte_writers;
};

// Bounded optional evidence collection. Attach observe() to the ordered tap;
// publish projections only after the owning host's independent final verdict.
// An exception withholds feedback and must not change that checker verdict.
class FeedbackEvidenceCollector {
public:
  explicit FeedbackEvidenceCollector(size_t max_records = 100000);
  void observe(const RuntimeEvent &event, const ObservationTime &order);
  const std::vector<FeedbackRetirement> &retirements() const { return retirements_; }
  std::vector<FeedbackMemoryEffect> scalar_memory_effects() const;

private:
  struct MemoryObservation {
    RuntimeEvent event;
    ObservationTime order;
  };
  size_t max_records_;
  std::vector<FeedbackRetirement> retirements_;
  std::vector<MemoryObservation> memory_;
};

} // namespace rvwmo
#endif
