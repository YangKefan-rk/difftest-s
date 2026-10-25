#ifndef DIFFTEST_RVWMO_SESSION_H
#define DIFFTEST_RVWMO_SESSION_H

#include "checker_event_consumer.h"
#include "order.h"
#include "stream.h"
#include <deque>
#include <map>
#include <optional>
#include <vector>

namespace rvwmo {

struct SessionSubmitResult {
  StreamResult transport;
  CheckResult check;
  size_t pending_events = 0;
  bool accepted = false;
};

struct ReferenceLoadValue {
  OperationId id;
  uint32_t attempt = 0;
  std::vector<uint8_t> expected_bytes;
};

enum class ArchitecturalDestination : uint8_t { None, Integer, Unsupported };

struct ArchitecturalRetirement {
  OperationId id;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  ArchitecturalDestination destination = ArchitecturalDestination::None;
  uint8_t destination_register = 0;
  uint64_t destination_value = 0;
};

struct ReferenceIntegerWrite {
  uint8_t destination_register = 0;
  uint64_t value = 0;
};

struct ReferenceStoreValue {
  OperationId id;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
};

struct ReferenceStepResult {
  CheckResult check;
  std::vector<ReferenceStoreValue> stores;
  std::optional<ReferenceIntegerWrite> integer_write;
  uint64_t reference_pc = 0;
  uint32_t reference_instruction = 0;
  bool took_trap = false;
};

// Joins transport closure, source-order ranks, scalar PPO and REF results. The
// host steps the per-hart REF; this session checks PC/raw/GPR results and audits
// REF-derived stores against provisional LocalStore events.
class ObservationSession {
public:
  using ReferenceStepper =
      std::function<ReferenceStepResult(const InstructionRetireEvent &, const ArchitecturalRetirement &,
                                        const std::vector<ReferenceLoadValue> &)>;

  ObservationSession(StreamContract contract, std::vector<ProducerCapability> producers,
                    Memory::ReadGlobal read_global, Memory::WriteGlobal write_global, ReferenceStepper reference_stepper,
                    size_t max_live_instructions = 65536, size_t max_pending_retirements = 65536);

  SessionSubmitResult submit(const EventBatch &batch,
                             const std::vector<ArchitecturalRetirement> &retirements = {});
  CheckResult poll();
  CheckResult finalize(uint64_t completed_cycle);
  size_t pending_events() const { return pending_events_.size(); }
  bool finalized() const { return finalized_; }

private:
  struct PendingEvent {
    RuntimeEvent event;
  };
  struct ReferenceRecord {
    std::vector<ReferenceStoreValue> stores;
    size_t audited_stores = 0;
  };

  size_t max_pending_events_;
  ObservationStream stream_;
  CheckerEventConsumer consumer_;
  ReferenceStepper reference_stepper_;
  std::deque<PendingEvent> pending_events_;
  std::map<OperationId, ArchitecturalRetirement> architectural_retirements_;
  std::map<OperationId, ReferenceRecord> reference_records_;
  std::optional<std::pair<uint32_t, uint64_t>> current_rank_event_;
  ObservationTime current_rank_;
  uint64_t next_rank_ = 1;
  bool finalized_ = false;
  CheckResult failure_;

  static bool is_memory_event(const RuntimeEvent &event);
  std::optional<ObservationTime> resolve_current_rank(const RuntimeEvent &event) const;
  CheckResult collect_closed_events();
  CheckResult consume_pending_events();
  CheckResult consume_retirement(const RuntimeEvent &event, const InstructionRetireEvent &retirement);
  CheckResult step_reference(const InstructionRetireEvent &retirement, const ArchitecturalRetirement &snapshot);
  CheckResult remember_failure(CheckResult result);
};

} // namespace rvwmo

#endif
