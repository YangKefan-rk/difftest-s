#ifndef DIFFTEST_RVWMO_RUNTIME_H
#define DIFFTEST_RVWMO_RUNTIME_H

#include "checker.h"
#include "dut.h"
#include "reference.h"
#include "refproxy.h"
#include <array>
#include <functional>
#include <memory>
#include <set>
#include <tuple>

namespace rvwmo {

// Adapter for the generated DiffTest event ABI. The rule and memory engines do
// not depend on this adapter or on any particular RTL implementation.
class Runtime {
public:
  explicit Runtime(unsigned harts);
  CheckResult capture(const std::vector<DiffTestState *> &states);
  CheckResult before_commit(unsigned hart, unsigned port, DiffTestState &state, RefProxy &reference);
  CheckResult after_commit(unsigned hart, RefProxy &reference);
  CheckResult note_reference_step(unsigned hart);
  CheckResult note_arch_compare(unsigned hart, uint64_t retired_instructions);
  bool print_final_statistics();
  CheckResult verify_store(unsigned hart, uint64_t store_uid, uint64_t address, uint64_t data, uint8_t mask);
  CheckResult note_done(unsigned hart, int code);
  CheckResult finish();
  bool read_reference_memory(unsigned hart, uint64_t address, size_t size, uint8_t *bytes) const;
  bool covered() const {
    return bool(coverage_);
  }
  bool done(unsigned hart) const {
    return harts_.at(hart).done;
  }
  bool all_done() const;
  void exclude(const std::string &reason) {
    unsupported(reason);
  }
  const CheckResult &coverage() const {
    return coverage_;
  }

private:
  struct Load {
    MemoryOperation operation;
    std::vector<uint8_t> actual;
    bool observed = false;
    bool cancelled = false;
    bool retired = false;
    std::string coverage_reason;
  };
  struct Store {
    OperationId id;
    MemoryStore memory;
    MemoryOperation operation;
    std::vector<uint8_t> audited;
    bool recorded = false;
    bool verified = false;
    bool excluded_io = false;
  };
  struct Group {
    unsigned hart = 0;
    uint64_t id = 0;
    uint64_t cycle = 0;
    uint64_t address = 0;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    std::vector<uint64_t> writers;
    std::set<uint64_t> members;
    bool queued = false;
  };
  enum class AtomicKind { Rmw, LoadReserved, StoreConditional };
  struct Atomic {
    AtomicKind kind = AtomicKind::Rmw;
    OperationId id;
    uint32_t attempt = 0;
    uint64_t address = 0;
    uint64_t old_data = 0;
    uint64_t cache_response = 0;
    bool success = false;
    uint64_t new_data = 0;
    uint64_t response = 0;
    uint8_t mask = 0;
    bool request_seen = false;
    bool awaiting_retry = false;
    bool read_seen = false;
    bool write_seen = false;
    bool response_seen = false;
    bool finished = false;
    bool observed = false;
    bool verified = false;
    std::string coverage_reason;
    MemoryStore store;
    std::shared_ptr<Load> load;
  };
  struct WriteObservation {
    unsigned hart;
    uint64_t address;
    std::vector<uint8_t> mask;
  };
  struct Active {
    RetiredInstruction instruction;
    std::shared_ptr<Load> load;
    bool reader = false;
    std::shared_ptr<Atomic> atomic;
    unsigned instruction_count = 1;
    bool is_rvc = false;
    std::vector<std::pair<uint64_t, uint32_t>> reference_instructions;
  };
  struct Hart {
    uint64_t next_uid = 1;
    uint64_t ref_instructions = 0;
    uint64_t frame_ref_steps = 0;
    uint64_t arch_compares = 0;
    uint64_t last_retired_uid = 0;
    uint64_t last_store_uid = 0;
    std::map<uint16_t, OperationId> allocations;
    std::map<uint64_t, Store> stores;
    std::map<OperationId, std::vector<uint64_t>> instruction_stores;
    std::map<OperationId, std::shared_ptr<Load>> loads;
    std::map<OperationId, uint32_t> attempts;
    std::map<OperationId, std::string> unsupported_allocations;
    std::shared_ptr<Atomic> atomic_inflight;
    std::map<OperationId, std::shared_ptr<Atomic>> atomics;
    ReferenceRead reader;
    std::optional<Active> active;
    bool done = false;
    uint64_t end_uid = 0;
    int exit_code = 0;
  };
  // Queue phases are separate from AtomicMemoryEvent lifecycle phases:
  // 1 data-read sample, 2 Sbuffer write, 3 indivisible AMO write point.
  // Overlapping cross-hart writes still require qualified hardware arbitration.
  using EventKey = std::tuple<uint64_t, unsigned, uint64_t, unsigned>;
  std::vector<Hart> harts_;
  std::map<uint64_t, std::vector<std::weak_ptr<Atomic>>> reserved_reads_by_cycle_;
  std::map<uint64_t, std::vector<WriteObservation>> writes_by_cycle_;
  Memory memory_;
  Checker checker_;
  std::map<std::pair<unsigned, uint64_t>, Group> groups_;
  std::map<OperationId, uint64_t> store_uids_;
  std::map<EventKey, std::function<CheckResult(ObservationTime)>> events_;
  std::map<uint64_t, std::vector<std::weak_ptr<Load>>> loads_by_cycle_;
  std::set<uint64_t> touched_cycles_;
  std::optional<uint64_t> transport_watermark_;
  uint64_t next_rank_ = 1;
  uint64_t ranks_consumed_ = 1;
  uint64_t latest_cycle_ = 0;
  uint64_t last_effect_cycle_ = 0;
  uint64_t capture_tick_ = 0;
  uint64_t last_event_tick_ = 0;
  uint64_t all_done_tick_ = 0;
  CheckResult coverage_;
  CheckResult failure_;
  bool finalized_ = false;
  bool statistics_emitted_ = false;
  std::string ordering_pending_;
  CheckResult unsupported(const std::string &reason);
  CheckResult advance(uint64_t watermark);
  CheckResult observe(const std::shared_ptr<Load> &load, ObservationTime time);
  CheckResult complete_group(Group &group, ObservationTime time);
  CheckResult observe_atomic(unsigned hart, const std::shared_ptr<Atomic> &atomic, ObservationTime time);
  CheckResult capture_atomics(unsigned hart, DiffTestState &state);
  void observe_write(uint64_t cycle, unsigned hart, uint64_t address, const std::vector<uint8_t> &mask);
  CheckResult allocate(unsigned hart, uint16_t rob);
  void collect_released_stores();
  void timestamp(uint64_t cycle);
  static void observe_reference_instruction(void *context, uint64_t pc, uint32_t instruction);
};

} // namespace rvwmo
#endif
