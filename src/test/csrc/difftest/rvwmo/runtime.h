#ifndef DIFFTEST_RVWMO_RUNTIME_H
#define DIFFTEST_RVWMO_RUNTIME_H

#include "checker.h"
#include "dut.h"
#include "reference.h"
#include "refproxy.h"
#include <array>
#include <deque>
#include <functional>
#include <memory>
#include <set>
#include <tuple>
#include <variant>

namespace rvwmo {

class UcBridge;
struct UcBoundRequest;
struct UcJoinedEffect;

// Opt-in host prototype. Raw Uncache A/grant handshakes have no qualification.
enum class UcRamProfileKind { Disabled, LinkNanExtraMemScalar, LinkNanExtraMemNative };
enum class UcAccessKind { Load, Store };
enum class UcObservationKind { UnqualifiedGrant, ReadSample, WriteEffect };

struct UcRamSources {
  static constexpr unsigned absent = 256;
  std::set<unsigned> request;
  std::set<unsigned> read_sample;
  std::set<unsigned> write_effect;
};

struct UcRamProfile {
  UcRamProfileKind kind = UcRamProfileKind::Disabled;
  // Whole zero pages in the independent extraMem aperture. Existing backing
  // is rejected before any page is seeded; DUT return bytes never seed RAM.
  std::vector<uint64_t> zero_pages;
  std::vector<UcRamSources> sources;
  std::shared_ptr<UcBridge> native_bridge;
};

CheckResult native_uc_profile_from_environment(UcRamProfile &profile);

struct UcSourcePosition {
  unsigned source_id = UcRamSources::absent;
  uint64_t sequence = 0;
  uint64_t cycle = 0;
};

struct UcRequest {
  unsigned hart = 0;
  uint64_t transaction_uid = 0;
  uint16_t robidx = 0;
  uint64_t allocation_uid = 0; // Exact request generation, never inferred at completion.
  UcAccessKind kind = UcAccessKind::Load;
  uint64_t store_uid = 0;
  uint64_t address = 0; // Aligned eight-byte word; mask selects scalar bytes.
  uint8_t mask = 0;
  UcSourcePosition source;
};

struct UcCompletion {
  unsigned hart = 0;
  uint64_t transaction_uid = 0;
  UcObservationKind observation = UcObservationKind::UnqualifiedGrant;
  uint64_t address = 0;
  uint8_t mask = 0;
  std::array<uint8_t, 8> bytes{};
  bool denied = false;
  bool corrupt = false;
  UcSourcePosition source;
};

// Adapter for the generated DiffTest event ABI. The rule and memory engines do
// not depend on this adapter or on any particular RTL implementation.
class Runtime {
public:
  explicit Runtime(unsigned harts, UcRamProfile uc_profile = {});
  // Submit before capture; request must name the exact allocation generation.
  // Completion uses only that saved identity, never the current ROB slot.
  // The source bridge must finish a bounded request/effect join before delivery
  // and preserve per-producer sequence and original effect time. Raw endpoint
  // callbacks from independent producers are not this joined input contract.
  CheckResult submit_uc_request(const UcRequest &request);
  CheckResult submit_uc_completion(const UcCompletion &completion);
  bool independently_execute_skipped_uc(unsigned hart) const;
  void print_native_uc_diagnostics(const char *phase) const;
  CheckResult capture(const std::vector<DiffTestState *> &states);
  CheckResult before_commit(unsigned hart, unsigned port, DiffTestState &state, RefProxy &reference);
  CheckResult execute_reference(unsigned hart, RefProxy &reference);
  CheckResult after_commit(unsigned hart, RefProxy &reference);
  CheckResult note_reference_step(unsigned hart);
  CheckResult note_arch_compare(unsigned hart, uint64_t retired_instructions);
  bool print_final_statistics();
#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_SOURCEPREFIXEVENT)
  bool print_observed_prefix_final();
  bool export_semantic_observed_prefix() const;
#endif
  CheckResult check_store_event(unsigned hart, uint64_t store_uid, uint64_t address, uint64_t data, uint8_t mask);
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
    unsigned source_id = 0;
    uint64_t source_sequence = 0;
    uint64_t source_cycle = 0;
    bool qualified_uc = false;
    std::shared_ptr<const UcJoinedEffect> external_effect;
    std::string coverage_reason;
  };
  struct StoreTrace {
    uint64_t address = 0;
    uint64_t data = 0;
    uint8_t mask = 0;
  };
  struct Store {
    OperationId id;
    MemoryStore memory;
    MemoryOperation operation;
    std::optional<StoreTrace> reference;
    bool effect_recorded = false;
    bool recorded = false;
    bool store_event_checked = false;
    bool checker_released = false;
    bool qualified_uc = false;
    std::shared_ptr<const UcJoinedEffect> external_effect;
    bool excluded_io = false;
    uint64_t excluded_io_address = 0;
    uint64_t excluded_io_cycle = 0;
    uint64_t excluded_io_mask = 0;
  };
  struct Group {
    unsigned hart = 0;
    uint64_t id = 0;
    uint64_t cycle = 0;
    unsigned source_id = 0;
    uint64_t source_sequence = 0;
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
    uint64_t source_cycle = 0;
    uint64_t read_source_cycle = 0;
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
    bool qualified_uc = false;
  };
  struct CheckedFusedRetirement {
    unsigned hart;
    uint64_t pc;
    uint32_t instruction;
    unsigned n_fused;
    bool is_rvc;
    unsigned lane;
    uint64_t source_cycle;
    unsigned source_id;
    uint64_t source_sequence;
    std::vector<std::pair<uint64_t, uint32_t>> reference_instructions;
  };
  struct Active {
    RetiredInstruction instruction;
    std::shared_ptr<Load> load;
    bool reader = false;
    bool qualified_uc = false;
    std::shared_ptr<const UcJoinedEffect> uc_store_effect;
    uint64_t store_uid = 0;
    std::optional<StoreTrace> reference_store;
    std::shared_ptr<Atomic> atomic;
    unsigned instruction_count = 1;
    bool is_rvc = false;
    std::vector<std::pair<uint64_t, uint32_t>> reference_instructions;
    std::optional<CheckedFusedRetirement> checked_fused_retirement;
    uint64_t retirement_source_cycle = 0;
    unsigned retirement_source_id = 0;
    uint64_t retirement_source_sequence = 0;
  };
  struct Hart {
    uint64_t next_uid = 1;
    uint64_t ref_instructions = 0;
    uint64_t frame_ref_steps = 0;
    uint64_t arch_compares = 0;
    uint64_t last_retired_uid = 0;
    uint64_t semantic_retirement_ordinal = 0;
    uint64_t accepted_retirement_instructions = 0;
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
  struct SemanticRetirement {
    OperationId id;
    uint64_t pc;
    uint32_t instruction;
    uint64_t source_cycle;
    unsigned source_id;
    uint64_t source_sequence;
    uint64_t program_order;
  };
  struct SemanticRetiredMemory {
    uint64_t pc;
    uint32_t instruction;
    uint64_t retirement_source_cycle;
    uint32_t attempt;
    uint64_t address;
    uint64_t byte_mask;
  };
  struct SemanticLoad {
    OperationId id;
    uint32_t attempt;
    uint64_t source_cycle;
    unsigned source_id;
    uint64_t source_sequence;
    uint64_t address;
    uint64_t byte_mask;
    std::shared_ptr<const UcJoinedEffect> external_effect;
  };
  struct SemanticGroup {
    unsigned hart;
    uint64_t transaction_id;
    uint64_t source_cycle;
    unsigned source_id;
    uint64_t source_sequence;
    uint64_t address;
    uint64_t byte_mask;
    std::vector<OperationId> members;
    // Only bytes whose final physical writer is this dynamic store are
    // externally visible in this coalesced publication.
    std::map<OperationId, uint64_t> visible_member_masks;
    std::shared_ptr<const UcJoinedEffect> external_effect;
  };
  struct ExcludedDeviceStore {
    OperationId id;
    uint64_t store_uid;
    uint64_t pc;
    uint32_t instruction;
    uint64_t address;
    uint64_t source_cycle;
    uint64_t byte_mask;
  };
  struct SemanticAtomicEffect {
    unsigned hart;
    uint64_t source_cycle;
    uint64_t address;
    uint64_t byte_mask;
  };
  struct UcTransaction {
    UcRequest request;
    OperationId allocation;
    std::shared_ptr<const UcBoundRequest> external_request;
  };
  // Queue phases are separate from AtomicMemoryEvent lifecycle phases:
  // 1 data-read sample, 2 Sbuffer write, 3 indivisible AMO write point,
  // 4 qualified UC single-store effect. Phase numbers do not certify tie order.
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
  bool observed_prefix_emitted_ = false;
  bool semantic_export_enabled_ = false;
  bool semantic_export_overflow_ = false;
  bool checked_fused_retirements_overflow_ = false;
  bool semantic_retirements_incomplete_ = false;
  std::vector<SemanticRetirement> semantic_retirements_;
  size_t checked_fused_instruction_count_ = 0;
  std::vector<CheckedFusedRetirement> checked_fused_retirements_;
  bool semantic_excluded_device_store_ = false;
  std::vector<ExcludedDeviceStore> semantic_excluded_device_stores_;
  uint64_t excluded_atomic_effect_count_ = 0;
  std::vector<SemanticAtomicEffect> semantic_atomic_effects_;
  std::vector<SemanticLoad> semantic_loads_;
  std::map<OperationId, SemanticRetiredMemory> semantic_retired_memories_;
  std::vector<SemanticGroup> semantic_groups_;
  std::set<OperationId> retired_semantic_stores_;
  std::set<OperationId> audited_semantic_stores_;
  std::string ordering_pending_;
  UcRamProfile uc_profile_;
  bool uc_memory_initialized_ = false;
  bool native_uc_startup_logged_ = false;
  uint64_t native_bound_requests_ = 0;
  uint64_t native_queued_effects_ = 0;
  std::deque<std::variant<UcRequest, UcCompletion>> uc_inputs_;
  std::map<std::pair<unsigned, uint64_t>, UcTransaction> uc_transactions_;
  std::map<std::pair<unsigned, unsigned>, uint64_t> uc_source_sequences_;
  std::set<std::pair<unsigned, uint64_t>> uc_seen_transactions_;
  CheckResult initialize_uc_profile();
  CheckResult seed_uc_zero_pages();
  CheckResult capture_native_uc(const std::vector<DiffTestState *> &states);
  CheckResult consume_native_uc_request(const UcBoundRequest &request);
  CheckResult consume_native_uc_effect(const UcJoinedEffect &effect);
  CheckResult validate_native_uc_store(const Active &active) const;
  CheckResult confirm_reference_store(Hart &hart, const Active &active);
  CheckResult record_uc_request(const UcRequest &request,
                                std::shared_ptr<const UcBoundRequest> external_request = {});
  CheckResult enqueue_uc_completion(const UcCompletion &completion,
                                    std::shared_ptr<const UcJoinedEffect> external_effect = {});
  std::optional<uint64_t> uc_effective_watermark(std::optional<uint64_t> legacy) const;
  CheckResult validate_uc_source(unsigned hart, const UcSourcePosition &source, const std::set<unsigned> &allowed);
  CheckResult capture_uc_inputs();
  CheckResult bind_uc_request(const UcRequest &request);
  CheckResult capture_uc_completion(const UcCompletion &completion);
  CheckResult publish_uc_store(const UcTransaction &transaction, const UcCompletion &completion,
                               ObservationTime time, std::shared_ptr<const UcJoinedEffect> external_effect = {});
  bool uc_word_is_declared(uint64_t address) const;
  CheckResult unsupported(const std::string &reason);
  CheckResult advance(uint64_t watermark);
  CheckResult observe(const std::shared_ptr<Load> &load, ObservationTime time);
  CheckResult complete_group(Group &group, ObservationTime time);
  CheckResult observe_atomic(unsigned hart, const std::shared_ptr<Atomic> &atomic, ObservationTime time);
  CheckResult capture_atomics(unsigned hart, DiffTestState &state);
  void observe_write(uint64_t cycle, unsigned hart, uint64_t address, const std::vector<uint8_t> &mask,
                     bool qualified_uc = false);
  CheckResult allocate(unsigned hart, uint16_t rob);
  void release_store(Hart &hart, uint64_t uid);
  void collect_released_stores();
  void record_checked_fused_retirement(Active &active);
  size_t pending_atomics() const;
  void timestamp(uint64_t cycle);
  static void observe_reference_instruction(void *context, uint64_t pc, uint32_t instruction);
};

} // namespace rvwmo
#endif
