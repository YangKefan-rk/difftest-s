#ifndef DIFFTEST_BLACKPARROT_NATIVE_BRIDGE_H
#define DIFFTEST_BLACKPARROT_NATIVE_BRIDGE_H

#include "adapter.h"
#include "../../rvwmo/session.h"
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
  // 1: WBUF acceptance, 2: physical drain, 3: load, 4: accepted store-miss payload.
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

struct NativeCoherenceFact {
  rvwmo::OperationId id;
  uint32_t attempt = 0;
  uint64_t source_time = 0;
  uint64_t address = 0;
  uint32_t cache_set = 0;
  uint32_t cache_way = 0;
  uint32_t coherence_state = 0;
  uint64_t grant_time = 0;
  uint32_t proof_flags = 0;
  uint32_t bank_select = 0;
  uint32_t physical_sram_index = 0;
  // Admission names the target location; drain proves the actual SRAM write.
  bool admission = false;
};

// Evidence is emitted only by the native terminal-WFI protocol after issue is
// stopped, retained speculative identities are explicitly squashed, and the
// synchronous source monitors have delivered their complete final prefix.
struct NativeHartCompletion {
  uint32_t hart = 0;
  uint64_t source_cycle = 0;
  uint64_t terminal_uid = 0;
};

struct NativeCompletionEvidence {
  std::optional<uint64_t> completed_cycle;
  bool all_harts_completed = false;
  bool observations_drained = false;
  // The checked scalar memory effects and their source records are complete.
  // This does not require dirty cache lines to reach DRAM or every network FIFO
  // to be empty; maintenance tails cannot create another included instruction.
  bool memory_drained = false;
  PendingState pending;
  std::vector<NativeHartCompletion> harts;
};

struct NativeVerification {
  rvwmo::CheckResult check{rvwmo::CheckStatus::Incomplete, 0, "no native semantic verifier installed"};
  bool finalized = false;
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
  uint64_t online_prefixes = 0;
  size_t live_instructions = 0;
  size_t peak_live_instructions = 0;
  std::vector<std::string> gaps;
  std::optional<NativeVerification> verification;
};

struct NativeCapture {
  ConvertedOutput converted;
  std::vector<NativeMemoryFact> memory_facts;
  std::vector<NativeRetirementFact> retirement_facts;
  std::vector<NativeTrapFact> trap_facts;
  std::vector<NativeCancellationFact> cancellation_facts;
  std::vector<NativeForwardFact> forwarding_facts;
  NativeSummary summary;
  std::vector<NativeCoherenceFact> coherence_facts;
  NativeCompletionEvidence completion;
};

using NativeVerifier = std::function<NativeVerification(const NativeCapture &)>;

using NativePrefixConsumer = std::function<rvwmo::SessionSubmitResult(const ConvertedOutput &)>;
using NativeSink = std::function<ConversionResult(const NativeCapture &)>;
// The callback receives the first transport rejection. It must remain alive
// with any objects it borrows until the native session is reset or destroyed.
using NativeFailureObserver = std::function<void(const rvwmo::CheckResult &)>;

// Install before probe initialization. The coordinator owns the producer roster,
// ObservationStream, source-prefix proof, REF, rank resolver and final verdict.
ConversionResult install_native_sink(Configuration configuration, NativeSink sink,
                                     NativeFailureObserver failure_observer = {});
// A verifier reports the public session result separately from transport status.
ConversionResult install_native_verifier(Configuration configuration, NativeVerifier verifier,
                                         NativeFailureObserver failure_observer = {});
// Private online embedding: callback delivery barriers only trigger progress.
// The bridge derives a source-safe frontier from unresolved instruction facts.
ConversionResult install_native_online_verifier(Configuration configuration, NativePrefixConsumer consume,
    NativeVerifier finalize, NativeFailureObserver failure_observer = {});
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
int bp_difftest_s_coherent_drain(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                 uint64_t source_time, uint64_t address, uint32_t cache_set,
                                 uint32_t cache_way, uint32_t state, uint64_t grant_time, uint32_t proof_flags,
                                 uint32_t bank_select, uint32_t physical_sram_index);
int bp_difftest_s_coherent_accept(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                  uint64_t source_time, uint64_t address, uint32_t cache_set,
                                  uint32_t cache_way, uint32_t state, uint64_t grant_time, uint32_t proof_flags,
                                  uint32_t bank_select, uint32_t target_sram_index);
int bp_difftest_s_terminal_state(uint32_t hart, uint64_t source_time, uint64_t terminal_uid,
                                uint32_t stopped, uint32_t pending_writebacks);
int bp_difftest_s_can_end();
int bp_difftest_s_close_hart(uint32_t hart, uint64_t source_time, uint64_t terminal_uid);
int bp_difftest_s_close_prefix(uint64_t completed_cycle);
int bp_difftest_s_advance(uint64_t delivered_through_tick);
int bp_difftest_s_finish();
}

#endif
