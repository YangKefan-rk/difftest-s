#ifndef DIFFTEST_BLACKPARROT_ADAPTER_H
#define DIFFTEST_BLACKPARROT_ADAPTER_H

#include "../../rvwmo/event.h"
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace blackparrot {

// Private native-host records, never a public SV/DPI wire ABI.
struct Origin {
  uint32_t producer_id = 0;
  rvwmo::SourcePosition source;
};

struct HartChannels {
  uint32_t hart = 0;
  uint32_t instruction = 0; // Allocation and retirement.
  uint32_t memory = 0;      // Samples, attempt cancellation and LocalStore.
  uint32_t control = 0;     // Atomic lifecycle, traps and HartDone.
  // All three IDs may name one merged, lossless per-hart channel.
};

struct Configuration {
  std::vector<HartChannels> harts;
  std::vector<uint32_t> publication_producers;
  // Independent bounds for live instructions and outstanding LocalStore records.
  size_t max_live_instructions = 65536;
  // Session-long exact transaction deduplication. Exhaustion is Unsupported;
  // history is never silently evicted or reused as a new publication.
  size_t max_publication_transactions = 65536;
};

enum class ConversionStatus { Accepted, Waiting, Incomplete, Invalid, Unsupported };
struct ConversionResult {
  ConversionStatus status = ConversionStatus::Accepted;
  std::string message;
  explicit operator bool() const { return status == ConversionStatus::Accepted; }
};

struct RetireRecord {
  rvwmo::OperationId id;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint8_t length = 0;
  bool integer_writeback = false;
  uint8_t rd = 0;
  // Empty means the independently identified architectural writeback is delayed.
  // x0 does not need a register value, but its load memory effect is retained.
  std::optional<uint64_t> register_value;
  bool failed_sc = false;
  std::vector<rvwmo::MemoryOperation> memory;
  std::vector<rvwmo::ActualLoadValue> loads;
};

struct WritebackRecord {
  rvwmo::OperationId id;
  uint8_t rd = 0;
  uint64_t value = 0;
  uint64_t source_cycle = 0;
};

struct CapturedRetirement {
  Origin origin;
  RetireRecord architectural;
  std::optional<uint64_t> writeback_source_cycle;
};

struct ConversionDiagnostic {
  rvwmo::CheckStatus status = rvwmo::CheckStatus::Incomplete;
  rvwmo::OperationId id;
  std::string message;
};

struct ConvertedOutput {
  rvwmo::EventBatch batch;
  // The caller steps its independent REF and audits this architectural result.
  // register_value is DUT actual; it must never become REF expected data.
  std::vector<CapturedRetirement> retirements;
  // Exact current-consumer gaps observed in this trace, never a final verdict.
  std::vector<ConversionDiagnostic> diagnostics;
};

struct PendingState {
  size_t instructions = 0;
  size_t writebacks = 0;
  size_t load_samples = 0;
  size_t unpublished_stores = 0;
};

// Converts native observations only. Caller owns the complete producer roster,
// source-prefix proof, ObservationStream submit/drain, qualified rank resolver,
// CheckerEventConsumer consume_closed, independent REF and session finalization.
// Accepted means converted/buffered, never architectural or RVWMO Pass.
// Source cycles are the common-domain hardware times, not delivery times.
// A miss may retire before its refill sample: retain both times. Such a trace
// exposes a current-consumer gap instead of moving retirement to writeback.
class Adapter {
public:
  explicit Adapter(Configuration configuration);
  ~Adapter();
  Adapter(Adapter &&) noexcept;
  Adapter &operator=(Adapter &&) noexcept;
  Adapter(const Adapter &) = delete;
  Adapter &operator=(const Adapter &) = delete;

  const ConversionResult &configuration() const;
  ConversionResult allocate(const Origin &origin, const rvwmo::InstructionAllocateEvent &record);
  ConversionResult load_sample(const Origin &origin, const rvwmo::LoadSampleEvent &record);
  ConversionResult cancel_load(const Origin &origin, const rvwmo::InstructionCancelAttemptEvent &record);
  ConversionResult local_store(const Origin &origin, const rvwmo::LocalStoreEvent &record);
  ConversionResult publish_store(const Origin &origin, const rvwmo::StorePublishEvent &record);
  // Memory/actual-load metadata must be supplied explicitly by the caller.
  // The selected sample or integer writeback may arrive later; the original
  // retirement origin is retained while either is outstanding.
  ConversionResult retire(const Origin &origin, const RetireRecord &record);
  // Pair by dispatch-supplied identity and rd, never by PC, data or arrival order.
  ConversionResult writeback(const WritebackRecord &record);
  ConversionResult atomic(const Origin &origin, const rvwmo::AtomicLifecycleEvent &record);
  ConversionResult trap(const Origin &origin, const rvwmo::TrapEvent &record);
  ConversionResult hart_done(const Origin &origin, const rvwmo::HartDoneEvent &record);
  // Only caller-proven complete prefixes; a delayed retirement prevents closure.
  // Waiting leaves the watermark untouched and requires a caller retry.
  // A prefix must cover all observations accepted on that producer. After
  // closure, take_output delivers the queued watermark before the next prefix;
  // intervening observations return Waiting without being consumed.
  ConversionResult close_prefix(const rvwmo::ProducerWatermark &watermark);
  // Emit v2 whole-instruction squash for a live, uncommitted instruction.
  // The event source is supplied by the caller and must follow that identity's
  // allocation and attempt observations.
  ConversionResult squash(const Origin &origin, const rvwmo::OperationId &id);

  ConvertedOutput take_output();
  PendingState pending() const;
  static std::vector<std::string> consumer_gaps();

private:
  struct State;
  std::unique_ptr<State> state_;
};

} // namespace blackparrot
#endif
