#ifndef DIFFTEST_RVWMO_EVENT_H
#define DIFFTEST_RVWMO_EVENT_H

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace rvwmo {

struct OperationId {
  uint32_t hart = 0;
  uint64_t epoch = 0;
  uint64_t uid = 0;
  uint32_t subaccess = 0;
  bool operator==(const OperationId &other) const {
    return hart == other.hart && epoch == other.epoch && uid == other.uid && subaccess == other.subaccess;
  }
  bool operator!=(const OperationId &other) const {
    return !(*this == other);
  }
  bool operator<(const OperationId &other) const {
    if (hart != other.hart)
      return hart < other.hart;
    if (epoch != other.epoch)
      return epoch < other.epoch;
    if (uid != other.uid)
      return uid < other.uid;
    return subaccess < other.subaccess;
  }
};

struct ObservationTime {
  uint64_t rank = 0;
  bool valid = false;
  // Internal certificate for loads sampling one source-closed read-only prefix.
  // It does not assert an order between equal-rank group members.
  bool unordered_read_group = false;
  // Independent effects commute on their enabled bytes; this certificate
  // preserves a partial order without inventing order inside the group.
  bool unordered_effect_group = false;
  // A physical coalesced store was the only memory effect in its closed cycle.
  bool isolated_store_group = false;
};

enum class CheckStatus {
  Pass,
  Violation,
  Pending,
  Incomplete,
  Unsupported,
  Invalid
};
struct CheckResult {
  CheckStatus status = CheckStatus::Pass;
  unsigned rule = 0;
  std::string message;
  explicit operator bool() const {
    return status == CheckStatus::Pass;
  }
};

// Register numbers 0..31 are integer registers; adapters may use other numbers
// for floating-point, vector and CSR dependency carriers.
struct DependencyMetadata {
  bool provided = false;
  bool complete = true;
  std::vector<unsigned> sources;
  std::vector<unsigned> destinations;
  // Optional per-destination carriers. Empty outer vector uses sources above;
  // an empty inner vector explicitly clears that destination's dependencies.
  std::vector<std::vector<unsigned>> destination_sources;
  std::vector<unsigned> address_sources;
  std::vector<unsigned> data_sources;
  bool carries_to_destination = true;
  bool control_transfer = false;
  bool fence = false;
  uint8_t fence_predecessor = 0;
  uint8_t fence_successor = 0;
};

// ModeledWitness identifies the source required by the fixed-order read-value
// axiom. It does not claim to identify a physical cache/forwarding data source.
enum class ReadSourceKind {
  Unavailable,
  ModeledWitness,
  Observed
};

struct MemoryOperation {
  OperationId id;
  uint32_t attempt = 0;
  uint64_t address = 0;
  std::vector<uint8_t> byte_mask;
  bool load = false;
  bool store = false;
  bool atomic = false;
  bool lr = false;
  bool sc = false;
  bool acquire = false;
  bool release = false;
  bool rcsc = false;
  bool has_paired_lr = false;
  OperationId paired_lr;
  ObservationTime read_time;
  ObservationTime write_time;
  ReadSourceKind source_kind = ReadSourceKind::Observed;
  // One writer per byte_mask element, including initialization writers.
  std::vector<OperationId> read_sources;
};

struct RetiredInstruction {
  uint32_t hart = 0;
  uint64_t epoch = 0;
  uint64_t uid = 0;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  bool failed_sc = false;
  // Explicitly excluded physical device store. No coherent RAM effect or REF execution.
  bool skipped_device_store = false;
  std::vector<MemoryOperation> memory;
  DependencyMetadata dependencies;
};

// Internal C++ event contract. Language-specific transports must convert to
// this representation; std::variant is not a DPI or generated RTL wire ABI.
struct SourcePosition {
  static constexpr uint16_t cycle_closed_phase = std::numeric_limits<uint16_t>::max();

  uint64_t cycle = 0;
  // Qualified phase values use one ABI-wide ordering shared by all producers.
  // A producer without that common phase contract must leave order_qualified false.
  uint16_t qualified_phase = 0;
  uint64_t producer_sequence = 0;
  bool order_qualified = false;

  static SourcePosition end_of_cycle(uint64_t cycle) {
    return {cycle, cycle_closed_phase, std::numeric_limits<uint64_t>::max(), true};
  }
};

struct ProducerWatermark {
  uint32_t producer_id = 0;
  SourcePosition closed_through;
};

enum class AtomicObservationPhase : uint8_t {
  ReadEffect = 1,
  WriteEffect = 2,
  Begin = 3,
  Request = 4,
  Replay = 5,
  Response = 6,
  Finish = 7,
  Cancel = 8
};

struct InstructionAllocateEvent {
  OperationId id;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint8_t length = 0;
};

struct InstructionCancelAttemptEvent {
  OperationId id;
  uint32_t attempt = 0;
};

struct InstructionSquashEvent {
  OperationId id;
};

struct LocalStoreEvent {
  OperationId id;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
};

struct LoadSampleEvent {
  MemoryOperation operation;
  std::vector<uint8_t> actual_bytes;
  std::vector<std::optional<OperationId>> forwarded_writers;
};

struct StorePublishMember {
  OperationId id;
  SourcePosition publish_position;
};

struct PhysicalStoreWrite {
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
};

struct StorePublishEvent {
  uint64_t transaction_id = 0;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
  std::vector<OperationId> byte_writers;
  std::vector<StorePublishMember> members;
  // Producer certificate: these same-hart stores first become externally
  // visible as one indivisible, complete coalesced publication. The checker
  // may linearize its members in program order at that point. This is a model
  // witness, not independently observed hardware timestamps for each member.
  bool coalesced_program_order = false;
  // ECC may physically rewrite preserved lanes outside the logical byte union.
  std::optional<PhysicalStoreWrite> physical_write = std::nullopt;
};

struct AtomicLifecycleEvent {
  OperationId id;
  uint32_t attempt = 0;
  AtomicObservationPhase phase = AtomicObservationPhase::Begin;
  uint64_t address = 0;
  uint64_t data = 0;
  uint8_t mask = 0;
  uint8_t command = 0;
  uint8_t fuop = 0;
  bool success = false;
  bool error = false;
};

struct ActualLoadValue {
  OperationId id;
  uint32_t attempt = 0;
  std::vector<uint8_t> bytes;
};

struct InstructionRetireEvent {
  RetiredInstruction instruction;
  std::vector<ActualLoadValue> loads;
};

struct HartDoneEvent {
  // This architectural notification does not close memory-observation channels.
  uint32_t hart = 0;
  int32_t exit_code = 0;
};

struct TrapEvent {
  uint32_t hart = 0;
  OperationId instruction;
  uint64_t pc = 0;
  uint64_t cause = 0;
  bool interrupt = false;
};

enum class RuntimeEventKind : uint8_t {
  InstructionAllocate,
  InstructionCancelAttempt,
  LocalStore,
  LoadSample,
  StorePublish,
  AtomicLifecycle,
  InstructionRetire,
  HartDone,
  Trap,
  InstructionSquash
};

using RuntimeEventPayload = std::variant<InstructionAllocateEvent, InstructionCancelAttemptEvent, LocalStoreEvent,
                                         LoadSampleEvent, StorePublishEvent, AtomicLifecycleEvent,
                                         InstructionRetireEvent, HartDoneEvent, TrapEvent, InstructionSquashEvent>;

struct RuntimeEvent {
  uint32_t producer_id = 0;
  SourcePosition source;
  RuntimeEventKind kind = RuntimeEventKind::InstructionAllocate;
  RuntimeEventPayload payload = InstructionAllocateEvent{};
};

struct EventBatch {
  uint32_t abi_version = 2;
  std::vector<RuntimeEvent> events;
  std::vector<ProducerWatermark> watermarks;
};

} // namespace rvwmo
#endif
