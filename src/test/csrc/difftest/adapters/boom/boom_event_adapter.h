#ifndef DIFFTEST_ADAPTERS_BOOM_EVENT_ADAPTER_H
#define DIFFTEST_ADAPTERS_BOOM_EVENT_ADAPTER_H

#include "../../rvwmo/event.h"
#include <map>
#include <optional>

namespace rvwmo {
class CheckerEventConsumer;
namespace boom {

// Private BOOM records; this header is not a DPI/wire ABI. Producer registration
// and source-clock/phase qualification belong to the simulation integration.
struct EventSource {
  uint32_t producer_id = 0;
  SourcePosition position;
};

struct SlotGeneration {
  uint32_t index = 0;
  uint64_t generation = 0;
  bool operator==(const SlotGeneration &other) const {
    return index == other.index && generation == other.generation;
  }
};

struct InstructionAllocation {
  OperationId id;
  SlotGeneration rob;
  std::optional<SlotGeneration> ldq;
  std::optional<SlotGeneration> stq;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint8_t length = 0;
  EventSource source;
};

struct LoadAttempt {
  OperationId id;
  SlotGeneration ldq;
  uint32_t attempt = 0;
};

enum class LoadSamplingPoint {
  Unavailable,
  CacheDataArray,
  StoreForwarding,
  RefillData
};

struct LoadObservation {
  LoadAttempt access;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
  std::vector<std::optional<OperationId>> forwarded_writers;
  LoadSamplingPoint sampling_point = LoadSamplingPoint::Unavailable;
  // Confirms that source refers to the selected data's actual sampling point,
  // including forwarding/refill/replay, rather than the response delivery time.
  bool source_complete = false;
  EventSource source;
};

struct StoreCommit {
  OperationId id;
  SlotGeneration stq;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
  bool architecturally_committed = false;
  EventSource source;
};

// These cases require a DUT-specific cache/coherence argument. A request, STQ
// clear or store ACK alone is deliberately not a publication authorization.
enum class StorePublicationEvidence {
  Unavailable,
  ExclusiveCacheDataWrite,
  CoherentRefillDataWrite
};

struct StorePublication {
  OperationId id;
  SlotGeneration stq;
  uint64_t transaction_id = 0;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
  std::vector<OperationId> byte_writers;
  StorePublicationEvidence evidence = StorePublicationEvidence::Unavailable;
  EventSource source;
};

struct Retirement {
  OperationId id;
  SlotGeneration rob;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  std::optional<uint32_t> load_attempt;
  // Independently captured retirement bytes, not copied from LoadObservation.
  std::vector<uint8_t> load_bytes;
  EventSource source;
};

struct ReferenceStoreAudit {
  OperationId id;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> byte_mask;
};

struct AdapterLimits {
  size_t rob_slots = 256;
  size_t ldq_slots = 64;
  size_t stq_slots = 64;
  size_t live_instructions = 4096;
  size_t attempts_per_load = 64;
  size_t queued_events = 65536;
  size_t producers = 64;
};

class BoomEventAdapter {
public:
  BoomEventAdapter(uint32_t hart, uint64_t epoch, AdapterLimits limits = {});

  CheckResult allocate(const InstructionAllocation &record);
  CheckResult begin_load_attempt(const LoadAttempt &record);
  CheckResult sample_load(const LoadObservation &record);
  CheckResult cancel_load_attempt(const LoadAttempt &record, const EventSource &source);
  CheckResult commit_store(const StoreCommit &record);
  // A physical STQ entry can be reused while its logical store is still
  // travelling through the cache/MSHR. This does not emit StorePublish.
  CheckResult release_store_slot(const OperationId &id, const SlotGeneration &stq);
  CheckResult publish_store(const StorePublication &record);
  CheckResult retire(const Retirement &record);
  CheckResult audit_reference_store(CheckerEventConsumer &consumer, const ReferenceStoreAudit &record);

  // Reclaims private slots but does not invent a public whole-instruction cancel
  // event. Until that protocol exists, this makes completion Incomplete.
  CheckResult squash(const OperationId &id, const SlotGeneration &rob);
  CheckResult close_prefix(const ProducerWatermark &watermark);
  EventBatch take_batch();
  // Private lifecycle completeness only; this is never an RVWMO verdict.
  CheckResult completion() const;
  size_t live_instructions() const { return instructions_.size(); }

private:
  enum class AttemptState { Executing, Sampled, Cancelled };
  struct Attempt {
    AttemptState state = AttemptState::Executing;
    std::optional<MemoryOperation> operation;
  };
  struct Instruction {
    InstructionAllocation allocation;
    std::map<uint32_t, Attempt> attempts;
    std::optional<uint32_t> latest_attempt;
    std::optional<MemoryOperation> store;
    std::vector<uint8_t> store_bytes;
    bool stq_released = false;
    bool published = false;
    bool audited = false;
    bool retired = false;
  };
  struct SlotOwner {
    uint64_t generation = 0;
    std::optional<OperationId> id;
  };

  uint32_t hart_;
  uint64_t epoch_;
  AdapterLimits limits_;
  uint64_t last_uid_ = 0;
  uint64_t last_retired_uid_ = 0;
  std::map<OperationId, Instruction> instructions_;
  std::vector<SlotOwner> rob_;
  std::vector<SlotOwner> ldq_;
  std::vector<SlotOwner> stq_;
  std::map<uint32_t, SourcePosition> watermarks_;
  EventBatch batch_;
  bool missing_squash_protocol_ = false;

  CheckResult validate_id(const OperationId &id) const;
  CheckResult validate_source(const EventSource &source) const;
  CheckResult available_slot(const std::vector<SlotOwner> &slots, const SlotGeneration &slot) const;
  CheckResult owned_slot(const std::vector<SlotOwner> &slots, const SlotGeneration &slot,
                         const OperationId &id) const;
  CheckResult find_load(const LoadAttempt &record, Instruction *&instruction);
  CheckResult append(const EventSource &source, RuntimeEventKind kind, RuntimeEventPayload payload);
  void claim_slot(std::vector<SlotOwner> &slots, const SlotGeneration &slot, const OperationId &id);
  void release_slot(std::vector<SlotOwner> &slots, const SlotGeneration &slot);
  void collect(const OperationId &id);
};

} // namespace boom
} // namespace rvwmo
#endif
