#ifndef DIFFTEST_ROCKET_EVENT_EMITTER_H
#define DIFFTEST_ROCKET_EVENT_EMITTER_H

#include "../../rvwmo/event.h"
#include <deque>
#include <map>
#include <optional>
#include <set>

namespace rocket_difftest {

struct EmitterConfiguration {
  uint32_t hart = 0;
  uint32_t producer = 0;
  uint64_t epoch = 0;
  size_t capacity = 65536;
  uint16_t xlen = 64;
  uint32_t publication_producer = 0; // Registered fabric channel; zero disables publication.
};

struct InstructionObservation {
  uint64_t token = 0;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint8_t length = 0;
  bool memory = false;
  uint8_t memory_command = 0;
  rvwmo::SourcePosition source;
};

struct LoadObservation {
  uint64_t token = 0;
  uint32_t attempt = 0;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;
  rvwmo::SourcePosition source;
};

struct StoreObservation {
  uint64_t token = 0;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;
  rvwmo::SourcePosition source;
};

struct StorePublicationGroup {
  uint64_t transaction = 0;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;
  std::vector<uint64_t> member_tokens;
  std::vector<std::optional<uint64_t>> byte_writer_tokens;
  rvwmo::SourcePosition source;
  std::optional<rvwmo::PhysicalStoreWrite> physical_write = std::nullopt;
};

// Private Rocket capture adapter, not a DPI ABI or an RVWMO verdict. Speculative
// observations stay private until retirement and its final sample are known.
// Native tokens must increase per session; physical slot indices are insufficient.
// Watermarks cannot pass an unresolved instruction, so squash never retracts
// an allocation already sent to the consumer.
class EventEmitter {
public:
  explicit EventEmitter(EmitterConfiguration configuration);
  rvwmo::CheckResult begin(const InstructionObservation &instruction, rvwmo::OperationId &id);
  rvwmo::CheckResult sample_load(const LoadObservation &load);
  // Canonical AMO/LR/SC lifecycle observation for an Atomic instruction. The
  // stale read/write points are supplied by the Rocket RTL probes; the emitter
  // only validates source order and stages the event.
  rvwmo::CheckResult atomic(uint64_t token, const rvwmo::AtomicLifecycleEvent &record,
                            const rvwmo::SourcePosition &source);
  rvwmo::CheckResult cancel_load(uint64_t token, uint32_t attempt);
  rvwmo::CheckResult commit_store(const StoreObservation &store);
  rvwmo::CheckResult publish_store(const StoreObservation &store, uint64_t transaction);
  rvwmo::CheckResult publish_store_group(const StorePublicationGroup &group);
  rvwmo::CheckResult retire(uint64_t token, rvwmo::SourcePosition source);
  rvwmo::CheckResult squash(uint64_t token);
  // Closes only this hart channel. The shared session closes the fabric channel.
  rvwmo::CheckResult close_through(uint64_t source_cycle);
  rvwmo::EventBatch take_batch();
  rvwmo::CheckResult finalize() const;
  size_t live_instructions() const { return instructions_.size(); }

private:
  enum class MemoryKind { None, Load, Store, Atomic, Unsupported };
  struct Instruction {
    rvwmo::OperationId id;
    InstructionObservation allocation;
    MemoryKind kind = MemoryKind::None;
    uint32_t next_attempt = 0;
    std::optional<LoadObservation> load;
    std::optional<StoreObservation> store;
    struct AtomicState {
      bool begun = false;
      bool request = false;
      bool read = false;
      bool write = false;
      bool response = false;
      bool success = false;
      bool lr = false;
      bool sc = false;
      bool rmw = false;
      bool has_old = false;
      uint64_t address = 0;
      uint8_t mask = 0;
      uint32_t attempt = 0;
      uint64_t old_data = 0;
    } atomic;
    bool retired = false;
  };

  EmitterConfiguration configuration_;
  std::map<uint64_t, Instruction> instructions_;
  std::set<uint64_t> unretired_tokens_;
  std::optional<uint64_t> last_token_;
  std::optional<uint64_t> closed_cycle_;
  uint64_t next_uid_ = 1;
  // Scalar EX/MEM/WB may repeat a termination over three source-ordered stages.
  static constexpr size_t pipeline_kill_history = 32;
  std::deque<uint64_t> terminated_tokens_;
  rvwmo::EventBatch batch_;
  rvwmo::CheckResult failure_;

  static MemoryKind memory_kind(uint32_t instruction, uint8_t length);
  static size_t memory_width(uint32_t instruction, uint8_t length);
  rvwmo::CheckResult reject(rvwmo::CheckStatus status, const char *message);
  rvwmo::CheckResult validate_source(const rvwmo::SourcePosition &source);
  rvwmo::CheckResult validate_access(uint64_t address, const std::vector<uint8_t> &bytes,
                                   const std::vector<uint8_t> &mask);
  void append(rvwmo::RuntimeEventKind kind, rvwmo::RuntimeEventPayload payload, rvwmo::SourcePosition source);
};

} // namespace rocket_difftest
#endif
