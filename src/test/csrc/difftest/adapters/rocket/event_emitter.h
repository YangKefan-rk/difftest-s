#ifndef DIFFTEST_ROCKET_EVENT_EMITTER_H
#define DIFFTEST_ROCKET_EVENT_EMITTER_H

#include "../../rvwmo/event.h"
#include <map>
#include <optional>

namespace rocket_difftest {

struct EmitterConfiguration {
  uint32_t hart = 0;
  uint32_t producer = 0;
  uint64_t epoch = 0;
  size_t capacity = 65536;
  uint16_t xlen = 64;
};

struct InstructionObservation {
  uint64_t token = 0;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  uint8_t length = 0;
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

// Private Rocket capture adapter, not a DPI ABI or an RVWMO verdict. Speculative
// observations stay private until retirement and its final sample are known.
// Native tokens must increase per session; physical slot indices are insufficient.
// Watermarks cannot pass an unresolved
// instruction, so squash never retracts an allocation already sent to the consumer.
class EventEmitter {
public:
  explicit EventEmitter(EmitterConfiguration configuration);
  rvwmo::CheckResult begin(const InstructionObservation &instruction, rvwmo::OperationId &id);
  rvwmo::CheckResult sample_load(const LoadObservation &load);
  rvwmo::CheckResult cancel_load(uint64_t token, uint32_t attempt);
  rvwmo::CheckResult commit_store(const StoreObservation &store);
  rvwmo::CheckResult publish_store(const StoreObservation &store, uint64_t transaction);
  rvwmo::CheckResult retire(uint64_t token, rvwmo::SourcePosition source);
  rvwmo::CheckResult squash(uint64_t token);
  rvwmo::CheckResult close_through(uint64_t source_cycle);
  rvwmo::EventBatch take_batch();
  rvwmo::CheckResult finalize() const;
  size_t live_instructions() const { return instructions_.size(); }

private:
  enum class MemoryKind { None, Load, Store, Unsupported };
  struct Instruction {
    rvwmo::OperationId id;
    InstructionObservation allocation;
    MemoryKind kind = MemoryKind::None;
    uint32_t next_attempt = 0;
    std::optional<LoadObservation> load;
    std::optional<StoreObservation> store;
    bool retired = false;
  };

  EmitterConfiguration configuration_;
  std::map<uint64_t, Instruction> instructions_;
  std::optional<uint64_t> last_token_;
  std::optional<uint64_t> closed_cycle_;
  uint64_t next_uid_ = 1;
  rvwmo::EventBatch batch_;
  rvwmo::CheckResult failure_;

  static MemoryKind memory_kind(uint32_t instruction, uint8_t length);
  rvwmo::CheckResult reject(rvwmo::CheckStatus status, const char *message);
  rvwmo::CheckResult validate_source(const rvwmo::SourcePosition &source);
  rvwmo::CheckResult validate_access(uint64_t address, const std::vector<uint8_t> &bytes,
                                   const std::vector<uint8_t> &mask);
  void append(rvwmo::RuntimeEventKind kind, rvwmo::RuntimeEventPayload payload, rvwmo::SourcePosition source);
};

} // namespace rocket_difftest
#endif
