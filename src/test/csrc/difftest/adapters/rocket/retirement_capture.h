#ifndef DIFFTEST_ROCKET_RETIREMENT_CAPTURE_H
#define DIFFTEST_ROCKET_RETIREMENT_CAPTURE_H

#include "event_emitter.h"
#include <array>
#include <deque>
#include <set>

namespace rocket_difftest {

struct RetirementConfiguration {
  uint32_t hart = 0;
  uint64_t epoch = 0;
  size_t capacity = 65536;
};

// Private records from RocketCoreObservation, not another public wire format.
struct NativeRetirement {
  uint64_t token = 0;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  rvwmo::SourcePosition source;
  bool integer_write = false;
  bool deferred_integer_write = false;
  uint8_t destination = 0;
  uint64_t value = 0;
  bool floating_point = false;
};

struct NativeLateWrite {
  uint64_t token = 0;
  bool identity_known = false;
  uint8_t destination = 0;
  uint64_t value = 0;
  rvwmo::SourcePosition source;
};

struct CapturedRetirement {
  rvwmo::OperationId id;
  uint64_t pc = 0;
  uint32_t instruction = 0;
  rvwmo::SourcePosition source;
  bool integer_write = false;
  uint8_t destination = 0;
  uint64_t value = 0;
};

// Joins independent WB/late-WB data with the emitter's logical instruction ID.
// Does not read modeled load bytes or derive a REF expectation from DUT data.
class RetirementCapture {
public:
  explicit RetirementCapture(RetirementConfiguration configuration);
  rvwmo::CheckResult allocate(const InstructionObservation &instruction, const rvwmo::OperationId &id);
  rvwmo::CheckResult retire(const NativeRetirement &retirement);
  rvwmo::CheckResult late_write(const NativeLateWrite &write);
  rvwmo::CheckResult squash(uint64_t token);
  std::vector<CapturedRetirement> take_ready();
  rvwmo::CheckResult finalize() const;
  size_t pending_instructions() const { return instructions_.size(); }

private:
  struct Instruction {
    InstructionObservation allocation;
    rvwmo::OperationId id;
    std::optional<CapturedRetirement> retirement;
    bool waiting_for_write = false;
  };

  RetirementConfiguration configuration_;
  std::map<uint64_t, Instruction> instructions_;
  std::set<uint64_t> unretired_tokens_;
  std::array<uint64_t, 32> pending_destinations_{};
  std::optional<uint64_t> last_token_;
  std::optional<uint64_t> last_uid_;
  std::optional<rvwmo::SourcePosition> last_allocation_source_;
  std::optional<rvwmo::SourcePosition> last_retirement_source_;
  static constexpr size_t pipeline_kill_history = 32;
  std::deque<uint64_t> squashed_tokens_;
  rvwmo::CheckResult failure_;

  rvwmo::CheckResult reject(rvwmo::CheckStatus status, const char *message);
  rvwmo::CheckResult follows(const rvwmo::SourcePosition &earlier, const rvwmo::SourcePosition &later);
  static uint32_t raw_instruction(uint32_t raw, uint8_t length);
};

} // namespace rocket_difftest
#endif
