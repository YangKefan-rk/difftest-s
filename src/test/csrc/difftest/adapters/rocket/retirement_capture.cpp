#include "retirement_capture.h"
#include "../../rvwmo/producer_ids.h"
#include "../../rvwmo/dependency.h"
#include "../../rvwmo/stream.h"
#include <algorithm>
#include <utility>

namespace rocket_difftest {
using namespace rvwmo;

RetirementCapture::RetirementCapture(RetirementConfiguration configuration) : configuration_(configuration) {
  if (!configuration_.capacity || !hart_producer_id(configuration_.hart))
    reject(CheckStatus::Invalid, "Rocket retirement capture requires a valid hart and positive capacity");
}

CheckResult RetirementCapture::reject(CheckStatus status, const char *message) {
  failure_ = {status, 0, message};
  return failure_;
}

uint32_t RetirementCapture::raw_instruction(uint32_t raw, uint8_t length) {
  return length == 2 ? raw & 0xffff : raw;
}

CheckResult RetirementCapture::follows(const SourcePosition &earlier, const SourcePosition &later) {
  if (!later.producer_sequence || later.producer_sequence <= earlier.producer_sequence ||
      later.qualified_phase == SourcePosition::cycle_closed_phase)
    return reject(CheckStatus::Invalid, "Rocket retirement capture received an invalid source position");
  const auto producer = hart_producer_id(configuration_.hart);
  const auto order = compare_source_position(producer, earlier, producer, later);
  if (order == SourceOrder::After || order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket retirement/writeback source does not follow its predecessor");
  if (order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket retirement/writeback source order is not established");
  return {};
}

CheckResult RetirementCapture::allocate(const InstructionObservation &allocation, const OperationId &id) {
  if (!failure_)
    return failure_;
  if (id.hart != configuration_.hart || id.epoch != configuration_.epoch || !id.uid || id.subaccess ||
      !allocation.token || !allocation.source.producer_sequence ||
      allocation.source.qualified_phase == SourcePosition::cycle_closed_phase ||
      (last_token_ && allocation.token <= *last_token_) || (last_uid_ && id.uid <= *last_uid_))
    return reject(CheckStatus::Invalid, "Rocket retirement allocation has an invalid or reused identity");
  if (last_allocation_source_) {
    auto result = follows(*last_allocation_source_, allocation.source);
    if (!result)
      return result;
  }
  if (instructions_.size() >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket retirement capture capacity reached"};
  instructions_.emplace(allocation.token, Instruction{allocation, id, std::nullopt, false, std::nullopt});
  unretired_tokens_.insert(allocation.token);
  last_token_ = allocation.token;
  last_uid_ = id.uid;
  last_allocation_source_ = allocation.source;
  return {};
}

CheckResult RetirementCapture::retire(const NativeRetirement &retirement) {
  if (!failure_)
    return failure_;
  auto found = instructions_.find(retirement.token);
  if (found == instructions_.end() || found->second.retirement)
    return reject(CheckStatus::Invalid, "Rocket architectural retirement is unknown or duplicated");
  auto &instruction = found->second;
  const auto &allocation = instruction.allocation;
  if (retirement.pc != allocation.pc ||
      raw_instruction(retirement.instruction, allocation.length) !=
        raw_instruction(allocation.instruction, allocation.length))
    return reject(CheckStatus::Invalid, "Rocket architectural retirement PC/raw disagrees with allocation");
  auto result = follows(allocation.source, retirement.source);
  if (!result)
    return result;
  if (last_retirement_source_ && !(result = follows(*last_retirement_source_, retirement.source)))
    return result;
  const bool compressed = (retirement.instruction & 3) != 3;
  const bool standard_length = (allocation.length == 2 && compressed) ||
    (allocation.length == 4 && !compressed && (retirement.instruction & 0x1f) != 0x1f);
  if ((allocation.length == 2 || allocation.length == 4) && !standard_length)
    return reject(CheckStatus::Invalid, "Rocket retirement raw instruction disagrees with its byte length");
  if (retirement.destination > 31 || (retirement.integer_write && retirement.deferred_integer_write))
    return reject(CheckStatus::Invalid, "Rocket architectural retirement has conflicting integer-write flags");
  if (allocation.length != 2 && allocation.length != 4)
    return reject(CheckStatus::Unsupported, "Rocket retirement requires a supported scalar instruction comparator");
  FloatingPointInstruction floating;
  result = decode_floating_point_instruction(raw_instruction(allocation.instruction, allocation.length), floating);
  if (!result)
    return reject(result.status, result.message.c_str());
  if (floating.recognized != retirement.floating_point)
    return reject(CheckStatus::Invalid, "Rocket floating-point retirement qualifier disagrees with its encoding");
  const bool integer_write = retirement.integer_write || retirement.deferred_integer_write;
  if (retirement.floating_write && integer_write)
    return reject(CheckStatus::Invalid, "Rocket retirement cannot write both integer and floating-point registers");
  if (floating.recognized &&
      (retirement.floating_write != floating.writes_floating_point ||
       integer_write != (floating.writes_integer && floating.destination != 0) ||
       ((retirement.floating_write || integer_write) && retirement.destination != floating.destination)))
    return reject(CheckStatus::Invalid, "Rocket floating-point destination disagrees with its encoded write class");
  if (!floating.recognized && retirement.floating_write)
    return reject(CheckStatus::Invalid, "Rocket non-floating instruction claims a floating-point destination");
  if (instruction.floating_write && !retirement.floating_write)
    return reject(CheckStatus::Invalid, "Rocket non-FPR retirement has a floating-point writeback");
  if (unretired_tokens_.empty() || *unretired_tokens_.begin() != retirement.token)
    return reject(CheckStatus::Invalid, "Rocket architectural retirement overtook a live older instruction");
  if (retirement.destination && (retirement.integer_write || retirement.deferred_integer_write) &&
      pending_destinations_[retirement.destination])
    return reject(CheckStatus::Invalid, "Rocket writeback reused a pending scoreboard destination");
  const bool writes = retirement.destination && (retirement.integer_write || retirement.deferred_integer_write);
  if (retirement.floating_write && pending_floating_destinations_[retirement.destination])
    return reject(CheckStatus::Invalid, "Rocket floating-point retirement reused a pending destination");
  const bool floating_ready = retirement.floating_write && instruction.floating_write.has_value();
  if (floating_ready && instruction.floating_write->destination != retirement.destination)
    return reject(CheckStatus::Invalid, "Rocket floating-point writeback changed its retirement destination");
  uint64_t value = writes && !retirement.deferred_integer_write ? retirement.value : 0;
  if (floating_ready)
    value = instruction.floating_write->value;
  instruction.retirement = CapturedRetirement{instruction.id, retirement.pc,
    raw_instruction(retirement.instruction, allocation.length), retirement.source, writes,
    static_cast<uint8_t>(writes || retirement.floating_write ? retirement.destination : 0), value,
    retirement.floating_write, retirement.fcsr};
  instruction.waiting_for_write = (writes && retirement.deferred_integer_write) ||
                                (retirement.floating_write && !floating_ready);
  if (writes && instruction.waiting_for_write)
    pending_destinations_[retirement.destination] = retirement.token;
  if (retirement.floating_write && instruction.waiting_for_write)
    pending_floating_destinations_[retirement.destination] = retirement.token;
  unretired_tokens_.erase(retirement.token);
  last_retirement_source_ = retirement.source;
  return {};
}

CheckResult RetirementCapture::late_write(const NativeLateWrite &write) {
  if (!failure_)
    return failure_;
  if (!write.identity_known)
    return reject(CheckStatus::Incomplete, "Rocket late writeback has no observed instruction identity");
  auto found = instructions_.find(write.token);
  if (found == instructions_.end() || !found->second.retirement || !found->second.waiting_for_write)
    return reject(CheckStatus::Invalid, "Rocket late writeback has no pending architectural destination");
  auto &instruction = found->second;
  if (instruction.retirement->floating_write || !write.destination ||
      write.destination != instruction.retirement->destination)
    return reject(CheckStatus::Invalid, "Rocket late writeback changed its scoreboard destination");
  auto result = follows(instruction.retirement->source, write.source);
  if (!result)
    return result;
  instruction.retirement->value = write.value;
  instruction.waiting_for_write = false;
  pending_destinations_[write.destination] = 0;
  return {};
}

CheckResult RetirementCapture::floating_write(const NativeFpWrite &write) {
  if (!failure_)
    return failure_;
  if (!write.identity_known)
    return reject(CheckStatus::Incomplete, "Rocket floating-point writeback has no observed instruction identity");
  auto found = instructions_.find(write.token);
  if (found == instructions_.end())
    return reject(CheckStatus::Incomplete, "Rocket floating-point writeback has no live instruction identity");
  auto &instruction = found->second;
  if (instruction.floating_write)
    return reject(CheckStatus::Invalid, "Rocket floating-point writeback was observed twice");
  FloatingPointInstruction decoded;
  auto result = decode_floating_point_instruction(
      raw_instruction(instruction.allocation.instruction, instruction.allocation.length), decoded);
  if (!result)
    return reject(result.status, result.message.c_str());
  if (!decoded.recognized || !decoded.writes_floating_point || write.destination > 31 ||
      write.destination != decoded.destination)
    return reject(CheckStatus::Invalid, "Rocket floating-point writeback disagrees with the encoded destination");
  result = follows(instruction.allocation.source, write.source);
  if (!result)
    return result;
  if (instruction.retirement &&
      (!instruction.retirement->floating_write || !instruction.waiting_for_write ||
       pending_floating_destinations_[write.destination] != write.token))
    return reject(CheckStatus::Invalid, "Rocket floating-point writeback has no pending architectural destination");
  instruction.floating_write = write;
  if (instruction.retirement) {
    instruction.retirement->value = write.value;
    instruction.waiting_for_write = false;
    pending_floating_destinations_[write.destination] = 0;
  }
  return {};
}

CheckResult RetirementCapture::cancel_load_attempt(uint64_t token) {
  if (!failure_)
    return failure_;
  const auto found = instructions_.find(token);
  if (found == instructions_.end() || found->second.retirement)
    return reject(CheckStatus::Invalid, "Rocket load-attempt cancellation has no unretired instruction");
  // A failed request's early result cannot be reused by the retried load.
  // Actual post-retirement writes retain their exact token and cannot cancel.
  found->second.floating_write.reset();
  return {};
}

CheckResult RetirementCapture::squash(uint64_t token) {
  if (!failure_)
    return failure_;
  auto found = instructions_.find(token);
  if (found == instructions_.end()) {
    if (std::find(squashed_tokens_.begin(), squashed_tokens_.end(), token) != squashed_tokens_.end())
      return {};
    return reject(CheckStatus::Invalid, "Rocket retirement squash has no live or recently squashed token");
  }
  if (found->second.retirement)
    return reject(CheckStatus::Invalid, "Rocket retirement squash cannot retract a retired instruction");
  instructions_.erase(found);
  unretired_tokens_.erase(token);
  squashed_tokens_.push_back(token);
  if (squashed_tokens_.size() > pipeline_kill_history)
    squashed_tokens_.pop_front();
  return {};
}

std::vector<CapturedRetirement> RetirementCapture::take_ready() {
  std::vector<CapturedRetirement> ready;
  if (!failure_)
    return ready;
  while (!instructions_.empty()) {
    auto next = instructions_.begin();
    if (!next->second.retirement || next->second.waiting_for_write)
      break;
    ready.push_back(std::move(*next->second.retirement));
    instructions_.erase(next);
  }
  return ready;
}

CheckResult RetirementCapture::finalize() const {
  if (!failure_)
    return failure_;
  if (!instructions_.empty())
    return {CheckStatus::Pending, 0, "Rocket retirement capture has unresolved or undelivered instructions"};
  return {};
}

} // namespace rocket_difftest
