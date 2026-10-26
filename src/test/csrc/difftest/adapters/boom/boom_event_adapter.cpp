#include "boom_event_adapter.h"
#include "../../rvwmo/checker_event_consumer.h"
#include "../../rvwmo/stream.h"
#include "../../rvwmo/producer_ids.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace rvwmo {
namespace boom {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }
CheckResult pending(const char *message) { return {CheckStatus::Pending, 0, message}; }
CheckResult unsupported(const char *message) { return {CheckStatus::Unsupported, 0, message}; }

bool valid_bytes(uint64_t address, const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask) {
  return (bytes.size() == 1 || bytes.size() == 2 || bytes.size() == 4 || bytes.size() == 8) &&
         bytes.size() == mask.size() && bytes.size() - 1 <= std::numeric_limits<uint64_t>::max() - address &&
         std::all_of(mask.begin(), mask.end(), [](uint8_t bit) { return bit <= 1; }) &&
         std::any_of(mask.begin(), mask.end(), [](uint8_t bit) { return bit != 0; });
}

std::optional<uint8_t> scalar_memory_log2_size(uint32_t instruction, uint8_t length, bool load) {
  unsigned function = 0;
  if (length == 4) {
    const unsigned expected_opcode = load ? 0x03 : 0x23;
    if ((instruction & 0x7f) != expected_opcode)
      return std::nullopt;
    function = (instruction >> 12) & 7;
    if (load) {
      switch (function) {
      case 0: case 4: return 0; // LB/LBU
      case 1: case 5: return 1; // LH/LHU
      case 2: case 6: return 2; // LW/LWU
      case 3: return 3;         // LD
      default: return std::nullopt;
      }
    }
    if (function <= 3)
      return static_cast<uint8_t>(function); // SB/SH/SW/SD
    return std::nullopt;
  }
  if (length != 2)
    return std::nullopt;
  const unsigned quadrant = instruction & 3;
  if (quadrant != 0 && quadrant != 2)
    return std::nullopt;
  function = (instruction >> 13) & 7;
  if (load) {
    if (function == 2) return 2; // C.LW/C.LWSP
    if (function == 3) return 3; // C.LD/C.LDSP
  } else {
    if (function == 6) return 2; // C.SW/C.SWSP
    if (function == 7) return 3; // C.SD/C.SDSP
  }
  return std::nullopt;
}

bool complete_scalar_mask(const std::vector<uint8_t> &mask) {
  return !mask.empty() && std::all_of(mask.begin(), mask.end(), [](uint8_t bit) { return bit == 1; });
}

bool selected_bytes_equal(const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs,
                          const std::vector<uint8_t> &mask) {
  if (lhs.size() != rhs.size())
    return false;
  for (size_t byte = 0; byte < mask.size(); ++byte)
    if (mask[byte] && lhs[byte] != rhs[byte])
      return false;
  return true;
}

std::optional<uint8_t> integer_rd(uint32_t instruction, uint8_t length) {
  if (length == 4) {
    const unsigned opcode = instruction & 0x7f;
    const unsigned function = (instruction >> 12) & 7;
    switch (opcode) {
    case 0x03: // scalar integer load
      if (function <= 6)
        return static_cast<uint8_t>((instruction >> 7) & 31);
      return std::nullopt;
    case 0x13: case 0x17: case 0x1b: case 0x33: case 0x37: case 0x3b:
    case 0x67: case 0x6f:
      return static_cast<uint8_t>((instruction >> 7) & 31);
    case 0x53: { // FP comparisons/conversions/fmv.x forms write an integer rd.
      const unsigned function7 = (instruction >> 25) & 0x7f;
      if (function7 == 0x50 || function7 == 0x51 || function7 == 0x60 || function7 == 0x61 ||
          function7 == 0x70 || function7 == 0x71)
        return static_cast<uint8_t>((instruction >> 7) & 31);
      return std::nullopt;
    }
    case 0x73: // CSR reads write rd; ECALL/returns have no integer rd.
      if (function != 0)
        return static_cast<uint8_t>((instruction >> 7) & 31);
      return std::nullopt;
    default:
      return std::nullopt;
    }
  }
  if (length != 2)
    return std::nullopt;
  const unsigned quadrant = instruction & 3;
  const unsigned function = (instruction >> 13) & 7;
  if (quadrant == 0) {
    if (function == 0 || function == 2 || function == 3)
      return static_cast<uint8_t>(((instruction >> 2) & 7) + 8); // C.ADDI4SPN/LW/LD
    return std::nullopt;
  }
  if (quadrant == 1) {
    if (function <= 3)
      return static_cast<uint8_t>((instruction >> 7) & 31); // C.ADDI/ADDIW/LI/LUI
    if (function == 4)
      return static_cast<uint8_t>(((instruction >> 7) & 7) + 8); // C integer ALU
    return std::nullopt;
  }
  if (quadrant == 2 && (function == 0 || function == 2 || function == 3))
    return static_cast<uint8_t>((instruction >> 7) & 31); // C.SLLI/LWSP/LDSP
  if (quadrant == 2 && function == 4) {
    const unsigned destination = (instruction >> 7) & 31;
    const unsigned source = (instruction >> 2) & 31;
    const bool high_bit = (instruction >> 12) & 1;
    if (!high_bit)
      return source ? std::optional<uint8_t>{static_cast<uint8_t>(destination)} : std::nullopt;
    if (!source)
      return destination ? std::optional<uint8_t>{1} : std::nullopt; // C.JALR; rd==0 is EBREAK.
    return static_cast<uint8_t>(destination);
  }
  return std::nullopt;
}

std::optional<uint8_t> floating_rd(uint32_t instruction, uint8_t length) {
  if (length == 2) {
    const unsigned quadrant = instruction & 3;
    const unsigned function = (instruction >> 13) & 7;
    if ((quadrant == 0 || quadrant == 2) && (function == 1 || function == 5))
      return static_cast<uint8_t>((instruction >> 7) & 31);
    return std::nullopt;
  }
  if (length != 4)
    return std::nullopt;
  const unsigned opcode = instruction & 0x7f;
  const unsigned function7 = (instruction >> 25) & 0x7f;
  if (opcode == 0x07) // FLH/FLW/FLD
    return static_cast<uint8_t>((instruction >> 7) & 31);
  if (opcode == 0x43 || opcode == 0x47 || opcode == 0x4b || opcode == 0x4f)
    return static_cast<uint8_t>((instruction >> 7) & 31);
  if (opcode != 0x53)
    return std::nullopt;
  // F2I and FMV.X/FCLASS forms write GPRs, not FPRs.
  if (function7 == 0x50 || function7 == 0x51 || function7 == 0x60 || function7 == 0x61 ||
      function7 == 0x70 || function7 == 0x71)
    return std::nullopt;
  return static_cast<uint8_t>((instruction >> 7) & 31);
}

bool csr_instruction(uint32_t instruction) {
  return (instruction & 0x7f) == 0x73 && ((instruction >> 12) & 7) != 0;
}

RetirementResultCoverage retirement_coverage(uint32_t instruction, IntegerDestinationType destination_type) {
  if (destination_type == IntegerDestinationType::Floating)
    return RetirementResultCoverage::FloatingRegisterAndFflagsNeedComparator;
  const unsigned opcode = instruction & 0x7f;
  const unsigned function7 = (instruction >> 25) & 0x7f;
  const bool floating_instruction = opcode == 0x43 || opcode == 0x47 || opcode == 0x4b ||
      opcode == 0x4f || (opcode == 0x53 && function7 != 0x70 && function7 != 0x71);
  if (floating_instruction)
    return RetirementResultCoverage::FloatingFlagsNeedComparator;
  if (csr_instruction(instruction))
    return RetirementResultCoverage::CsrStateNeedsComparator;
  // A retired WFI has no scalar register or CSR write. Trap/interrupt handling
  // and proof of native completion remain separate lifecycle obligations.
  if (instruction == 0x10500073)
    return RetirementResultCoverage::Complete;
  if ((instruction & 0x7f) == 0x73)
    return RetirementResultCoverage::SystemStateNeedsComparator;
  return RetirementResultCoverage::Complete;
}

bool fence_instruction(uint32_t instruction) {
  const unsigned opcode = instruction & 0x7f;
  const unsigned function = (instruction >> 12) & 7;
  return (opcode == 0x0f && (function == 0 || function == 1)) ||
         (opcode == 0x73 && (instruction & 0xfe007fff) == 0x12000073);
}

bool same_position(const SourcePosition &lhs, const SourcePosition &rhs) {
  return lhs.cycle == rhs.cycle && lhs.qualified_phase == rhs.qualified_phase &&
         lhs.producer_sequence == rhs.producer_sequence && lhs.order_qualified == rhs.order_qualified;
}
} // namespace

BoomEventAdapter::BoomEventAdapter(uint32_t hart, uint64_t epoch, AdapterLimits limits)
    : hart_(hart), epoch_(epoch), limits_(limits), rob_(limits.rob_slots), ldq_(limits.ldq_slots),
      stq_(limits.stq_slots) {
  if (!limits.rob_slots || !limits.ldq_slots || !limits.stq_slots || !limits.live_instructions ||
      !limits.attempts_per_load || !limits.queued_events || !limits.producers ||
      !limits.captured_retirements)
    throw std::invalid_argument("BOOM adapter requires nonzero lifecycle and transport limits");
}

CheckResult BoomEventAdapter::validate_id(const OperationId &id) const {
  if (id.hart != hart_ || id.epoch != epoch_ || !id.uid)
    return invalid("BOOM instruction identity differs from the configured hart/epoch or has zero UID");
  if (id.subaccess)
    return unsupported("BOOM scalar adapter does not cover split or vector subaccesses");
  return {};
}

CheckResult BoomEventAdapter::validate_source(const EventSource &source) const {
  if (!source.position.producer_sequence)
    return invalid("BOOM source sequence zero is reserved by the public event stream");
  if (!source.producer_id)
    return invalid("BOOM event has no registered producer identity");
  if (source.position.qualified_phase == SourcePosition::cycle_closed_phase)
    return invalid("cycle-closed sentinel is a watermark, not an event source position");
  auto watermark = watermarks_.find(source.producer_id);
  if (watermark != watermarks_.end()) {
    if (source.position.cycle < watermark->second.cycle ||
        (source.position.cycle == watermark->second.cycle && watermark->second.order_qualified &&
         watermark->second.qualified_phase == SourcePosition::cycle_closed_phase))
      return invalid("BOOM late event targets an already closed producer prefix");
    const auto order = compare_source_position(source.producer_id, source.position,
                                               source.producer_id, watermark->second);
    if (order == SourceOrder::Before || order == SourceOrder::Equal)
      return invalid("BOOM event targets an already closed producer prefix");
    if (source.position.cycle == watermark->second.cycle && order == SourceOrder::Unordered)
      return incomplete("BOOM event cannot be ordered after its producer watermark");
  }
  return {};
}

CheckResult BoomEventAdapter::reserve_source_sequence(const EventSource &source) {
  auto result = validate_source(source);
  if (!result)
    return result;
  auto highest = highest_source_sequences_.find(source.producer_id);
  if (highest == highest_source_sequences_.end() && highest_source_sequences_.size() >= limits_.producers)
    return incomplete("BOOM producer source history bound reached");
  if (highest != highest_source_sequences_.end() && source.position.producer_sequence <= highest->second)
    return invalid("BOOM producer source sequence is not strictly increasing");
  highest_source_sequences_[source.producer_id] = source.position.producer_sequence;
  return {};
}

CheckResult BoomEventAdapter::validate_event_source(RuntimeEventKind kind, const EventSource &source) const {
  auto result = validate_source(source);
  if (!result)
    return result;
  const bool publication = kind == RuntimeEventKind::StorePublish;
  const uint32_t expected = publication ? kMemoryFabricProducerBase + 0 : hart_producer_id(hart_);
  const bool valid_channel = publication ? source.producer_id >= kMemoryFabricProducerBase
                                         : source.producer_id == expected;
  if (!valid_channel)
    return invalid(publication ? "BOOM StorePublish must use a registered shared-fabric producer"
                               : "BOOM hart-private event must use the configured hart producer");
  return {};
}

CheckResult BoomEventAdapter::available_slot(const std::vector<SlotOwner> &slots, const SlotGeneration &slot) const {
  if (slot.index >= slots.size() || !slot.generation)
    return invalid("BOOM slot is out of range or has zero generation");
  const auto &owner = slots[slot.index];
  if (owner.id)
    return invalid("BOOM physical slot is still owned by another live instruction");
  if (slot.generation <= owner.generation)
    return invalid("BOOM slot generation did not advance on reuse");
  return {};
}

CheckResult BoomEventAdapter::owned_slot(const std::vector<SlotOwner> &slots, const SlotGeneration &slot,
                                        const OperationId &id) const {
  if (slot.index >= slots.size() || !slots[slot.index].id || slots[slot.index].generation != slot.generation ||
      *slots[slot.index].id != id)
    return invalid("BOOM packet names a stale slot generation or the wrong instruction");
  return {};
}

void BoomEventAdapter::claim_slot(std::vector<SlotOwner> &slots, const SlotGeneration &slot, const OperationId &id) {
  slots[slot.index] = {slot.generation, id};
}

void BoomEventAdapter::release_slot(std::vector<SlotOwner> &slots, const SlotGeneration &slot) {
  slots[slot.index].id.reset();
}

CheckResult BoomEventAdapter::append(const EventSource &source, RuntimeEventKind kind, RuntimeEventPayload payload) {
  auto result = validate_event_source(kind, source);
  if (!result)
    return result;
  if (batch_.events.size() >= limits_.queued_events)
    return pending("BOOM event queue is full; submit the existing batch before retrying");
  result = reserve_source_sequence(source);
  if (!result)
    return result;
  batch_.events.push_back({source.producer_id, source.position, kind, std::move(payload)});
  return {};
}

CheckResult BoomEventAdapter::allocate(const InstructionAllocation &record) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  if (record.id.uid <= last_uid_ || instructions_.count(record.id))
    return invalid("BOOM allocation UID is not strictly increasing");
  if (instructions_.size() >= limits_.live_instructions)
    return pending("BOOM live instruction bound reached; drain retirements and publications before retrying");
  if (record.pc % 2 || (record.length != 2 && record.length != 4) ||
      (((record.instruction & 3) != 3) != (record.length == 2)))
    return invalid("BOOM allocation PC, instruction encoding or length is inconsistent");
  const unsigned opcode = record.instruction & 0x7f;
  const unsigned quadrant = record.instruction & 3;
  const unsigned compressed_function = (record.instruction >> 13) & 7;
  const bool unsupported_memory =
      (record.length == 4 && (opcode == 0x2f || opcode == 0x07 || opcode == 0x27)) ||
      (record.length == 2 && (quadrant == 0 || quadrant == 2) &&
       (compressed_function == 1 || compressed_function == 5));
  const bool load = record.length == 4 ? opcode == 0x03 :
      (quadrant == 0 || quadrant == 2) && (compressed_function == 2 || compressed_function == 3);
  const bool store = record.length == 4 ? opcode == 0x23 :
      (quadrant == 0 || quadrant == 2) && (compressed_function == 6 || compressed_function == 7);
  if (!unsupported_memory && (load != record.ldq.has_value() ||
      (store != record.stq.has_value() && !(record.stq && fence_instruction(record.instruction)))))
    return invalid("BOOM raw scalar opcode does not match its LDQ/STQ allocation");
  if (load && !scalar_memory_log2_size(record.instruction, record.length, true))
    return unsupported("BOOM load encoding is not a supported scalar integer width");
  if (store && !scalar_memory_log2_size(record.instruction, record.length, false))
    return unsupported("BOOM store encoding is not a supported scalar integer width");
  if (record.length == 4 && ((record.instruction >> 2) & 7) == 7)
    return unsupported("BOOM extended-length instruction exceeds the scalar consumer decode width");
  if (record.ldq && record.stq)
    return unsupported("BOOM atomic read/write allocation needs the public atomic lifecycle consumer");
  result = available_slot(rob_, record.rob);
  if (!result)
    return result;
  if (record.ldq) {
    result = available_slot(ldq_, *record.ldq);
    if (!result)
      return result;
  }
  if (record.stq) {
    result = available_slot(stq_, *record.stq);
    if (!result)
      return result;
  }
  result = append(record.source, RuntimeEventKind::InstructionAllocate,
                  InstructionAllocateEvent{record.id, record.pc, record.instruction, record.length});
  if (!result)
    return result;
  Instruction state;
  state.allocation = record;
  state.unsupported_memory = unsupported_memory;
  instructions_.emplace(record.id, std::move(state));
  claim_slot(rob_, record.rob, record.id);
  if (record.ldq)
    claim_slot(ldq_, *record.ldq, record.id);
  if (record.stq)
    claim_slot(stq_, *record.stq, record.id);
  last_uid_ = record.id.uid;
  return {};
}

CheckResult BoomEventAdapter::find_load(const LoadAttempt &record, Instruction *&instruction) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  result = owned_slot(ldq_, record.ldq, record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || found->second.retired || !found->second.allocation.ldq ||
      !(*found->second.allocation.ldq == record.ldq))
    return invalid("BOOM load packet has no matching live LDQ instruction");
  instruction = &found->second;
  return {};
}

CheckResult BoomEventAdapter::begin_load_attempt(const LoadAttempt &record, const EventSource &source_lower_bound) {
  Instruction *instruction = nullptr;
  auto result = find_load(record, instruction);
  if (!result)
    return result;
  result = validate_source(source_lower_bound);
  if (!result)
    return result;
  if (instruction->attempts.size() >= limits_.attempts_per_load)
    return incomplete("BOOM load exceeded the configured attempt history bound");
  if (instruction->latest_attempt) {
    if (record.attempt <= *instruction->latest_attempt)
      return invalid("BOOM load attempt did not increase monotonically");
    if (instruction->attempts.at(*instruction->latest_attempt).state != AttemptState::Cancelled)
      return invalid("BOOM replay began before cancellation of the previous load attempt");
  }
  if (source_lower_bound.producer_id != hart_producer_id(hart_))
    return invalid("BOOM load attempt lower bound must use its hart-private producer");
  if (source_lower_bound.position.cycle < instruction->allocation.source.position.cycle)
    return invalid("BOOM load attempt precedes its instruction allocation");
  // A begin is a private sampling lower bound, not a public stream event. Its
  // eventual sample can return after other observations with the same source
  // cycle and receives its public sequence only when that prefix is complete.
  instruction->attempts.emplace(record.attempt, Attempt{AttemptState::Executing, {}, source_lower_bound});
  instruction->latest_attempt = record.attempt;
  return {};
}

CheckResult BoomEventAdapter::sample_load(const LoadObservation &record) {
  Instruction *instruction = nullptr;
  auto result = find_load(record.access, instruction);
  if (!result)
    return result;
  auto attempt = instruction->attempts.find(record.access.attempt);
  if (attempt == instruction->attempts.end() || attempt->second.state != AttemptState::Executing)
    return invalid("BOOM sample names an unknown, cancelled or already sampled attempt");
  const auto &lower_bound = attempt->second.source_lower_bound;
  if (record.source.producer_id != lower_bound.producer_id)
    return incomplete("BOOM load attempt and sample do not share their negotiated source channel");
  if (record.source.position.cycle < lower_bound.position.cycle)
    return invalid("BOOM load source sample precedes its execution-attempt lower bound");
  switch (record.sampling_point) {
  case LoadSamplingPoint::Unavailable:
    return incomplete("BOOM load sample lacks source-side sampling evidence");
  case LoadSamplingPoint::CacheDataArray:
  case LoadSamplingPoint::StoreForwarding:
  case LoadSamplingPoint::RefillData:
    break;
  default:
    return invalid("BOOM load sample has an unknown sampling-evidence kind");
  }
  if (!record.source_complete)
    return incomplete("BOOM load sample lacks complete source-side sampling evidence");
  if (instruction->unsupported_memory) {
    // Keep speculative identities so a later branch squash is harmless. No
    // unsupported memory value becomes a public sample or reference oracle.
    attempt->second.state = AttemptState::Sampled;
    return {};
  }
  const auto expected_size = scalar_memory_log2_size(instruction->allocation.instruction,
                                                       instruction->allocation.length, true);
  if (!expected_size || record.bytes.size() != (size_t{1} << *expected_size) ||
      !complete_scalar_mask(record.byte_mask) ||
      !valid_bytes(record.address, record.bytes, record.byte_mask) ||
      (!record.forwarded_writers.empty() && record.forwarded_writers.size() != record.bytes.size()))
    return invalid("BOOM load sample width, scalar mask or forwarding shape differs from its instruction");
  if (!record.forwarded_writers.empty()) {
    for (const auto &writer : record.forwarded_writers)
      if (writer && (writer->hart != hart_ || writer->epoch != epoch_ || !writer->uid || writer->subaccess))
        return invalid("BOOM forwarding metadata names an invalid local logical writer");
  }
  if (record.sampling_point == LoadSamplingPoint::StoreForwarding && record.forwarded_writers.empty())
    return incomplete("BOOM forwarded load lacks byte writer evidence");
  MemoryOperation operation;
  operation.id = record.access.id;
  operation.attempt = record.access.attempt;
  operation.address = record.address;
  operation.byte_mask = record.byte_mask;
  operation.load = true;
  operation.source_kind = ReadSourceKind::Observed;
  result = append(record.source, RuntimeEventKind::LoadSample,
                  LoadSampleEvent{operation, record.bytes, record.forwarded_writers});
  if (!result)
    return result;
  attempt->second.operation = operation;
  attempt->second.state = AttemptState::Sampled;
  return {};
}

CheckResult BoomEventAdapter::cancel_load_attempt(const LoadAttempt &record, const EventSource &source) {
  Instruction *instruction = nullptr;
  auto result = find_load(record, instruction);
  if (!result)
    return result;
  auto attempt = instruction->attempts.find(record.attempt);
  if (attempt == instruction->attempts.end() || attempt->second.state == AttemptState::Cancelled)
    return invalid("BOOM cancel names an unknown or already cancelled attempt");
  result = append(source, RuntimeEventKind::InstructionCancelAttempt,
                  InstructionCancelAttemptEvent{record.id, record.attempt});
  if (!result)
    return result;
  attempt->second.state = AttemptState::Cancelled;
  return {};
}

CheckResult BoomEventAdapter::commit_store(const StoreCommit &record) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || !found->second.allocation.stq ||
      found->second.store || found->second.allocation.stq->index != record.stq.index ||
      found->second.allocation.stq->generation != record.stq.generation)
    return invalid("BOOM store commit has no matching live STQ instruction or is duplicated");
  if (found->second.unsupported_memory)
    return unsupported("BOOM committed memory instruction exceeds the scalar consumer profile");
  if (fence_instruction(found->second.allocation.instruction))
    return invalid("BOOM fence STQ entry has no LocalStore memory effect");
  if (!record.architecturally_committed)
    return incomplete("BOOM STQ allocation/request is not an architectural LocalStore commit");
  const auto expected_size = scalar_memory_log2_size(found->second.allocation.instruction,
                                                       found->second.allocation.length, false);
  if (!expected_size || record.bytes.size() != (size_t{1} << *expected_size) ||
      !complete_scalar_mask(record.byte_mask) || !valid_bytes(record.address, record.bytes, record.byte_mask))
    return invalid("BOOM LocalStore width or scalar byte mask differs from its instruction");
  result = append(record.source, RuntimeEventKind::LocalStore,
                  LocalStoreEvent{record.id, record.address, record.bytes, record.byte_mask});
  if (!result)
    return result;
  MemoryOperation operation;
  operation.id = record.id;
  operation.address = record.address;
  operation.byte_mask = record.byte_mask;
  operation.store = true;
  found->second.store = operation;
  found->second.store_bytes = record.bytes;
  return {};
}

CheckResult BoomEventAdapter::release_store_slot(const OperationId &id, const SlotGeneration &stq) {
  auto result = validate_id(id);
  if (!result)
    return result;
  result = owned_slot(stq_, stq, id);
  if (!result)
    return result;
  auto found = instructions_.find(id);
  if (found == instructions_.end() || found->second.stq_released ||
      (!found->second.store && !fence_instruction(found->second.allocation.instruction)))
    return invalid("BOOM STQ release has no committed store/fence or was already released");
  release_slot(stq_, stq);
  found->second.stq_released = true;
  collect(id);
  return {};
}

CheckResult BoomEventAdapter::publish_store(const StorePublication &record) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || !found->second.store || found->second.published ||
      !found->second.allocation.stq || !(*found->second.allocation.stq == record.stq))
    return invalid("BOOM publication has no matching LocalStore generation or was already published");
  if (!found->second.stq_released) {
    result = owned_slot(stq_, record.stq, record.id);
    if (!result)
      return result;
  }
  switch (record.evidence) {
  case StorePublicationEvidence::Unavailable:
    return incomplete("BOOM store lacks cache/coherence evidence for global publication");
  case StorePublicationEvidence::ExclusiveCacheDataWrite:
  case StorePublicationEvidence::CoherentRefillDataWrite:
    break;
  default:
    return invalid("BOOM store publication has an unknown evidence kind");
  }
  const auto &store = *found->second.store;
  if (!record.transaction_id || record.address != store.address || record.byte_mask != store.byte_mask ||
      !valid_bytes(record.address, record.bytes, record.byte_mask) || record.byte_writers.size() != record.bytes.size())
    return invalid("BOOM publication range, transaction or byte writers differ from LocalStore");
  if (!selected_bytes_equal(found->second.store_bytes, record.bytes, record.byte_mask))
    return invalid("BOOM publication bytes differ from the committed LocalStore bytes");
  for (size_t byte = 0; byte < record.byte_mask.size(); ++byte)
    if (record.byte_mask[byte] && record.byte_writers[byte] != record.id)
      return invalid("BOOM single-store publication names a different logical byte writer");
  StorePublishEvent publication{record.transaction_id, record.address, record.bytes, record.byte_mask,
                                record.byte_writers, {{record.id, record.source.position}}};
  result = append(record.source, RuntimeEventKind::StorePublish, std::move(publication));
  if (!result)
    return result;
  found->second.published = true;
  collect(record.id);
  return {};
}

CheckResult BoomEventAdapter::retire(const Retirement &record) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  result = owned_slot(rob_, record.rob, record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || found->second.retired || record.id.uid <= last_retired_uid_)
    return invalid("BOOM retirement is stale, duplicated or out of architectural program order");
  if (found->second.unsupported_memory)
    return unsupported("BOOM retired memory instruction exceeds the scalar consumer profile");
  if (captured_retirements_.size() >= limits_.captured_retirements)
    return pending("BOOM architectural result queue is full; retrieve captured retirements and retry");
  if (record.destination_type > IntegerDestinationType::Zero || record.logical_destination > 31)
    return invalid("BOOM retirement has an invalid destination type or architectural register");
  const auto decoded_integer_rd = integer_rd(record.instruction, found->second.allocation.length);
  const auto decoded_floating_rd = floating_rd(record.instruction, found->second.allocation.length);
  if (record.destination_type == IntegerDestinationType::Integer) {
    if (!decoded_integer_rd || *decoded_integer_rd != record.logical_destination)
      return invalid("BOOM integer retirement destination differs from its raw instruction rd");
  } else if (record.destination_type == IntegerDestinationType::Floating) {
    if (!decoded_floating_rd || *decoded_floating_rd != record.logical_destination)
      return invalid("BOOM floating retirement destination differs from its raw instruction rd");
  } else if ((record.destination_type == IntegerDestinationType::None ||
              record.destination_type == IntegerDestinationType::Zero) &&
             ((decoded_integer_rd && *decoded_integer_rd != 0) ||
              (decoded_floating_rd && *decoded_floating_rd != 0))) {
    return invalid("BOOM retirement omits a register destination present in its raw instruction");
  }
  for (const auto &older : instructions_)
    if (older.first.hart == record.id.hart && older.first.epoch == record.id.epoch &&
        older.first.uid < record.id.uid && !older.second.retired)
      return pending("BOOM retirement awaits an older live instruction to retire or squash");
  auto &state = found->second;
  if (record.pc != state.allocation.pc || record.instruction != state.allocation.instruction)
    return invalid("BOOM retirement raw instruction or PC differs from allocation");
  InstructionRetireEvent retirement;
  retirement.instruction.hart = record.id.hart;
  retirement.instruction.epoch = record.id.epoch;
  retirement.instruction.uid = record.id.uid;
  retirement.instruction.pc = record.pc;
  retirement.instruction.instruction = record.instruction;
  if (state.allocation.ldq) {
    if (!record.load_attempt)
      return incomplete("BOOM load retirement lacks its final attempt identity");
    auto selected = state.attempts.find(*record.load_attempt);
    if (selected == state.attempts.end() || selected->second.state != AttemptState::Sampled ||
        !selected->second.operation)
      return invalid("BOOM load retirement selected an unsampled or cancelled attempt");
    for (const auto &attempt : state.attempts)
      if (attempt.first != *record.load_attempt && attempt.second.state != AttemptState::Cancelled)
        return invalid("BOOM load retirement left an uncancelled attempt");
    if (!record.load_address || !record.load_log2_size)
      return incomplete("BOOM load retirement lacks an independent physical address or width");
    const auto expected_size = scalar_memory_log2_size(record.instruction, state.allocation.length, true);
    if (!expected_size || *record.load_log2_size != *expected_size)
      return invalid("BOOM load retirement width differs from its raw instruction");
    if (*record.load_log2_size > 3 || *record.load_address != selected->second.operation->address ||
        (size_t{1} << *record.load_log2_size) != selected->second.operation->byte_mask.size())
      return invalid("BOOM retirement physical load address or width differs from its selected sample");
    if (record.load_bytes.size() != selected->second.operation->byte_mask.size())
      return incomplete("BOOM load retirement lacks independently captured actual bytes");
    retirement.instruction.memory.push_back(*selected->second.operation);
    retirement.loads.push_back({record.id, *record.load_attempt, record.load_bytes});
  } else if (record.load_attempt || !record.load_bytes.empty() || record.load_address || record.load_log2_size) {
    return invalid("BOOM non-load retirement carries a load attempt/result");
  }
  if (state.allocation.stq) {
    if (!state.store && !fence_instruction(record.instruction))
      return incomplete("BOOM store retirement lacks its architectural LocalStore");
    if (state.store)
      retirement.instruction.memory.push_back(*state.store);
  }
  result = append(record.source, RuntimeEventKind::InstructionRetire, std::move(retirement));
  if (!result)
    return result;
  state.retired = true;
  CapturedRetirement captured{record.id, record.pc, record.instruction, record.source,
                              record.destination_type, {}, {},
                              retirement_coverage(record.instruction, record.destination_type)};
  if (record.destination_type == IntegerDestinationType::Integer && record.logical_destination != 0) {
    captured.destination_register = record.logical_destination;
    captured.destination_value = record.writeback_value;
  } else if (record.destination_type == IntegerDestinationType::Floating) {
    captured.destination_register = record.logical_destination;
    captured.destination_value = record.writeback_value;
  } else if (record.destination_type == IntegerDestinationType::Zero ||
             (record.destination_type == IntegerDestinationType::Integer && record.logical_destination == 0)) {
    captured.destination_type = IntegerDestinationType::Zero;
  }
  captured_retirements_.push_back(std::move(captured));
  last_retired_uid_ = record.id.uid;
  release_slot(rob_, state.allocation.rob);
  if (state.allocation.ldq)
    release_slot(ldq_, *state.allocation.ldq);
  collect(record.id);
  return {};
}

CheckResult BoomEventAdapter::audit_reference_store(CheckerEventConsumer &consumer, const ReferenceStoreAudit &record) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || !found->second.store)
    return pending("BOOM reference store audit awaits LocalStore conversion");
  if (found->second.audited)
    return invalid("BOOM reference store was already audited");
  // The record is REF-produced. Do not replace any field with DUT store bytes.
  result = consumer.audit_store(record.id, record.address, record.bytes, record.byte_mask);
  if (!result)
    return result;
  found->second.audited = true;
  collect(record.id);
  return {};
}

CheckResult BoomEventAdapter::audit_reference_store(const ReferenceStoreAudit &record) {
  auto result = validate_id(record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || !found->second.store)
    return pending("BOOM reference store audit awaits LocalStore conversion");
  if (found->second.audited)
    return invalid("BOOM reference store was already audited");
  const auto &store = *found->second.store;
  if (record.address != store.address || record.byte_mask != store.byte_mask ||
      !selected_bytes_equal(found->second.store_bytes, record.bytes, store.byte_mask))
    return {CheckStatus::Violation, 0, "BOOM independent REF store differs from LocalStore"};
  found->second.audited = true;
  collect(record.id);
  return {};
}

void BoomEventAdapter::collect(const OperationId &id) {
  auto found = instructions_.find(id);
  if (found == instructions_.end() || !found->second.retired)
    return;
  const auto &instruction = found->second;
  if (instruction.store && (!instruction.published || !instruction.audited))
    return;
  // A retired store may be observed by the native LocalStore probe after the
  // physical STQ slot was released and reused. Retain its identity until the
  // delayed LocalStore arrives; otherwise commit_store cannot audit it.
  if (instruction.allocation.stq && (!instruction.store || !instruction.stq_released))
    return;
  instructions_.erase(found);
}

CheckResult BoomEventAdapter::squash(const OperationId &id, const SlotGeneration &rob, const EventSource &source) {
  auto result = validate_id(id);
  if (!result)
    return result;
  result = owned_slot(rob_, rob, id);
  if (!result)
    return result;
  auto found = instructions_.find(id);
  if (found == instructions_.end() || found->second.retired || found->second.store)
    return invalid("BOOM cannot squash an unknown, retired or architecturally committed store");
  result = append(source, RuntimeEventKind::InstructionSquash, InstructionSquashEvent{id});
  if (!result)
    return result;
  release_slot(rob_, rob);
  if (found->second.allocation.ldq)
    release_slot(ldq_, *found->second.allocation.ldq);
  if (found->second.allocation.stq)
    release_slot(stq_, *found->second.allocation.stq);
  instructions_.erase(found);
  return {};
}

CheckResult BoomEventAdapter::close_prefix(const ProducerWatermark &watermark) {
  if (!watermark.producer_id)
    return invalid("BOOM watermark has no registered producer identity");
  if (watermark.producer_id != hart_producer_id(hart_))
    return unsupported("BOOM adapter closes only its hart channel; the common session owns fabric watermarks");
  auto previous = watermarks_.find(watermark.producer_id);
  if (previous == watermarks_.end() && watermarks_.size() >= limits_.producers)
    return incomplete("BOOM producer watermark bound reached");
  if (previous != watermarks_.end()) {
    const auto order = compare_source_position(watermark.producer_id, previous->second,
                                               watermark.producer_id, watermark.closed_through);
    if (order == SourceOrder::After)
      return invalid("BOOM producer watermark regressed");
    if (order == SourceOrder::Unordered && !same_position(previous->second, watermark.closed_through))
      return incomplete("BOOM producer watermark has no qualified prefix order");
  }
  for (const auto &instruction : instructions_) {
    for (const auto &entry : instruction.second.attempts) {
      const auto &attempt = entry.second;
      if (attempt.state != AttemptState::Executing ||
          attempt.source_lower_bound.producer_id != watermark.producer_id)
        continue;
      const auto &bound = attempt.source_lower_bound.position;
      if (watermark.closed_through.cycle >= bound.cycle)
        return pending("BOOM load attempt may still deliver an earlier source sample; prefix remains open");
    }
  }
  for (const auto &event : batch_.events) {
    if (event.producer_id != watermark.producer_id)
      continue;
    if (event.source.cycle < watermark.closed_through.cycle ||
        (event.source.cycle == watermark.closed_through.cycle && watermark.closed_through.order_qualified &&
         watermark.closed_through.qualified_phase == SourcePosition::cycle_closed_phase))
      continue;
    const auto order = compare_source_position(event.producer_id, event.source, event.producer_id,
                                               watermark.closed_through);
    if (order != SourceOrder::Before && order != SourceOrder::Equal)
      return incomplete("BOOM caller watermark does not close its complete queued source prefix");
  }
  auto queued = std::find_if(batch_.watermarks.begin(), batch_.watermarks.end(), [&](const ProducerWatermark &item) {
    return item.producer_id == watermark.producer_id;
  });
  if (queued == batch_.watermarks.end())
    batch_.watermarks.push_back(watermark);
  else
    *queued = watermark;
  watermarks_[watermark.producer_id] = watermark.closed_through;
  return {};
}

EventBatch BoomEventAdapter::take_batch() {
  EventBatch result;
  std::swap(result, batch_);
  return result;
}

std::vector<CapturedRetirement> BoomEventAdapter::take_retirements() {
  std::vector<CapturedRetirement> result;
  result.swap(captured_retirements_);
  return result;
}

CheckResult BoomEventAdapter::completion() const {
  if (!batch_.events.empty())
    return incomplete("BOOM converted events have not been handed to the observation stream");
  if (!captured_retirements_.empty())
    return incomplete("BOOM architectural results have not been handed to the REF comparator");
  if (!instructions_.empty())
    return incomplete("BOOM instructions or store publish/reference-audit obligations remain live");
  return {};
}

} // namespace boom
} // namespace rvwmo
