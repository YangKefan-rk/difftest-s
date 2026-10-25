#include "boom_event_adapter.h"
#include "../../rvwmo/checker_event_consumer.h"
#include "../../rvwmo/stream.h"
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

bool selected_bytes_equal(const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs,
                          const std::vector<uint8_t> &mask) {
  if (lhs.size() != rhs.size())
    return false;
  for (size_t byte = 0; byte < mask.size(); ++byte)
    if (mask[byte] && lhs[byte] != rhs[byte])
      return false;
  return true;
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
      !limits.attempts_per_load || !limits.queued_events || !limits.producers)
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
  if (batch_.events.size() >= limits_.queued_events)
    return pending("BOOM event queue is full; submit the existing batch before retrying");
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
  auto result = validate_source(source);
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
  if ((record.length == 4 && (opcode == 0x2f || opcode == 0x07 || opcode == 0x27)) ||
      (record.length == 2 && (quadrant == 0 || quadrant == 2) &&
       (compressed_function == 1 || compressed_function == 5)))
    return unsupported("BOOM atomic/floating/vector memory needs a richer public consumer");
  const bool load = record.length == 4 ? opcode == 0x03 :
      (quadrant == 0 || quadrant == 2) && (compressed_function == 2 || compressed_function == 3);
  const bool store = record.length == 4 ? opcode == 0x23 :
      (quadrant == 0 || quadrant == 2) && (compressed_function == 6 || compressed_function == 7);
  if (load != record.ldq.has_value() ||
      (store != record.stq.has_value() && !(record.stq && fence_instruction(record.instruction))))
    return invalid("BOOM raw scalar opcode does not match its LDQ/STQ allocation");
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

CheckResult BoomEventAdapter::begin_load_attempt(const LoadAttempt &record) {
  Instruction *instruction = nullptr;
  auto result = find_load(record, instruction);
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
  instruction->attempts.emplace(record.attempt, Attempt{});
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
  if (!record.source_complete || record.sampling_point == LoadSamplingPoint::Unavailable)
    return incomplete("BOOM load sample lacks complete source-side sampling evidence");
  if (!valid_bytes(record.address, record.bytes, record.byte_mask) ||
      (!record.forwarded_writers.empty() && record.forwarded_writers.size() != record.bytes.size()))
    return invalid("BOOM load sample has an invalid scalar byte range or forwarding shape");
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
  result = owned_slot(stq_, record.stq, record.id);
  if (!result)
    return result;
  auto found = instructions_.find(record.id);
  if (found == instructions_.end() || found->second.retired || !found->second.allocation.stq || found->second.store)
    return invalid("BOOM store commit has no matching live STQ instruction or is duplicated");
  if (fence_instruction(found->second.allocation.instruction))
    return invalid("BOOM fence STQ entry has no LocalStore memory effect");
  if (!record.architecturally_committed)
    return incomplete("BOOM STQ allocation/request is not an architectural LocalStore commit");
  if (!valid_bytes(record.address, record.bytes, record.byte_mask))
    return invalid("BOOM LocalStore has an invalid scalar byte range");
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
  if (record.evidence == StorePublicationEvidence::Unavailable)
    return incomplete("BOOM store lacks cache/coherence evidence for global publication");
  const auto &store = *found->second.store;
  if (!record.transaction_id || record.address != store.address || record.byte_mask != store.byte_mask ||
      !valid_bytes(record.address, record.bytes, record.byte_mask) || record.byte_writers.size() != record.bytes.size())
    return invalid("BOOM publication range, transaction or byte writers differ from LocalStore");
  if (!selected_bytes_equal(found->second.store_bytes, record.bytes, record.byte_mask))
    return invalid("BOOM publication bytes differ from the committed LocalStore bytes");
  for (size_t byte = 0; byte < record.byte_mask.size(); ++byte)
    if (record.byte_mask[byte] && record.byte_writers[byte] != record.id)
      return unsupported("BOOM merged/multi-writer publication needs the public merged-store consumer");
  StorePublishEvent publication{record.transaction_id, record.address, record.bytes, record.byte_mask,
                                record.byte_writers, {{record.id, record.source.position}}};
  result = append(record.source, RuntimeEventKind::StorePublish, std::move(publication));
  if (!result)
    return result;
  found->second.published = true;
  if (!found->second.stq_released)
    release_slot(stq_, record.stq);
  found->second.stq_released = true;
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
    if (record.load_bytes.size() != selected->second.operation->byte_mask.size())
      return incomplete("BOOM load retirement lacks independently captured actual bytes");
    retirement.instruction.memory.push_back(*selected->second.operation);
    retirement.loads.push_back({record.id, *record.load_attempt, record.load_bytes});
  } else if (record.load_attempt || !record.load_bytes.empty()) {
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

void BoomEventAdapter::collect(const OperationId &id) {
  auto found = instructions_.find(id);
  if (found == instructions_.end() || !found->second.retired)
    return;
  const auto &instruction = found->second;
  if (instruction.store && (!instruction.published || !instruction.audited))
    return;
  if (instruction.allocation.stq && !instruction.stq_released)
    return;
  instructions_.erase(found);
}

CheckResult BoomEventAdapter::squash(const OperationId &id, const SlotGeneration &rob) {
  auto result = validate_id(id);
  if (!result)
    return result;
  result = owned_slot(rob_, rob, id);
  if (!result)
    return result;
  auto found = instructions_.find(id);
  if (found == instructions_.end() || found->second.retired || found->second.store)
    return invalid("BOOM cannot squash an unknown, retired or architecturally committed store");
  release_slot(rob_, rob);
  if (found->second.allocation.ldq)
    release_slot(ldq_, *found->second.allocation.ldq);
  if (found->second.allocation.stq)
    release_slot(stq_, *found->second.allocation.stq);
  instructions_.erase(found);
  missing_squash_protocol_ = true;
  return incomplete("BOOM private slots reclaimed; public whole-instruction squash protocol is missing");
}

CheckResult BoomEventAdapter::close_prefix(const ProducerWatermark &watermark) {
  if (!watermark.producer_id)
    return invalid("BOOM watermark has no registered producer identity");
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

CheckResult BoomEventAdapter::completion() const {
  if (missing_squash_protocol_)
    return incomplete("BOOM observed a whole-instruction squash unsupported by the public consumer");
  if (!batch_.events.empty())
    return incomplete("BOOM converted events have not been handed to the observation stream");
  if (!instructions_.empty())
    return incomplete("BOOM instructions or store publish/reference-audit obligations remain live");
  return {};
}

} // namespace boom
} // namespace rvwmo
