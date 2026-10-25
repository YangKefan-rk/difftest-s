#include "stream.h"
#include <algorithm>
#include <limits>
#include <tuple>

namespace rvwmo {
namespace {
StreamResult invalid(const char *message) { return {EventValidationStatus::Invalid, message}; }
StreamResult incomplete(const char *message) { return {EventValidationStatus::Incomplete, message}; }
StreamResult unsupported(const char *message) { return {EventValidationStatus::Unsupported, message}; }

bool has_kind(const ProducerCapability &producer, RuntimeEventKind kind) {
  return std::find(producer.event_kinds.begin(), producer.event_kinds.end(), kind) != producer.event_kinds.end();
}

bool valid_range(uint64_t address, const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask) {
  return !bytes.empty() && bytes.size() == mask.size() &&
         bytes.size() - 1 <= std::numeric_limits<uint64_t>::max() - address &&
         std::any_of(mask.begin(), mask.end(), [](uint8_t enabled) { return enabled != 0; });
}
} // namespace

SourceOrder compare_source_position(uint32_t lhs_producer, const SourcePosition &lhs, uint32_t rhs_producer,
                                    const SourcePosition &rhs) {
  if (lhs.cycle < rhs.cycle)
    return SourceOrder::Before;
  if (lhs.cycle > rhs.cycle)
    return SourceOrder::After;
  if (!lhs.order_qualified || !rhs.order_qualified)
    return SourceOrder::Unordered;
  if (lhs.qualified_phase < rhs.qualified_phase)
    return SourceOrder::Before;
  if (lhs.qualified_phase > rhs.qualified_phase)
    return SourceOrder::After;
  if (lhs_producer != rhs_producer)
    return SourceOrder::Unordered;
  if (lhs.producer_sequence < rhs.producer_sequence)
    return SourceOrder::Before;
  if (lhs.producer_sequence > rhs.producer_sequence)
    return SourceOrder::After;
  return SourceOrder::Equal;
}

ObservationStream::ObservationStream(StreamContract contract, std::vector<ProducerCapability> producers)
    : contract_(std::move(contract)) {
  if (contract_.abi_version != 2 || contract_.required_producers.empty() || producers.empty() ||
      contract_.max_pending_events == 0) {
    configuration_ = unsupported("at least one event producer is required");
    return;
  }
  std::map<uint32_t, ProducerRequirement> requirements;
  for (auto &requirement : contract_.required_producers) {
    if (!requirement.producer_id || requirement.event_kinds.empty() || requirements.count(requirement.producer_id)) {
      configuration_ = unsupported("event contract has zero/duplicate producer or no required event kinds");
      return;
    }
    requirements.emplace(requirement.producer_id, std::move(requirement));
  }
  for (auto &producer : producers) {
    if (!producer.producer_id || !producer.lossless_events || !producer.provides_source_positions ||
        !producer.provides_watermarks || producer.event_kinds.empty() || producers_.count(producer.producer_id)) {
      configuration_ = unsupported("producer lacks a unique ID, lossless source positions, or watermarks");
      producers_.clear();
      return;
    }
    auto required = requirements.find(producer.producer_id);
    if (required == requirements.end() ||
        !std::all_of(required->second.event_kinds.begin(), required->second.event_kinds.end(),
                     [&](RuntimeEventKind kind) { return has_kind(producer, kind); })) {
      configuration_ = unsupported("producer capabilities do not satisfy the requested stream contract");
      producers_.clear();
      return;
    }
    producers_.emplace(producer.producer_id, std::move(producer));
  }
  if (producers_.size() != requirements.size())
    configuration_ = unsupported("a required event producer was not configured");
}

std::optional<uint64_t> ObservationStream::minimum_closed_cycle() const {
  if (!configuration_)
    return std::nullopt;
  uint64_t minimum = std::numeric_limits<uint64_t>::max();
  for (const auto &producer : producers_) {
    auto watermark = watermarks_.find(producer.first);
    if (watermark == watermarks_.end())
      return std::nullopt;
    uint64_t closed = watermark->second.cycle;
    if (watermark->second.qualified_phase != SourcePosition::cycle_closed_phase ||
        !watermark->second.order_qualified) {
      if (!closed)
        return std::nullopt;
      --closed;
    }
    minimum = std::min(minimum, closed);
  }
  // This is an upper bound on source-open events, not a semantic object cache.
  // A stalled producer causes submit() backpressure rather than unbounded growth.
  return minimum;
}

bool ObservationStream::payload_matches_kind(const RuntimeEvent &event) {
  switch (event.kind) {
  case RuntimeEventKind::InstructionAllocate: return std::holds_alternative<InstructionAllocateEvent>(event.payload);
  case RuntimeEventKind::InstructionCancelAttempt:
    return std::holds_alternative<InstructionCancelAttemptEvent>(event.payload);
  case RuntimeEventKind::LocalStore: return std::holds_alternative<LocalStoreEvent>(event.payload);
  case RuntimeEventKind::LoadSample: return std::holds_alternative<LoadSampleEvent>(event.payload);
  case RuntimeEventKind::StorePublish: return std::holds_alternative<StorePublishEvent>(event.payload);
  case RuntimeEventKind::AtomicLifecycle: return std::holds_alternative<AtomicLifecycleEvent>(event.payload);
  case RuntimeEventKind::InstructionRetire: return std::holds_alternative<InstructionRetireEvent>(event.payload);
  case RuntimeEventKind::HartDone: return std::holds_alternative<HartDoneEvent>(event.payload);
  case RuntimeEventKind::Trap: return std::holds_alternative<TrapEvent>(event.payload);
  case RuntimeEventKind::InstructionSquash: return std::holds_alternative<InstructionSquashEvent>(event.payload);
  }
  return false;
}

bool ObservationStream::payload_has_valid_shape(const RuntimeEvent &event) {
  if (!payload_matches_kind(event))
    return false;
  switch (event.kind) {
  case RuntimeEventKind::InstructionAllocate: {
    const auto &p = std::get<InstructionAllocateEvent>(event.payload);
    return p.id.uid && p.pc % 2 == 0 && (p.length == 2 || p.length == 4 || p.length == 6 || p.length == 8);
  }
  case RuntimeEventKind::InstructionCancelAttempt:
    return std::get<InstructionCancelAttemptEvent>(event.payload).id.uid != 0;
  case RuntimeEventKind::LocalStore: {
    const auto &p = std::get<LocalStoreEvent>(event.payload);
    return p.id.uid && valid_range(p.address, p.bytes, p.byte_mask);
  }
  case RuntimeEventKind::LoadSample: {
    const auto &p = std::get<LoadSampleEvent>(event.payload);
    return p.operation.id.uid && p.operation.load && !p.operation.byte_mask.empty() &&
           p.actual_bytes.size() == p.operation.byte_mask.size() &&
           (p.forwarded_writers.empty() || p.forwarded_writers.size() == p.operation.byte_mask.size());
  }
  case RuntimeEventKind::StorePublish: {
    const auto &p = std::get<StorePublishEvent>(event.payload);
    if (!p.transaction_id || p.members.empty() || !valid_range(p.address, p.bytes, p.byte_mask) ||
        p.byte_writers.size() != p.bytes.size())
      return false;
    std::set<OperationId> members;
    for (const auto &member : p.members)
      if (!member.id.uid || !members.insert(member.id).second)
        return false;
    for (size_t byte = 0; byte < p.byte_mask.size(); ++byte)
      if (p.byte_mask[byte] && !members.count(p.byte_writers[byte]))
        return false;
    return true;
  }
  case RuntimeEventKind::AtomicLifecycle: {
    const auto &p = std::get<AtomicLifecycleEvent>(event.payload);
    return p.id.uid && ((p.phase != AtomicObservationPhase::ReadEffect &&
                         p.phase != AtomicObservationPhase::WriteEffect) || p.mask != 0);
  }
  case RuntimeEventKind::InstructionRetire: {
    const auto &p = std::get<InstructionRetireEvent>(event.payload);
    return p.instruction.uid && std::all_of(p.loads.begin(), p.loads.end(), [](const ActualLoadValue &load) {
      return load.id.uid && !load.bytes.empty();
    });
  }
  case RuntimeEventKind::HartDone: return true;
  case RuntimeEventKind::Trap: return std::get<TrapEvent>(event.payload).instruction.uid != 0;
  case RuntimeEventKind::InstructionSquash: {
    const auto &squash = std::get<InstructionSquashEvent>(event.payload);
    return squash.id.uid && squash.id.subaccess == 0;
  }
  }
  return false;
}

bool ObservationStream::position_is_closed(uint32_t producer, const SourcePosition &position,
                                           const SourcePosition &watermark) {
  if (position.cycle < watermark.cycle)
    return true;
  if (position.cycle > watermark.cycle)
    return false;
  if (watermark.order_qualified && watermark.qualified_phase == SourcePosition::cycle_closed_phase)
    return true;
  const auto order = compare_source_position(producer, position, producer, watermark);
  return order == SourceOrder::Before || order == SourceOrder::Equal;
}

std::optional<ObservationStream::MemoryEffect> ObservationStream::memory_effect(const RuntimeEvent &event) {
  MemoryEffect effect;
  effect.producer_id = event.producer_id;
  effect.source = event.source;
  switch (event.kind) {
  case RuntimeEventKind::LoadSample: {
    const auto &load = std::get<LoadSampleEvent>(event.payload).operation;
    effect.address = load.address;
    effect.byte_mask = load.byte_mask;
    return effect;
  }
  case RuntimeEventKind::StorePublish: {
    const auto &store = std::get<StorePublishEvent>(event.payload);
    effect.address = store.address;
    effect.byte_mask = store.byte_mask;
    effect.write = true;
    return effect;
  }
  case RuntimeEventKind::AtomicLifecycle: {
    const auto &atomic = std::get<AtomicLifecycleEvent>(event.payload);
    if (atomic.phase != AtomicObservationPhase::ReadEffect && atomic.phase != AtomicObservationPhase::WriteEffect)
      return std::nullopt;
    effect.address = atomic.address;
    effect.write = atomic.phase == AtomicObservationPhase::WriteEffect;
    for (unsigned byte = 0; byte < 8; ++byte)
      effect.byte_mask.push_back((atomic.mask >> byte) & 1);
    return effect;
  }
  default: return std::nullopt;
  }
}

bool ObservationStream::effects_overlap(const MemoryEffect &lhs, const MemoryEffect &rhs) {
  if (!lhs.write && !rhs.write)
    return false;
  for (size_t byte = 0; byte < lhs.byte_mask.size(); ++byte) {
    if (!lhs.byte_mask[byte] || lhs.address > std::numeric_limits<uint64_t>::max() - byte)
      continue;
    const uint64_t address = lhs.address + byte;
    if (address >= rhs.address && address - rhs.address < rhs.byte_mask.size() && rhs.byte_mask[address - rhs.address])
      return true;
  }
  return false;
}

StreamResult ObservationStream::validate_transaction(const ObservationStream &stream, const EventBatch &batch) {
  if (!stream.configuration_)
    return stream.configuration_;
  if (batch.abi_version != 2)
    return unsupported("unsupported event ABI version");

  using SourceSequenceKey = std::tuple<uint32_t, uint64_t, uint16_t, uint64_t>;
  std::set<SourceSequenceKey> pending_sequences;
  for (const auto &pending : stream.pending_events_)
    pending_sequences.emplace(pending.producer_id, pending.source.cycle, pending.source.qualified_phase,
                              pending.source.producer_sequence);
  for (const auto &event : batch.events) {
    auto producer = stream.producers_.find(event.producer_id);
    if (producer == stream.producers_.end() || !has_kind(producer->second, event.kind))
      return unsupported("event producer or kind was not negotiated");
    if (!payload_has_valid_shape(event))
      return invalid("event payload kind or shape is invalid");
    if (event.source.producer_sequence == 0)
      return invalid("producer source sequence zero is reserved");
    auto watermark = stream.watermarks_.find(event.producer_id);
    if (watermark != stream.watermarks_.end()) {
      if (position_is_closed(event.producer_id, event.source, watermark->second))
        return invalid("event arrived after its producer source watermark");
      if (event.source.cycle == watermark->second.cycle &&
          compare_source_position(event.producer_id, event.source, event.producer_id, watermark->second) ==
              SourceOrder::Unordered)
        return incomplete("same-cycle event cannot be classified against partial source watermark");
    }
    if (!pending_sequences.emplace(event.producer_id, event.source.cycle, event.source.qualified_phase,
                                   event.source.producer_sequence).second)
      return invalid("producer source position sequence was reused in an open prefix");

    if (event.kind == RuntimeEventKind::StorePublish) {
      const auto &publish = std::get<StorePublishEvent>(event.payload);
      for (const auto &member : publish.members) {
        const auto &position = member.publish_position;
        if (position.cycle != event.source.cycle || position.qualified_phase != event.source.qualified_phase ||
            position.producer_sequence != event.source.producer_sequence ||
            position.order_qualified != event.source.order_qualified)
          return incomplete("per-member store publish ordering is not supported by the single-point stream contract");
        if (publish.members.size() > 1 && !position.order_qualified)
          return incomplete("merged store members lack a qualified common publication point");
      }
    }
  }

  std::set<uint32_t> watermark_producers;
  for (const auto &watermark : batch.watermarks) {
    auto producer = stream.producers_.find(watermark.producer_id);
    if (producer == stream.producers_.end() || !producer->second.provides_watermarks)
      return unsupported("watermark came from an unregistered producer");
    if (!watermark_producers.insert(watermark.producer_id).second)
      return invalid("batch contains duplicate producer watermarks");
    auto previous = stream.watermarks_.find(watermark.producer_id);
    if (previous != stream.watermarks_.end()) {
      const auto order = compare_source_position(watermark.producer_id, previous->second,
                                                 watermark.producer_id, watermark.closed_through);
      if (order == SourceOrder::After)
        return invalid("producer watermark regressed");
      if (order == SourceOrder::Unordered)
        return incomplete("producer watermark update lacks qualified order");
    }
    for (const auto &event : batch.events) {
      if (event.producer_id != watermark.producer_id)
        continue;
      if (position_is_closed(watermark.producer_id, event.source, watermark.closed_through))
        continue;
      const auto order = compare_source_position(watermark.producer_id, event.source,
                                                 watermark.producer_id, watermark.closed_through);
      if (order == SourceOrder::After)
        return invalid("watermark does not cover all events in its batch");
      if (order == SourceOrder::Unordered)
        return incomplete("watermark cannot close an unqualified event in its cycle");
    }
  }

  // Detect malformed duplicate entries within a batch without retaining every
  // semantic identity for the duration of a long run. The checker owns lifetime validation.
  std::set<OperationId> allocated;
  std::set<OperationId> retired;
  std::set<OperationId> squashed;
  std::set<OperationId> local_stores;
  std::set<std::pair<OperationId, uint32_t>> attempts;
  for (const auto &event : batch.events) {
    if (event.kind == RuntimeEventKind::InstructionAllocate) {
      if (!allocated.insert(std::get<InstructionAllocateEvent>(event.payload).id).second)
        return invalid("instruction identity was allocated more than once");
    } else if (event.kind == RuntimeEventKind::InstructionRetire) {
      const auto &instruction = std::get<InstructionRetireEvent>(event.payload).instruction;
      OperationId id{instruction.hart, instruction.epoch, instruction.uid, 0};
      if (!retired.insert(id).second)
        return invalid("instruction identity was retired more than once");
    } else if (event.kind == RuntimeEventKind::InstructionSquash) {
      const auto &squash = std::get<InstructionSquashEvent>(event.payload);
      if (!squashed.insert(squash.id).second)
        return invalid("instruction identity was squashed more than once");
    } else if (event.kind == RuntimeEventKind::LocalStore) {
      if (!local_stores.insert(std::get<LocalStoreEvent>(event.payload).id).second)
        return invalid("local store identity was published more than once");
    } else if (event.kind == RuntimeEventKind::LoadSample) {
      const auto &load = std::get<LoadSampleEvent>(event.payload);
      if (!attempts.insert({load.operation.id, load.operation.attempt}).second)
        return invalid("load attempt was submitted more than once");
    }
  }
  return {EventValidationStatus::Accepted, {}};
}

StreamResult ObservationStream::submit(const EventBatch &batch) {
  if (pending_events_.size() > contract_.max_pending_events ||
      batch.events.size() > contract_.max_pending_events - pending_events_.size())
    return {EventValidationStatus::Pending, "event stream backpressure: source watermarks must advance"};
  auto result = validate_transaction(*this, batch);
  if (!result)
    return result;
  for (const auto &event : batch.events)
    pending_events_.push_back(event);
  for (const auto &watermark : batch.watermarks)
    watermarks_[watermark.producer_id] = watermark.closed_through;
  return {EventValidationStatus::Accepted, {}};
}

DrainedEventBatch ObservationStream::drain() {
  DrainedEventBatch result;
  if (!configuration_) {
    result.status = configuration_.status;
    result.message = configuration_.message;
    return result;
  }
  result.closed_through_cycle = minimum_closed_cycle();
  if (!result.closed_through_cycle) {
    result.status = EventValidationStatus::Pending;
    result.message = "waiting for every producer watermark";
    return result;
  }
  std::vector<const RuntimeEvent *> ready;
  for (const auto &event : pending_events_)
    if (event.source.cycle <= *result.closed_through_cycle)
      ready.push_back(&event);
  for (size_t lhs = 0; lhs < ready.size(); ++lhs) {
    for (size_t rhs = lhs + 1; rhs < ready.size(); ++rhs) {
      const auto &a = *ready[lhs];
      const auto &b = *ready[rhs];
      if (a.source.cycle != b.source.cycle)
        continue;
      const auto lhs_effect = memory_effect(a);
      const auto rhs_effect = memory_effect(b);
      if (lhs_effect && rhs_effect && effects_overlap(*lhs_effect, *rhs_effect) &&
          compare_source_position(a.producer_id, a.source, b.producer_id, b.source) == SourceOrder::Unordered) {
        result.status = EventValidationStatus::Incomplete;
        result.message = "closed same-cycle overlapping memory events lack qualified order";
        return result;
      }
    }
  }
  std::stable_sort(ready.begin(), ready.end(), [](const RuntimeEvent *lhs, const RuntimeEvent *rhs) {
    if (lhs->source.cycle != rhs->source.cycle)
      return lhs->source.cycle < rhs->source.cycle;
    const auto order = compare_source_position(lhs->producer_id, lhs->source, rhs->producer_id, rhs->source);
    if (order == SourceOrder::Before)
      return true;
    if (order == SourceOrder::After)
      return false;
    return lhs->producer_id < rhs->producer_id;
  });
  for (const auto *event : ready)
    result.events.push_back(*event);
  pending_events_.erase(std::remove_if(pending_events_.begin(), pending_events_.end(), [&](const RuntimeEvent &event) {
                          return event.source.cycle <= *result.closed_through_cycle;
                        }),
                        pending_events_.end());
  return result;
}

} // namespace rvwmo
