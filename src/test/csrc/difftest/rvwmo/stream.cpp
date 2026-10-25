#include "stream.h"
#include <algorithm>
#include <iterator>
#include <limits>
#include <set>
#include <tuple>

namespace rvwmo {
namespace {
StreamResult invalid(const char *message) { return {EventValidationStatus::Invalid, message}; }
StreamResult incomplete(const char *message) { return {EventValidationStatus::Incomplete, message}; }
StreamResult unsupported(const char *message) { return {EventValidationStatus::Unsupported, message}; }

bool has_kind(const ProducerCapability &producer, RuntimeEventKind kind) {
  return std::find(producer.event_kinds.begin(), producer.event_kinds.end(), kind) != producer.event_kinds.end();
}

std::optional<uint32_t> memory_hart(const RuntimeEvent &event) {
  switch (event.kind) {
  case RuntimeEventKind::LoadSample:
    return std::get<LoadSampleEvent>(event.payload).operation.id.hart;
  case RuntimeEventKind::StorePublish: {
    const auto &members = std::get<StorePublishEvent>(event.payload).members;
    if (members.empty())
      return std::nullopt;
    const auto hart = members.front().id.hart;
    if (std::any_of(members.begin(), members.end(), [hart](const StorePublishMember &member) {
          return member.id.hart != hart;
        }))
      return std::nullopt;
    return hart;
  }
  case RuntimeEventKind::AtomicLifecycle:
    return std::get<AtomicLifecycleEvent>(event.payload).id.hart;
  default:
    return std::nullopt;
  }
}

struct OrderedNode {
  const RuntimeEvent *event = nullptr;
  uint16_t phase = 0;
  uint32_t producer = 0;
  uint64_t sequence = 0;
  uint8_t tie_kind = 0;
  size_t indegree = 0;
  std::vector<size_t> successors;
};

struct SourceOrderSummary {
  struct ProducerEvidence {
    bool unqualified = false;
    std::set<uint16_t> phases;
  };

  std::map<uint32_t, ProducerEvidence> producers;
  std::map<uint16_t, size_t> qualified_phase_producers;
  size_t unqualified_producers = 0;

  bool has_unordered_with(uint32_t producer, const SourcePosition &source) const {
    auto own = producers.find(producer);
    if (own == producers.end()) {
      if (!source.order_qualified)
        return !producers.empty();
      auto phase = qualified_phase_producers.find(source.qualified_phase);
      return unqualified_producers != 0 ||
             (phase != qualified_phase_producers.end() && phase->second != 0);
    }

    if (!source.order_qualified)
      return producers.size() > 1;
    auto phase = qualified_phase_producers.find(source.qualified_phase);
    const bool same_phase_other_producer =
        phase != qualified_phase_producers.end() && phase->second > own->second.phases.count(source.qualified_phase);
    const bool unqualified_other_producer = unqualified_producers > own->second.unqualified;
    return same_phase_other_producer || unqualified_other_producer;
  }

  void add(uint32_t producer, const SourcePosition &source) {
    auto &evidence = producers[producer];
    if (!source.order_qualified) {
      if (!evidence.unqualified) {
        evidence.unqualified = true;
        ++unqualified_producers;
      }
      return;
    }
    if (evidence.phases.insert(source.qualified_phase).second)
      ++qualified_phase_producers[source.qualified_phase];
  }
};

struct ByteOrderSummary {
  SourceOrderSummary all;
  SourceOrderSummary writes;
};

void add_order_edge(std::vector<OrderedNode> &nodes, size_t before, size_t after) {
  nodes[before].successors.push_back(after);
  ++nodes[after].indegree;
}

StreamResult order_same_cycle(const std::vector<const RuntimeEvent *> &events,
                              std::vector<const RuntimeEvent *> &ordered) {
  std::vector<OrderedNode> nodes;
  nodes.reserve(events.size() * 3);
  std::map<const RuntimeEvent *, size_t> event_nodes;
  std::map<uint16_t, std::pair<size_t, size_t>> qualified_phases;
  std::map<uint32_t, std::vector<size_t>> producer_events;

  for (const auto *event : events) {
    const size_t index = nodes.size();
    nodes.push_back({event, event->source.qualified_phase, event->producer_id,
                     event->source.producer_sequence, 1, 0, {}});
    event_nodes.emplace(event, index);
    producer_events[event->producer_id].push_back(index);
    if (event->source.order_qualified && event->source.qualified_phase != SourcePosition::cycle_closed_phase)
      qualified_phases.try_emplace(event->source.qualified_phase, std::make_pair(0, 0));
  }

  for (auto &producer : producer_events) {
    auto &indices = producer.second;
    std::sort(indices.begin(), indices.end(), [&](size_t lhs, size_t rhs) {
      return nodes[lhs].sequence < nodes[rhs].sequence;
    });
    for (size_t index = 1; index < indices.size(); ++index)
      add_order_edge(nodes, indices[index - 1], indices[index]);
  }

  for (auto &phase : qualified_phases) {
    const size_t before = nodes.size();
    nodes.push_back({nullptr, phase.first, 0, 0, 0, 0, {}});
    const size_t after = nodes.size();
    nodes.push_back({nullptr, phase.first, 0, 0, 2, 0, {}});
    phase.second = {before, after};
  }

  for (const auto *event : events) {
    if (!event->source.order_qualified)
      continue;
    const auto &barriers = qualified_phases.at(event->source.qualified_phase);
    const size_t event_node = event_nodes.at(event);
    add_order_edge(nodes, barriers.first, event_node);
    add_order_edge(nodes, event_node, barriers.second);
  }
  for (auto phase = qualified_phases.begin(); phase != qualified_phases.end();) {
    auto next = std::next(phase);
    if (next == qualified_phases.end())
      break;
    add_order_edge(nodes, phase->second.second, next->second.first);
    phase = next;
  }

  using ReadyKey = std::tuple<uint8_t, uint32_t, uint16_t, uint64_t, size_t>;
  std::set<ReadyKey> ready;
  auto ready_key = [&](size_t index) {
    const auto &node = nodes[index];
    return ReadyKey{node.tie_kind, node.producer, node.phase, node.sequence, index};
  };
  for (size_t index = 0; index < nodes.size(); ++index)
    if (!nodes[index].indegree)
      ready.insert(ready_key(index));

  ordered.clear();
  ordered.reserve(events.size());
  size_t visited = 0;
  while (!ready.empty()) {
    const size_t index = std::get<4>(*ready.begin());
    ready.erase(ready.begin());
    ++visited;
    if (nodes[index].event)
      ordered.push_back(nodes[index].event);
    for (const auto successor : nodes[index].successors)
      if (--nodes[successor].indegree == 0)
        ready.insert(ready_key(successor));
  }

  if (visited != nodes.size())
    return incomplete("same-cycle producer sequence conflicts with qualified phase order");
  return {EventValidationStatus::Accepted, {}};
}

StreamResult order_closed_events(const std::vector<const RuntimeEvent *> &ready,
                                 std::vector<const RuntimeEvent *> &ordered) {
  std::map<uint64_t, std::vector<const RuntimeEvent *>> cycles;
  for (const auto *event : ready)
    cycles[event->source.cycle].push_back(event);

  ordered.clear();
  ordered.reserve(ready.size());
  for (const auto &cycle : cycles) {
    std::vector<const RuntimeEvent *> cycle_events;
    auto result = order_same_cycle(cycle.second, cycle_events);
    if (!result)
      return result;
    ordered.insert(ordered.end(), cycle_events.begin(), cycle_events.end());
  }
  return {EventValidationStatus::Accepted, {}};
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
  if (lhs_producer == rhs_producer) {
    if (lhs.producer_sequence < rhs.producer_sequence)
      return SourceOrder::Before;
    if (lhs.producer_sequence > rhs.producer_sequence)
      return SourceOrder::After;
    return SourceOrder::Equal;
  }
  if (!lhs.order_qualified || !rhs.order_qualified)
    return SourceOrder::Unordered;
  if (lhs.qualified_phase < rhs.qualified_phase)
    return SourceOrder::Before;
  if (lhs.qualified_phase > rhs.qualified_phase)
    return SourceOrder::After;
  return SourceOrder::Unordered;
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

StreamResult ObservationStream::validate_transaction(const ObservationStream &stream, const EventBatch &batch) {
  if (!stream.configuration_)
    return stream.configuration_;
  if (batch.abi_version != 2)
    return unsupported("unsupported event ABI version");

  using SourceSequenceKey = std::pair<uint32_t, uint64_t>;
  std::set<SourceSequenceKey> pending_sequences;
  for (const auto &pending : stream.pending_events_)
    pending_sequences.emplace(pending.producer_id, pending.source.producer_sequence);
  for (const auto &event : batch.events) {
    auto producer = stream.producers_.find(event.producer_id);
    if (producer == stream.producers_.end() || !has_kind(producer->second, event.kind))
      return unsupported("event producer or kind was not negotiated");
    if (!payload_has_valid_shape(event))
      return invalid("event payload kind or shape is invalid");
    if (event.source.producer_sequence == 0)
      return invalid("producer source sequence zero is reserved");
    if (event.source.qualified_phase == SourcePosition::cycle_closed_phase)
      return invalid("cycle-closed sentinel is reserved for producer watermarks");
    auto closed_sequence = stream.closed_source_sequences_.find(event.producer_id);
    if (closed_sequence != stream.closed_source_sequences_.end() &&
        event.source.producer_sequence <= closed_sequence->second)
      return invalid("producer source sequence did not advance beyond the closed prefix");
    auto watermark = stream.watermarks_.find(event.producer_id);
    if (watermark != stream.watermarks_.end()) {
      if (position_is_closed(event.producer_id, event.source, watermark->second))
        return invalid("event arrived after its producer source watermark");
      if (event.source.cycle == watermark->second.cycle &&
          compare_source_position(event.producer_id, event.source, event.producer_id, watermark->second) ==
              SourceOrder::Unordered)
        return incomplete("same-cycle event cannot be classified against partial source watermark");
    }
    if (!pending_sequences.emplace(event.producer_id, event.source.producer_sequence).second)
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
  std::map<uint64_t, std::map<uint32_t, SourceOrderSummary>> hart_sources;
  std::map<uint64_t, std::map<uint64_t, ByteOrderSummary>> byte_sources;
  for (const auto *event : ready) {
    const auto effect = memory_effect(*event);
    if (!effect)
      continue;

    const auto hart = memory_hart(*event);
    if (hart) {
      auto &sources = hart_sources[event->source.cycle][*hart];
      if (sources.has_unordered_with(event->producer_id, event->source)) {
        result.status = EventValidationStatus::Incomplete;
        result.message = "same-hart memory events lack source order within a closed cycle";
        return result;
      }
      sources.add(event->producer_id, event->source);
    }

    for (size_t byte = 0; byte < effect->byte_mask.size(); ++byte) {
      if (!effect->byte_mask[byte] || effect->address > std::numeric_limits<uint64_t>::max() - byte)
        continue;
      auto &sources = byte_sources[event->source.cycle][effect->address + byte];
      const auto &prior = effect->write ? sources.all : sources.writes;
      if (prior.has_unordered_with(event->producer_id, event->source)) {
        result.status = EventValidationStatus::Incomplete;
        result.message = "closed same-cycle overlapping memory events lack qualified order";
        return result;
      }
      sources.all.add(event->producer_id, event->source);
      if (effect->write)
        sources.writes.add(event->producer_id, event->source);
    }
  }
  std::vector<const RuntimeEvent *> ordered;
  const auto order_result = order_closed_events(ready, ordered);
  if (!order_result) {
    result.status = order_result.status;
    result.message = order_result.message;
    return result;
  }
  std::map<uint32_t, uint64_t> latest_sequences = closed_source_sequences_;
  for (const auto *event : ordered) {
    auto previous = latest_sequences.find(event->producer_id);
    if (previous != latest_sequences.end() && event->source.producer_sequence <= previous->second) {
      result.status = EventValidationStatus::Invalid;
      result.message = "producer source sequence regressed in the closed source order";
      return result;
    }
    latest_sequences[event->producer_id] = event->source.producer_sequence;
  }
  result.events.reserve(ordered.size());
  for (const auto *event : ordered)
    result.events.push_back(*event);
  pending_events_.erase(std::remove_if(pending_events_.begin(), pending_events_.end(), [&](const RuntimeEvent &event) {
                          return event.source.cycle <= *result.closed_through_cycle;
                        }),
                        pending_events_.end());
  closed_source_sequences_ = std::move(latest_sequences);
  return result;
}

} // namespace rvwmo
