#include "session.h"
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace rvwmo {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult pending(const char *message) { return {CheckStatus::Pending, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }

bool is_memory_event_kind(const RuntimeEvent &event) {
  switch (event.kind) {
  case RuntimeEventKind::LoadSample:
  case RuntimeEventKind::StorePublish:
    return true;
  case RuntimeEventKind::AtomicLifecycle: {
    const auto phase = std::get<AtomicLifecycleEvent>(event.payload).phase;
    return phase == AtomicObservationPhase::ReadEffect || phase == AtomicObservationPhase::WriteEffect;
  }
  default:
    return false;
  }
}

CheckResult validate_memory_rank_order(const std::vector<RuntimeEvent> &events) {
  struct CycleSources {
    std::set<uint32_t> producers;
    std::map<uint16_t, std::set<uint32_t>> phase_producers;
    bool has_unqualified_source = false;
  };

  std::map<uint64_t, CycleSources> cycles;
  for (const auto &event : events) {
    if (!is_memory_event_kind(event))
      continue;
    auto &sources = cycles[event.source.cycle];
    sources.producers.insert(event.producer_id);
    if (!event.source.order_qualified) {
      sources.has_unqualified_source = true;
      continue;
    }
    sources.phase_producers[event.source.qualified_phase].insert(event.producer_id);
  }

  for (const auto &cycle : cycles) {
    const auto &sources = cycle.second;
    if (sources.producers.size() < 2)
      continue;
    if (sources.has_unqualified_source)
      return incomplete("same-cycle memory events lack cross-producer order evidence");
    for (const auto &phase : sources.phase_producers)
      if (phase.second.size() > 1)
        return incomplete("same-cycle memory events share a phase without qualified relative order");
  }
  return {};
}
} // namespace

ObservationSession::ObservationSession(StreamContract contract, std::vector<ProducerCapability> producers,
                                       Memory::ReadGlobal read_global, Memory::WriteGlobal write_global,
                                       ReferenceStepper reference_stepper,
                                       size_t max_live_instructions, size_t max_pending_retirements)
    : max_pending_events_(contract.max_pending_events), max_architectural_retirements_(max_pending_retirements),
      stream_(std::move(contract), producers),
      consumer_(std::move(read_global), std::move(write_global),
                [this](const RuntimeEvent &event) { return resolve_current_rank(event); },
                max_live_instructions, max_pending_retirements),
      reference_stepper_(std::move(reference_stepper)) {
  if (!stream_.configuration())
    failure_ = {CheckStatus::Unsupported, 0, stream_.configuration().message};
}

bool ObservationSession::is_memory_event(const RuntimeEvent &event) {
  return is_memory_event_kind(event);
}

std::optional<ObservationTime> ObservationSession::resolve_current_rank(const RuntimeEvent &event) const {
  if (!current_rank_event_ || !current_rank_.valid ||
      current_rank_event_->first != event.producer_id ||
      current_rank_event_->second != event.source.producer_sequence)
    return std::nullopt;
  return current_rank_;
}

CheckResult ObservationSession::remember_failure(CheckResult result) {
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    failure_ = result;
  return result;
}

CheckResult ObservationSession::collect_closed_events() {
  if (pending_events_.size() >= max_pending_events_)
    return pending("semantic event queue is full; retry after audits or checker progress");
  const auto drained = stream_.drain();
  if (drained.status == EventValidationStatus::Pending)
    return pending("waiting for every registered producer to close a source prefix");
  if (drained.status != EventValidationStatus::Accepted) {
    const auto status = drained.status == EventValidationStatus::Unsupported ? CheckStatus::Unsupported
                         : drained.status == EventValidationStatus::Invalid ? CheckStatus::Invalid
                                                                           : CheckStatus::Incomplete;
    return remember_failure({status, 0, drained.message});
  }
  std::vector<RuntimeEvent> rank_window;
  rank_window.reserve(pending_events_.size() + drained.events.size());
  for (const auto &pending_event : pending_events_)
    rank_window.push_back(pending_event.event);
  rank_window.insert(rank_window.end(), drained.events.begin(), drained.events.end());
  auto order = validate_memory_rank_order(rank_window);
  if (!order)
    return remember_failure(order);
  for (const auto &event : drained.events)
    pending_events_.push_back({event});
  return {};
}

CheckResult ObservationSession::consume_pending_events() {
  bool progress = true;
  while (progress) {
    progress = false;
    bool memory_blocked = false;
    std::map<uint32_t, bool> retirement_blocked;
    for (auto pending_event = pending_events_.begin(); pending_event != pending_events_.end();) {
      const auto &event = pending_event->event;
      const bool memory_event = is_memory_event(event);
      if (memory_event && memory_blocked) {
        ++pending_event;
        continue;
      }
      if (event.kind == RuntimeEventKind::InstructionRetire &&
          retirement_blocked[std::get<InstructionRetireEvent>(event.payload).instruction.hart]) {
        ++pending_event;
        continue;
      }

      if (memory_event) {
        if (next_rank_ == std::numeric_limits<uint64_t>::max())
          return remember_failure(invalid("session memory rank space exhausted"));
        current_rank_event_ = std::make_pair(event.producer_id, event.source.producer_sequence);
        current_rank_ = {next_rank_, true};
      }
      auto result = event.kind == RuntimeEventKind::InstructionRetire
                        ? consume_retirement(event, std::get<InstructionRetireEvent>(event.payload))
                        : consumer_.consume_closed(event);
      current_rank_event_.reset();
      current_rank_ = {};

      if (result.status == CheckStatus::Pending) {
        if (memory_event)
          memory_blocked = true;
        if (event.kind == RuntimeEventKind::InstructionRetire)
          retirement_blocked[std::get<InstructionRetireEvent>(event.payload).instruction.hart] = true;
        ++pending_event;
        continue;
      }
      if (!result)
        return remember_failure(result);
      if (memory_event)
        ++next_rank_;
      pending_event = pending_events_.erase(pending_event);
      progress = true;
    }
  }

  auto result = consumer_.poll();
  if (!result || result.status == CheckStatus::Pending)
    return result;
  if (!pending_events_.empty())
    return pending("session retains closed events awaiting semantic prerequisites");
  return result;
}

CheckResult ObservationSession::step_reference(const InstructionRetireEvent &retirement,
                                               const ArchitecturalRetirement &snapshot) {
  if (!reference_stepper_)
    return {CheckStatus::Unsupported, 0, "retirement has no independent reference-step callback"};
  if (snapshot.destination == ArchitecturalDestination::Unsupported)
    return {CheckStatus::Unsupported, 0, "architectural destination type is outside the scalar integer session"};

  std::vector<ReferenceLoadValue> loads;
  for (const auto &operation : retirement.instruction.memory) {
    if (!operation.load)
      continue;
    auto actual = std::find_if(retirement.loads.begin(), retirement.loads.end(), [&](const ActualLoadValue &value) {
      return value.id == operation.id && value.attempt == operation.attempt;
    });
    if (actual == retirement.loads.end())
      return incomplete("reference step awaits the selected actual load value");
    std::vector<uint8_t> expected;
    auto candidate = consumer_.candidate_load(operation.id, operation.attempt, expected);
    if (candidate.status == CheckStatus::Pending)
      return candidate;
    if (!candidate)
      return candidate;
    loads.push_back({operation.id, operation.attempt, std::move(expected)});
  }

  auto result = reference_stepper_(retirement, snapshot, loads);
  if (result.check.status == CheckStatus::Pending)
    return invalid("reference step callback must finish synchronously once invoked");
  if (!result.check)
    return result.check;
  if (result.reference_pc != retirement.instruction.pc ||
      result.reference_instruction != retirement.instruction.instruction)
    return {CheckStatus::Violation, 0, "reference PC or instruction differs from retirement"};
  if (result.took_trap)
    return {CheckStatus::Unsupported, 0, "reference instruction trapped outside generic trap semantics"};
  if (snapshot.destination == ArchitecturalDestination::Integer) {
    if (!snapshot.destination_register || snapshot.destination_register >= 32 || !result.integer_write ||
        result.integer_write->destination_register != snapshot.destination_register ||
        result.integer_write->value != snapshot.destination_value)
      return {CheckStatus::Violation, 0, "reference integer write differs from the DUT retirement snapshot"};
  } else if (snapshot.destination_register != 0 || result.integer_write) {
    return {CheckStatus::Violation, 0, "unexpected integer write for a non-writing retirement"};
  }

  std::vector<const MemoryOperation *> stores;
  for (const auto &operation : retirement.instruction.memory)
    if (operation.store)
      stores.push_back(&operation);
  if (stores.size() != result.stores.size())
    return {CheckStatus::Incomplete, 0, "reference store audit count differs from retired store operations"};
  for (size_t index = 0; index < stores.size(); ++index) {
    const auto &operation = *stores[index];
    const auto &store = result.stores[index];
    if (store.id != operation.id || store.address != operation.address || store.byte_mask != operation.byte_mask ||
        store.bytes.size() != operation.byte_mask.size())
      return {CheckStatus::Violation, 0, "reference store address, mask, width or identity differs from retirement"};
  }

  const OperationId id{retirement.instruction.hart, retirement.instruction.epoch, retirement.instruction.uid, 0};
  reference_records_[id] = {std::move(result.stores), 0};
  return {};
}

CheckResult ObservationSession::consume_retirement(const RuntimeEvent &event,
                                                   const InstructionRetireEvent &retirement) {
  const OperationId id{retirement.instruction.hart, retirement.instruction.epoch, retirement.instruction.uid, 0};
  auto snapshot = architectural_retirements_.find(id);
  if (snapshot == architectural_retirements_.end())
    return pending("retirement awaits its independent architectural snapshot");
  if (snapshot->second.pc != retirement.instruction.pc ||
      snapshot->second.instruction != retirement.instruction.instruction)
    return remember_failure(invalid("architectural snapshot differs from the retired instruction identity"));
  auto reference = reference_records_.find(id);
  if (reference == reference_records_.end()) {
    auto result = step_reference(retirement, snapshot->second);
    if (!result)
      return result;
    reference = reference_records_.find(id);
  }
  if (reference == reference_records_.end())
    return {CheckStatus::Incomplete, 0, "retirement has no completed independent reference result"};

  while (reference->second.audited_stores < reference->second.stores.size()) {
    const auto &store = reference->second.stores[reference->second.audited_stores];
    auto audited = consumer_.audit_store(store.id, store.address, store.bytes, store.byte_mask);
    if (audited.status == CheckStatus::Pending)
      return audited;
    if (!audited)
      return audited;
    ++reference->second.audited_stores;
  }

  auto result = consumer_.consume_closed(event);
  if (result) {
    reference_records_.erase(reference);
    architectural_retirements_.erase(snapshot);
  }
  return result;
}

SessionSubmitResult ObservationSession::submit(const EventBatch &batch,
                                               const std::vector<ArchitecturalRetirement> &retirements) {
  SessionSubmitResult result;
  if (!failure_) {
    result.transport = {EventValidationStatus::Invalid, failure_.message};
    result.check = failure_;
    result.pending_events = pending_events_.size();
    return result;
  }
  if (finalized_) {
    result.transport = {EventValidationStatus::Invalid, "event submitted after session finalization"};
    result.check = remember_failure(invalid("event submitted after session finalization"));
    result.pending_events = pending_events_.size();
    return result;
  }

  if (retirements.size() > max_architectural_retirements_ - architectural_retirements_.size()) {
    result.transport = {EventValidationStatus::Pending,
                        "architectural retirement snapshot queue is full; retry after matching retirements"};
    result.check = pending(result.transport.message.c_str());
    result.pending_events = pending_events_.size();
    return result;
  }

  std::set<OperationId> new_retirement_ids;
  if (retirements.size() > max_pending_events_ -
                               std::min(max_pending_events_, architectural_retirements_.size())) {
    result.transport = {EventValidationStatus::Pending, "architectural snapshot queue is full"};
    result.check = pending("retry architectural snapshots after their retirement events are consumed");
    result.pending_events = pending_events_.size();
    return result;
  }
  for (const auto &snapshot : retirements) {
    const bool supported_destination = snapshot.destination == ArchitecturalDestination::None ||
                                       snapshot.destination == ArchitecturalDestination::Integer ||
                                       snapshot.destination == ArchitecturalDestination::Unsupported;
    if (!snapshot.id.uid || snapshot.id.subaccess != 0 || snapshot.pc % 2 ||
        !supported_destination ||
        (snapshot.destination == ArchitecturalDestination::Integer &&
         (snapshot.destination_register == 0 || snapshot.destination_register >= 32)) ||
        (snapshot.destination != ArchitecturalDestination::Integer && snapshot.destination_register != 0) ||
        architectural_retirements_.count(snapshot.id) || !new_retirement_ids.insert(snapshot.id).second) {
      result.transport = {EventValidationStatus::Invalid, "invalid or duplicate architectural retirement snapshot"};
      result.check = remember_failure(invalid("invalid or duplicate architectural retirement snapshot"));
      result.pending_events = pending_events_.size();
      return result;
    }
  }

  result.transport = stream_.submit(batch);
  if (!result.transport) {
    result.check = result.transport.status == EventValidationStatus::Unsupported
                       ? CheckResult{CheckStatus::Unsupported, 0, result.transport.message}
                       : result.transport.status == EventValidationStatus::Incomplete
                             ? CheckResult{CheckStatus::Incomplete, 0, result.transport.message}
                             : result.transport.status == EventValidationStatus::Invalid
                                   ? CheckResult{CheckStatus::Invalid, 0, result.transport.message}
                                   : pending("event stream backpressure: close and consume a source prefix");
    result.check = remember_failure(result.check);
    result.pending_events = pending_events_.size();
    return result;
  }

  for (const auto &snapshot : retirements)
    architectural_retirements_.emplace(snapshot.id, snapshot);

  result.check = poll();
  result.pending_events = pending_events_.size();
  result.accepted = true;
  return result;
}

CheckResult ObservationSession::poll() {
  if (!failure_)
    return failure_;
  CheckResult progress;
  while (true) {
    const size_t pending_before = pending_events_.size();
    const size_t buffered_before = stream_.buffered_events();
    auto collected = collect_closed_events();
    if (collected.status != CheckStatus::Pending && !collected)
      return collected;
    progress = consume_pending_events();
    if (!progress && progress.status != CheckStatus::Pending)
      return progress;

    const size_t pending_after = pending_events_.size();
    const size_t buffered_after = stream_.buffered_events();
    if (buffered_after == 0)
      return progress;
    if (pending_before == pending_after && buffered_before == buffered_after)
      return pending("waiting for source closure or semantic prerequisites");
  }
}

CheckResult ObservationSession::finalize(uint64_t completed_cycle) {
  if (!failure_)
    return failure_;
  if (finalized_)
    return {};

  auto progress = poll();
  if (!progress)
    return progress;
  if (progress.status == CheckStatus::Pending)
    return progress;
  const auto closed_cycle = stream_.minimum_closed_cycle();
  if (!closed_cycle || *closed_cycle < completed_cycle)
    return pending("finalization awaits every producer watermark through the requested cycle");
  if (!pending_events_.empty())
    return incomplete("session has retained semantic events that cannot make progress");
  if (!architectural_retirements_.empty())
    return remember_failure(incomplete("session has architectural snapshots without matching retirements"));
  auto result = consumer_.finalize();
  if (!result)
    return remember_failure(result);
  finalized_ = true;
  return {};
}

} // namespace rvwmo
