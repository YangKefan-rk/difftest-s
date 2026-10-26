#include "native_collector.h"
#include "../../rvwmo/producer_ids.h"
#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace rvwmo {
namespace boom {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }
CheckResult pending(const char *message) { return {CheckStatus::Pending, 0, message}; }
bool same_instruction(const ProbeIdentity &lhs, const ProbeIdentity &rhs) {
  return lhs.epoch == rhs.epoch && lhs.uid == rhs.uid && lhs.rob_generation == rhs.rob_generation;
}
} // namespace

NativeCollector::NativeCollector(NativeCollectorConfiguration configuration)
    : configuration_(configuration), adapter_(configuration.hart, configuration.epoch, configuration.limits) {
  if (!hart_producer_id(configuration.hart) || !configuration.staged_events)
    throw std::invalid_argument("BOOM collector requires a valid hart and nonzero staging limit");
}

OperationId NativeCollector::id(const ProbeIdentity &identity) const {
  return {configuration_.hart, identity.epoch, identity.uid, 0};
}

EventSource NativeCollector::capture_source(uint64_t cycle) {
  // Capture sequence is private lifecycle bookkeeping. take_ready assigns the
  // public sequence only after all source samples in the prefix have arrived.
  return {hart_producer_id(configuration_.hart), {cycle, 0, ++capture_sequence_, false}};
}

CheckResult NativeCollector::remember_failure(CheckResult result) {
  if (!result)
    failure_ = result;
  return result;
}

CaptureResult NativeCollector::capture(const NativeFrame &frame) {
  if (!failure_)
    return {failure_, false};
  const uint64_t expected = captured_cycle_ ? *captured_cycle_ + 1 : configuration_.initial_cycle;
  if ((captured_cycle_ && *captured_cycle_ == std::numeric_limits<uint64_t>::max()) ||
      frame.hart != configuration_.hart || frame.epoch != configuration_.epoch || frame.cycle != expected)
    return {remember_failure(invalid("BOOM source frame is missing, repeated or from another hart/epoch")), false};
  const size_t facts = frame.allocations.size() + frame.begins.size() + frame.cancellations.size() +
      frame.completions.size() + frame.local_stores.size() + frame.retirements.size() +
      frame.store_releases.size() + frame.squashes.size() + frame.publications.size();
  if (facts > configuration_.staged_events - std::min(configuration_.staged_events, staged_events_.size()))
    return {pending("BOOM source staging is full; retain the complete frame and drain before retrying"), false};
  if (facts > std::numeric_limits<uint64_t>::max() - capture_sequence_)
    return {remember_failure(invalid("BOOM capture sequence exhausted")), false};
  if (frame.trap)
    return {remember_failure({CheckStatus::Unsupported, 0, "BOOM trap requires the common trap-state consumer"}), false};
  auto result = capture_frame(frame);
  if (!result) {
    // A frame may already have applied earlier native facts. It cannot be
    // retried after partial application or silently discarded as backpressure.
    if (result.status == CheckStatus::Pending)
      result = incomplete("BOOM lifecycle capacity prevents lossless frame consumption");
    return {remember_failure(result), false};
  }
  captured_cycle_ = frame.cycle;
  queues_empty_ = frame.queues_empty;
  cache_idle_ = frame.cache_idle;
  result = collect_adapter_output();
  return {remember_failure(result), static_cast<bool>(result)};
}

CheckResult NativeCollector::capture_frame(const NativeFrame &frame) {
  auto result = capture_allocations(frame);
  if (!result || !(result = capture_attempts(frame)))
    return result;
  for (const auto &store : frame.local_stores) {
    StoreCommit local;
    auto result = convert_store(configuration_.hart, store, capture_source(frame.cycle), local);
    if (!result || !(result = adapter_.commit_store(local)))
      return result;
  }
  result = capture_retirements(frame);
  if (!result || !(result = capture_terminations(frame)))
    return result;
  for (const auto &publication : frame.publications) {
    if (publication.source.position.cycle > frame.cycle)
      return invalid("BOOM store publication claims a future source cycle");
    StorePublication converted;
    auto result = convert_single_store_publication(configuration_.hart, publication.probe, publication.source,
        publication.transaction_id, publication.evidence, publication.single_writer_complete, converted);
    if (!result || !(result = adapter_.publish_store(converted)))
      return result;
  }
  return {};
}

CheckResult NativeCollector::capture_allocations(const NativeFrame &frame) {
  std::set<size_t> used_queues;
  for (const auto &core : frame.allocations) {
    std::optional<ProbeQueueAllocation> queue;
    for (size_t index = 0; index < frame.queue_allocations.size(); ++index) {
      const auto &candidate = frame.queue_allocations[index];
      if (!same_instruction(core.identity, candidate.identity))
        continue;
      if (queue || !used_queues.insert(index).second)
        return invalid("BOOM dispatch has duplicate queue identity");
      queue = candidate;
    }
    InstructionAllocation allocation;
    auto result = merge_allocation(configuration_.hart, core, queue, configuration_.limits.ldq_slots,
                                   configuration_.limits.stq_slots, capture_source(frame.cycle), allocation);
    if (!result || !(result = adapter_.allocate(allocation)))
      return result;
    allocations_.emplace(allocation.id, allocation);
  }
  if (used_queues.size() != frame.queue_allocations.size())
    return invalid("BOOM queue allocation has no matching core dispatch");

  return {};
}

CheckResult NativeCollector::capture_attempts(const NativeFrame &frame) {
  std::set<OperationId> beginning_instructions;
  std::set<AttemptKey> begins;
  for (const auto &begin : frame.begins) {
    auto result = validate_attempt(begin);
    if (!result)
      return result;
    const AttemptKey key{id(begin.identity), begin.identity.attempt};
    if (!beginning_instructions.insert(key.first).second || !begins.insert(key).second ||
        unresolved_samples_.count(key))
      return invalid("BOOM source frame repeats a load execution begin");
  }
  std::map<AttemptKey, NativeAttempt> cancellations;
  for (const auto &cancel : frame.cancellations) {
    auto result = validate_attempt(cancel);
    if (!result)
      return result;
    cancellations.emplace(AttemptKey{id(cancel.identity), cancel.identity.attempt}, cancel);
  }
  // A TLB retry may begin on the edge that reports the previous attempt's
  // delayed cancellation. Normalize those private lifecycle facts before the
  // new begin; a cancellation of that new attempt still follows its own begin.
  for (const auto &cancel : cancellations) {
    if (begins.count(cancel.first))
      continue;
    auto result = capture_cancellation(cancel.second, frame.cycle);
    if (!result)
      return result;
  }
  for (const auto &begin : frame.begins) {
    auto result = adapter_.begin_load_attempt(convert_attempt(configuration_.hart, begin.identity, begin.queue_index),
                                               capture_source(frame.cycle));
    if (!result)
      return result;
    unresolved_samples_.emplace(AttemptKey{id(begin.identity), begin.identity.attempt}, frame.cycle);
  }
  for (const auto &cancel : cancellations) {
    if (!begins.count(cancel.first))
      continue;
    auto result = capture_cancellation(cancel.second, frame.cycle);
    if (!result)
      return result;
  }
  for (const auto &complete : frame.completions) {
    const auto &probe = complete.probe;
    auto checked = validate_attempt({probe.identity, probe.queue_index});
    if (!checked)
      return checked;
    if (complete.sampled_at.cycle > frame.cycle)
      return invalid("BOOM completed load claims a future source cycle");
    LoadObservation sample;
    auto source = capture_source(complete.sampled_at.cycle);
    source.position.qualified_phase = complete.sampled_at.qualified_phase;
    source.position.order_qualified = complete.sampled_at.order_qualified;
    auto result = convert_load(configuration_.hart, probe, source, sample);
    if (!result || !(result = adapter_.sample_load(sample)))
      return result;
    unresolved_samples_.erase({id(probe.identity), probe.identity.attempt});
  }
  return {};
}

CheckResult NativeCollector::capture_cancellation(const NativeAttempt &cancel, uint64_t cycle) {
  auto result = adapter_.cancel_load_attempt(convert_attempt(configuration_.hart, cancel.identity, cancel.queue_index),
                                             capture_source(cycle));
  if (result)
    unresolved_samples_.erase({id(cancel.identity), cancel.identity.attempt});
  return result;
}

CheckResult NativeCollector::capture_retirements(const NativeFrame &frame) {
  std::set<size_t> used_retired_loads;
  for (const auto &core : frame.retirements) {
    const auto instruction_id = id(core.identity);
    auto allocation = allocations_.find(instruction_id);
    if (allocation == allocations_.end())
      return invalid("BOOM retirement has no retained core/queue allocation");
    if (core.identity.rob_generation != allocation->second.rob.generation ||
        core.rob_index != allocation->second.rob.index || core.pc != allocation->second.pc ||
        core.instruction != allocation->second.instruction ||
        core.uses_ldq != allocation->second.ldq.has_value() || core.uses_stq != allocation->second.stq.has_value())
      return invalid("BOOM physical retirement differs from its retained core/ROB allocation");
    if (!core.architectural) {
      auto result = adapter_.squash(instruction_id, allocation->second.rob, capture_source(frame.cycle));
      if (!result)
        return result;
    } else {
      std::optional<ProbeLoadRetirement> load;
      for (size_t index = 0; index < frame.retired_loads.size(); ++index) {
        const auto &candidate = frame.retired_loads[index];
        if (!same_instruction(core.identity, candidate.identity))
          continue;
        if (load || !used_retired_loads.insert(index).second)
          return invalid("BOOM retirement has duplicate final LDQ identities");
        load = candidate;
      }
      Retirement retirement;
      auto result = merge_retirement(configuration_.hart, core, allocation->second, load,
                                     configuration_.limits.ldq_slots, configuration_.limits.stq_slots,
                                     capture_source(frame.cycle), retirement);
      if (!result || !(result = adapter_.retire(retirement)))
        return result;
    }
    allocations_.erase(allocation);
    for (auto attempt = unresolved_samples_.begin(); attempt != unresolved_samples_.end();)
      if (attempt->first.first == instruction_id)
        attempt = unresolved_samples_.erase(attempt);
      else
        ++attempt;
  }
  if (used_retired_loads.size() != frame.retired_loads.size())
    return invalid("BOOM final LDQ result has no matching architectural retirement");
  return {};
}

CheckResult NativeCollector::capture_terminations(const NativeFrame &frame) {
  for (const auto &release : frame.store_releases) {
    auto result = adapter_.release_store_slot(id(release.identity), {release.queue_index, release.identity.memory_generation});
    if (!result)
      return result;
  }
  for (const auto &squash : frame.squashes) {
    const auto instruction_id = id(squash.identity);
    auto allocation = allocations_.find(instruction_id);
    if (allocation == allocations_.end() || allocation->second.rob.index != squash.rob_index ||
        allocation->second.rob.generation != squash.identity.rob_generation)
      return invalid("BOOM squash has no matching live ROB generation");
    auto result = adapter_.squash(instruction_id, allocation->second.rob, capture_source(frame.cycle));
    if (!result)
      return result;
    allocations_.erase(allocation);
    for (auto attempt = unresolved_samples_.begin(); attempt != unresolved_samples_.end();)
      if (attempt->first.first == instruction_id)
        attempt = unresolved_samples_.erase(attempt);
      else
        ++attempt;
  }
  return {};
}

CheckResult NativeCollector::validate_attempt(const NativeAttempt &attempt) const {
  auto allocation = allocations_.find(id(attempt.identity));
  if (allocation == allocations_.end() || !allocation->second.ldq ||
      allocation->second.rob.generation != attempt.identity.rob_generation ||
      allocation->second.ldq->generation != attempt.identity.memory_generation ||
      allocation->second.ldq->index != attempt.queue_index)
    return invalid("BOOM native load attempt has a stale ROB or LDQ identity");
  return {};
}

CheckResult NativeCollector::collect_adapter_output() {
  auto batch = adapter_.take_batch();
  staged_events_.insert(staged_events_.end(), batch.events.begin(), batch.events.end());
  auto retirements = adapter_.take_retirements();
  staged_retirements_.insert(staged_retirements_.end(), retirements.begin(), retirements.end());
  if (staged_events_.size() > configuration_.staged_events)
    return incomplete("BOOM source staging limit exceeded");
  return {};
}

CheckResult NativeCollector::take_ready(CollectedObservations &output) {
  if (!failure_)
    return failure_;
  if (!captured_cycle_)
    return pending("BOOM collector has not captured a complete source edge");
  uint64_t through = *captured_cycle_;
  for (const auto &attempt : unresolved_samples_) {
    if (!attempt.second)
      return pending("BOOM unresolved load can still sample cycle zero");
    through = std::min(through, attempt.second - 1);
  }
  if (closed_cycle_ && through <= *closed_cycle_)
    return pending("BOOM delayed load sample keeps the source prefix open");
  auto result = adapter_.close_prefix({hart_producer_id(configuration_.hart), SourcePosition::end_of_cycle(through)});
  if (!result)
    return result;
  adapter_.take_batch(); // The only generated record here is the checked hart watermark.
  std::stable_sort(staged_events_.begin(), staged_events_.end(), [](const RuntimeEvent &lhs, const RuntimeEvent &rhs) {
    return lhs.source.cycle < rhs.source.cycle;
  });
  CollectedObservations ready;
  std::map<OperationId, SourcePosition> retirement_positions;
  uint64_t next_sequence = emitted_sequence_;
  // The shared session certifies concurrent read prefixes and checks PPO ties.
  // This producer sequence preserves delivery identity, not subcycle GMO order.
  for (const auto &event : staged_events_) {
    if (event.source.cycle > through)
      continue;
    auto converted = event;
    if (event.producer_id == hart_producer_id(configuration_.hart)) {
      if (next_sequence == std::numeric_limits<uint64_t>::max())
        return remember_failure(invalid("BOOM public source sequence exhausted"));
      converted.source.producer_sequence = ++next_sequence;
    }
    if (event.kind == RuntimeEventKind::InstructionRetire) {
      const auto &retired = std::get<InstructionRetireEvent>(event.payload).instruction;
      retirement_positions[{retired.hart, retired.epoch, retired.uid, 0}] = converted.source;
    }
    ready.batch.events.push_back(std::move(converted));
  }
  for (const auto &retirement : staged_retirements_) {
    auto position = retirement_positions.find(retirement.id);
    if (position == retirement_positions.end())
      continue;
    ArchitecturalRetirement converted;
    result = convert_retirement_snapshot(retirement, converted);
    if (!result)
      return remember_failure(result);
    ready.retirements.push_back(converted);
  }
  ready.batch.watermarks.push_back({hart_producer_id(configuration_.hart), SourcePosition::end_of_cycle(through)});
  staged_events_.erase(std::remove_if(staged_events_.begin(), staged_events_.end(), [through](const RuntimeEvent &event) {
    return event.source.cycle <= through;
  }), staged_events_.end());
  staged_retirements_.erase(std::remove_if(staged_retirements_.begin(), staged_retirements_.end(),
      [&](const CapturedRetirement &event) { return retirement_positions.count(event.id); }), staged_retirements_.end());
  emitted_sequence_ = next_sequence;
  closed_cycle_ = through;
  output = std::move(ready);
  return {};
}

CheckResult NativeCollector::audit_reference_store(const ReferenceStoreAudit &reference) {
  if (!failure_)
    return failure_;
  auto result = adapter_.audit_reference_store(reference);
  if (result.status == CheckStatus::Pending)
    return result;
  return remember_failure(result);
}

CheckResult NativeCollector::completion() const {
  if (!failure_)
    return failure_;
  if (!captured_cycle_ || !closed_cycle_ || *closed_cycle_ != *captured_cycle_ ||
      !staged_events_.empty() || !staged_retirements_.empty() || !unresolved_samples_.empty() ||
      !allocations_.empty() || !queues_empty_ || !cache_idle_)
    return incomplete("BOOM source, instruction or cache observations have not drained");
  return adapter_.completion();
}

} // namespace boom
} // namespace rvwmo
