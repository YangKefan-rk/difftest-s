#include "session_adapter.h"
#include "cache_geometry.h"
#include "native_bridge.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>

namespace blackparrot {
namespace {
// A speculative SRAM read is not an irrevocable GMO witness. In particular,
// reversing W->R FENCE edges in those timestamps alone does not establish an
// illegal architectural execution. Reject this known certificate gap before
// the public session interprets the physical observations as model order.
rvwmo::CheckResult validate_fenced_array_samples(const NativeCapture &capture) {
  using AttemptKey = std::pair<rvwmo::OperationId, uint32_t>;
  std::map<AttemptKey, const NativeMemoryFact *> samples;
  std::map<AttemptKey, uint64_t> publications;
  std::map<rvwmo::OperationId, uint32_t> final_attempts;
  for (const auto &fact : capture.retirement_facts)
    final_attempts.emplace(fact.id, fact.attempt);
  for (const auto &fact : capture.memory_facts)
    if (fact.kind == 3)
      samples.emplace(AttemptKey{fact.id, fact.attempt}, &fact);
  for (const auto &proof : capture.coherence_facts)
    if (proof.proof_flags == 0x1f)
      publications.emplace(AttemptKey{proof.id, proof.attempt}, proof.source_time);

  std::map<rvwmo::OperationId, const RetireRecord *> retired;
  for (const auto &captured : capture.converted.retirements)
    retired.emplace(captured.architectural.id, &captured.architectural);
  uint64_t latest_store = 0;
  uint64_t fenced_stores = 0;
  std::optional<std::pair<uint32_t, uint64_t>> current_hart_epoch;
  for (const auto &entry : retired) {
    const auto &instruction = *entry.second;
    const auto hart_epoch = std::make_pair(entry.first.hart, entry.first.epoch);
    if (!current_hart_epoch || *current_hart_epoch != hart_epoch) {
      current_hart_epoch = hart_epoch;
      latest_store = 0;
      fenced_stores = 0;
    }
    const uint32_t encoding = instruction.instruction;
    const bool fence = instruction.length == 4 && (encoding & 0xf000707f) == 0x000f;
    const bool orders_write_read = fence && (encoding & (1u << 24)) && (encoding & (1u << 21));
    if (orders_write_read)
      fenced_stores = std::max(fenced_stores, latest_store);
    for (const auto &operation : instruction.memory) {
      const auto selected = final_attempts.find(instruction.id);
      if (selected == final_attempts.end() || selected->second != operation.attempt)
        return {rvwmo::CheckStatus::Incomplete, 0,
                "native memory effect lacks its final retired attempt for FENCE sampling validation"};
      const AttemptKey key{instruction.id, selected->second};
      if (operation.store) {
        const auto publication = publications.find(key);
        if (publication == publications.end())
          return {rvwmo::CheckStatus::Incomplete, 0,
                  "retired store lacks a qualified publication for FENCE sampling validation"};
        // Every preceding store matters, including disjoint addresses and an
        // earlier store that publishes later than the immediately preceding one.
        latest_store = std::max(latest_store, publication->second);
      }
      if (!operation.load || !fenced_stores)
        continue;
      const auto sample = samples.find(key);
      if (sample == samples.end())
        return {rvwmo::CheckStatus::Incomplete, 0,
                "retired load lacks its final byte sample for FENCE sampling validation"};
      const auto &fact = *sample->second;
      const uint32_t array_bytes = fact.mask & ~fact.forwarded_mask;
      if (array_bytes && (!fact.array_time || fact.array_time <= fenced_stores))
        return {rvwmo::CheckStatus::Incomplete, 0,
                "SRAM load sample crosses a W->R FENCE without an irrevocable or interval order certificate"};
    }
  }
  return {};
}

rvwmo::CheckResult validate_capture(const NativeCapture &capture) {
  using rvwmo::CheckStatus;
  if (capture.summary.malformed_transport)
    return {CheckStatus::Invalid, 0, "native capture reports malformed transport"};
  if (!capture.trap_facts.empty() || capture.summary.traps)
    return {CheckStatus::Unsupported, 0, "native trap/interrupt capture needs architectural session support"};
  if (std::any_of(capture.retirement_facts.begin(), capture.retirement_facts.end(),
                  [](const NativeRetirementFact &retirement) { return retirement.fp; }))
    return {CheckStatus::Unsupported, 0, "native floating-point retirement is outside the scalar integer session"};

  using DrainKey = std::tuple<rvwmo::OperationId, uint32_t, uint64_t, uint64_t>;
  std::map<DrainKey, size_t> physical_drains;
  for (const auto &fact : capture.memory_facts)
    if (fact.kind == 2)
      ++physical_drains[{fact.id, fact.attempt, fact.source_time, fact.address}];

  std::map<DrainKey, size_t> qualified_drains;
  std::map<DrainKey, size_t> coherence_records;
  for (const auto &proof : capture.coherence_facts) {
    const DrainKey key{proof.id, proof.attempt, proof.source_time, proof.address};
    if (++coherence_records[key] != 1)
      return {CheckStatus::Invalid, 0, "duplicate coherence proof for one physical store drain"};
    const auto drain = physical_drains.find(key);
    if (drain == physical_drains.end() || drain->second != 1)
      return {CheckStatus::Incomplete, 0, "coherence proof has no unique matching physical store drain"};
    if (proof.proof_flags != 0x1f)
      continue;
    if ((proof.address & 7) || proof.cache_set >= cache_geometry::kSetCount ||
        proof.cache_way >= cache_geometry::kWayCount ||
        !cache_geometry::is_one_hot_bank(proof.bank_select) ||
        proof.physical_sram_index >= cache_geometry::kPhysicalEntryCount)
      return {CheckStatus::Invalid, 0, "ordinary coherence proof has malformed cache or SRAM geometry"};

    const uint32_t physical_set = cache_geometry::set_for_physical_index(proof.physical_sram_index);
    const uint32_t expected_set = cache_geometry::set_for_address(proof.address);
    const uint32_t expected_way = cache_geometry::way_for_location(proof.bank_select,
                                                                   proof.physical_sram_index);
    if (physical_set != expected_set || proof.cache_set != expected_set || proof.cache_way != expected_way)
      return {CheckStatus::Invalid, 0,
              "coherence proof cache set/way differs from its PA and physical SRAM write location"};
    ++qualified_drains[key];
  }
  for (const auto &drain : physical_drains)
    if (drain.second != 1 || !qualified_drains.count(drain.first))
      return {CheckStatus::Incomplete, 0, "physical store drain lacks one qualified coherent SRAM location proof"};

  if (!capture.converted.diagnostics.empty()) {
    const auto &diagnostic = capture.converted.diagnostics.front();
    auto status = diagnostic.status;
    if (status == CheckStatus::Pending)
      status = CheckStatus::Incomplete;
    if (status == CheckStatus::Pass)
      status = CheckStatus::Invalid;
    return {status, 0, diagnostic.message.empty() ? "native conversion retains an unresolved diagnostic"
                                                 : diagnostic.message};
  }
  if (!capture.summary.gaps.empty())
    return {CheckStatus::Incomplete, 0, capture.summary.gaps.front()};
  if (capture.summary.incomplete)
    return {CheckStatus::Incomplete, 0, "native capture lacks complete observation and source-prefix evidence"};
  return validate_fenced_array_samples(capture);
}

rvwmo::EventValidationStatus transport_status(rvwmo::CheckStatus status) {
  switch (status) {
  case rvwmo::CheckStatus::Incomplete:
    return rvwmo::EventValidationStatus::Incomplete;
  case rvwmo::CheckStatus::Unsupported:
    return rvwmo::EventValidationStatus::Unsupported;
  default:
    return rvwmo::EventValidationStatus::Invalid;
  }
}

rvwmo::CheckResult validate_completion(const NativeCompletionEvidence &evidence) {
  using rvwmo::CheckStatus;
  if (!evidence.completed_cycle)
    return {CheckStatus::Incomplete, 0, "native finalization has no caller-proven completed source cycle"};
  if (!evidence.all_harts_completed)
    return {CheckStatus::Incomplete, 0, "native finalization lacks completion proof for every configured hart"};
  if (!evidence.observations_drained)
    return {CheckStatus::Incomplete, 0, "native finalization lacks complete observation delivery and source closure"};
  if (!evidence.memory_drained)
    return {CheckStatus::Incomplete, 0, "native finalization lacks completion of checked memory effects and their observation sources"};
  const auto &pending = evidence.pending;
  if (pending.instructions || pending.writebacks || pending.load_samples || pending.unpublished_stores)
    return {CheckStatus::Incomplete, 0, "native finalization retains instructions, writebacks, samples or unpublished stores"};
  return {};
}
} // namespace

rvwmo::CheckResult validate_native_capture(const NativeCapture &capture) { return validate_capture(capture); }
rvwmo::CheckResult validate_native_completion(const NativeCompletionEvidence &evidence) {
  return validate_completion(evidence);
}

rvwmo::CheckResult capture_architectural_retirements(
    const ConvertedOutput &converted, std::vector<rvwmo::ArchitecturalRetirement> &retirements) {
  retirements.clear();
  std::vector<rvwmo::ArchitecturalRetirement> snapshots;
  snapshots.reserve(converted.retirements.size());
  for (const auto &captured : converted.retirements) {
    const auto &actual = captured.architectural;
    if (!actual.id.uid || actual.id.subaccess || actual.pc % 2 || actual.rd >= 32 ||
        (actual.length != 2 && actual.length != 4))
      return {rvwmo::CheckStatus::Invalid, 0, "native architectural retirement has invalid identity, PC, length or rd"};
    if (!actual.integer_writeback && actual.register_value)
      return {rvwmo::CheckStatus::Invalid, 0, "native retirement carries a GPR value without integer writeback"};
    rvwmo::ArchitecturalRetirement snapshot;
    snapshot.id = actual.id;
    snapshot.pc = actual.pc;
    snapshot.instruction = actual.instruction;
    if (actual.integer_writeback && actual.rd != 0) {
      if (!actual.register_value)
        return {rvwmo::CheckStatus::Incomplete, 0, "native architectural retirement awaits its identified GPR writeback"};
      snapshot.destination = rvwmo::ArchitecturalDestination::Integer;
      snapshot.destination_register = actual.rd;
      snapshot.destination_value = *actual.register_value;
    }
    snapshots.push_back(snapshot);
  }
  retirements = std::move(snapshots);
  return {};
}

rvwmo::SessionSubmitResult submit_converted_prefixes(
    const ConvertedOutput &converted, size_t max_events_per_batch,
    const ClosedBatchSubmitter &submit, const SessionPoller &poll) {
  using rvwmo::CheckStatus;
  if (!max_events_per_batch || !submit || !poll) {
    rvwmo::SessionSubmitResult result;
    result.check = {CheckStatus::Invalid, 0, "prefix replay requires a nonzero batch bound and session callbacks"};
    return result;
  }

  std::vector<rvwmo::ArchitecturalRetirement> snapshots;
  const auto mapped = capture_architectural_retirements(converted, snapshots);
  if (!mapped) {
    rvwmo::SessionSubmitResult result;
    result.check = mapped;
    return result;
  }

  std::map<uint32_t, rvwmo::SourcePosition> final_watermarks;
  std::optional<uint64_t> final_cycle;
  for (const auto &watermark : converted.batch.watermarks) {
    if (!final_watermarks.emplace(watermark.producer_id, watermark.closed_through).second) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Invalid, 0, "completed capture contains duplicate producer watermarks"};
      return result;
    }
    if (final_cycle && *final_cycle != watermark.closed_through.cycle) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Incomplete, 0, "completed capture producers do not share one final source cycle"};
      return result;
    }
    final_cycle = watermark.closed_through.cycle;
    if (watermark.closed_through.qualified_phase != rvwmo::SourcePosition::cycle_closed_phase ||
        watermark.closed_through.producer_sequence != std::numeric_limits<uint64_t>::max() ||
        !watermark.closed_through.order_qualified) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Incomplete, 0, "completed capture watermark does not close its full source cycle"};
      return result;
    }
  }
  if (final_watermarks.empty()) {
    rvwmo::SessionSubmitResult result;
    result.check = {CheckStatus::Incomplete, 0, "completed capture has no source-prefix watermarks"};
    return result;
  }

  std::map<rvwmo::OperationId, const rvwmo::ArchitecturalRetirement *> snapshots_by_id;
  for (const auto &snapshot : snapshots)
    if (!snapshots_by_id.emplace(snapshot.id, &snapshot).second) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Invalid, 0, "completed capture contains duplicate retirement snapshots"};
      return result;
    }
  std::set<rvwmo::OperationId> matched_snapshots;
  std::map<rvwmo::OperationId, const CapturedRetirement *> captured_retirements_by_id;
  for (const auto &retirement : converted.retirements)
    if (!captured_retirements_by_id.emplace(retirement.architectural.id, &retirement).second) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Invalid, 0, "completed capture contains duplicate retirement provenance"};
      return result;
    }

  std::map<uint64_t, std::vector<const rvwmo::RuntimeEvent *>> events_by_cycle;
  for (const auto &event : converted.batch.events) {
    const auto watermark = final_watermarks.find(event.producer_id);
    if (watermark == final_watermarks.end()) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Incomplete, 0, "captured event producer has no final source watermark"};
      return result;
    }
    const auto coverage = rvwmo::compare_source_position(
        event.producer_id, event.source, watermark->first, watermark->second);
    if (coverage != rvwmo::SourceOrder::Before && coverage != rvwmo::SourceOrder::Equal) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Incomplete, 0, "final source watermark does not cover every captured event"};
      return result;
    }
    events_by_cycle[event.source.cycle].push_back(&event);
  }

  std::map<uint32_t, uint64_t> previous_sequences;
  for (const auto &cycle : events_by_cycle)
    for (const auto *event : cycle.second) {
      const auto previous = previous_sequences.find(event->producer_id);
      if (previous != previous_sequences.end() && event->source.producer_sequence <= previous->second) {
        rvwmo::SessionSubmitResult result;
        result.check = {CheckStatus::Invalid, 0, "captured producer sequence is not monotonic by source cycle"};
        return result;
      }
      previous_sequences[event->producer_id] = event->source.producer_sequence;
    }

  for (const auto &entry : events_by_cycle) {
    if (entry.second.size() > max_events_per_batch) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Incomplete, 0, "one complete source cycle exceeds the bounded replay batch"};
      return result;
    }
  }

  for (const auto &event : converted.batch.events) {
    if (event.kind != rvwmo::RuntimeEventKind::InstructionRetire)
      continue;
    const auto &retirement = std::get<rvwmo::InstructionRetireEvent>(event.payload).instruction;
    const rvwmo::OperationId id{retirement.hart, retirement.epoch, retirement.uid, 0};
    auto snapshot = snapshots_by_id.find(id);
    const auto captured = captured_retirements_by_id.find(id);
    if (snapshot == snapshots_by_id.end() || snapshot->second->pc != retirement.pc ||
        snapshot->second->instruction != retirement.instruction || captured == captured_retirements_by_id.end() ||
        captured->second->origin.producer_id != event.producer_id ||
        captured->second->origin.source.cycle != event.source.cycle ||
        captured->second->origin.source.qualified_phase != event.source.qualified_phase ||
        captured->second->origin.source.producer_sequence != event.source.producer_sequence ||
        captured->second->origin.source.order_qualified != event.source.order_qualified ||
        !matched_snapshots.insert(id).second) {
      rvwmo::SessionSubmitResult result;
      result.check = {CheckStatus::Invalid, 0,
                      "retirement event lacks a unique matching architectural snapshot and source position"};
      return result;
    }
  }
  if (matched_snapshots.size() != snapshots_by_id.size()) {
    rvwmo::SessionSubmitResult result;
    result.check = {CheckStatus::Incomplete, 0, "architectural snapshot has no matching retirement event"};
    return result;
  }

  rvwmo::EventBatch batch;
  batch.abi_version = converted.batch.abi_version;
  std::vector<rvwmo::ArchitecturalRetirement> batch_snapshots;
  rvwmo::SessionSubmitResult last_result;
  size_t batch_event_count = 0;
  size_t batch_index = 0;
  std::optional<uint64_t> batch_through;
  const auto set_watermarks = [&](uint64_t through) {
    batch.watermarks.clear();
    for (const auto &watermark : final_watermarks) {
      batch.watermarks.push_back(
          {watermark.first, rvwmo::SourcePosition::end_of_cycle(through)});
    }
  };
  const auto send_batch = [&]() -> bool {
    unsigned retries = 0;
    while (true) {
      auto result = submit(batch, batch_snapshots);
      if (std::getenv("BP_DIFFTEST_S_REPLAY_TRACE"))
        std::cerr << "[BP-DIFFTEST-S-REPLAY] batch=" << batch_index << " events=" << batch.events.size()
                  << " snapshots=" << batch_snapshots.size() << " through="
                  << (batch_through ? std::to_string(*batch_through) : "watermark-only")
                  << " accepted=" << result.accepted << " status=" << static_cast<unsigned>(result.check.status)
                  << " pending=" << result.pending_events << " retry=" << retries << '\n';
      if (result.accepted) {
        last_result = std::move(result);
        batch.events.clear();
        batch.watermarks.clear();
        batch_snapshots.clear();
        batch_event_count = 0;
        ++batch_index;
        return last_result.check.status == CheckStatus::Pass ||
               last_result.check.status == CheckStatus::Pending;
      }
      if (result.check.status != CheckStatus::Pending || retries++ == 4) {
        if (result.check.status == CheckStatus::Pending)
          result.check = {CheckStatus::Incomplete, result.check.rule,
                          "one-shot complete-capture replay could not accept its next prefix after polling"};
        last_result = std::move(result);
        return false;
      }
      const auto progress = poll();
      if (std::getenv("BP_DIFFTEST_S_REPLAY_TRACE"))
        std::cerr << "[BP-DIFFTEST-S-REPLAY] poll_status=" << static_cast<unsigned>(progress.status)
                  << " message=" << progress.message << '\n';
      if (!progress && progress.status != CheckStatus::Pending) {
        result.check = progress;
        last_result = std::move(result);
        return false;
      }
    }
  };

  for (const auto &cycle : events_by_cycle) {
    if (batch_event_count && batch_event_count + cycle.second.size() > max_events_per_batch) {
      set_watermarks(*batch_through);
      if (!send_batch())
        return last_result;
      batch_through.reset();
    }
    for (const auto *event : cycle.second) {
      batch.events.push_back(*event);
      ++batch_event_count;
      if (event->kind == rvwmo::RuntimeEventKind::InstructionRetire) {
        const auto &retirement = std::get<rvwmo::InstructionRetireEvent>(event->payload).instruction;
        const rvwmo::OperationId id{retirement.hart, retirement.epoch, retirement.uid, 0};
        auto snapshot = snapshots_by_id.find(id);
        if (snapshot == snapshots_by_id.end()) {
          rvwmo::SessionSubmitResult result;
          result.check = {CheckStatus::Invalid, 0, "retirement snapshot disappeared during prefix replay"};
          return result;
        }
        batch_snapshots.push_back(*snapshot->second);
      }
    }
    batch_through = cycle.first;
  }

  if (batch_through) {
    set_watermarks(*batch_through);
    if (!send_batch())
      return last_result;
  }

  // The complete terminal capture proves any remaining empty suffixes.
  batch.watermarks.clear();
  for (const auto &watermark : final_watermarks)
    batch.watermarks.push_back({watermark.first, watermark.second});
  if (!send_batch())
    return last_result;
  last_result.accepted = true;
  return last_result;
}

SessionAdapter::SessionAdapter(rvwmo::ObservationSession &session) : session_(session) {}

rvwmo::SessionSubmitResult SessionAdapter::reject_capture(rvwmo::CheckResult failure) {
  capture_failure_ = std::move(failure);
  finalized_ = false;
  rvwmo::SessionSubmitResult result;
  result.transport = {transport_status(capture_failure_.status), capture_failure_.message};
  result.check = capture_failure_;
  result.pending_events = session_.pending_events();
  return result;
}

rvwmo::SessionSubmitResult SessionAdapter::submit(const NativeCapture &capture) {
  if (!capture_failure_)
    return reject_capture(capture_failure_);
  const auto valid = validate_native_capture(capture);
  if (!valid)
    return reject_capture(valid);
  std::vector<rvwmo::ArchitecturalRetirement> retirements;
  const auto converted = capture_architectural_retirements(capture.converted, retirements);
  if (!converted)
    return reject_capture(converted);
  return submit_closed(capture.converted.batch, retirements);
}

rvwmo::SessionSubmitResult SessionAdapter::submit_complete_capture(const NativeCapture &capture) {
  finalized_ = false;
  if (!capture_failure_)
    return reject_capture(capture_failure_);
  const auto valid = validate_native_capture(capture);
  if (!valid)
    return reject_capture(valid);
  const auto completion = validate_native_completion(capture.completion);
  if (!completion)
    return reject_capture(completion);
  auto result = submit_converted_prefixes(
      capture.converted, kMaximumCompleteCaptureBatchEvents,
      [this](const rvwmo::EventBatch &batch, const std::vector<rvwmo::ArchitecturalRetirement> &retirements) {
        return submit_closed(batch, retirements);
      },
      [this]() { return session_.poll(); });
  if (!result.accepted && result.check.status != rvwmo::CheckStatus::Pass)
    return reject_capture(result.check);
  return result;
}

rvwmo::SessionSubmitResult SessionAdapter::submit_closed(
    const rvwmo::EventBatch &batch, const std::vector<rvwmo::ArchitecturalRetirement> &retirements) {
  if (!capture_failure_)
    return reject_capture(capture_failure_);
  auto result = session_.submit(batch, retirements);
  // A post-finalization rejection must also remove any cached final Pass.
  if (result.check.status != rvwmo::CheckStatus::Pass)
    finalized_ = false;
  return result;
}

rvwmo::CheckResult SessionAdapter::finalize(const NativeCompletionEvidence &evidence) {
  finalized_ = false;
  if (!capture_failure_)
    return capture_failure_;
  const auto progress = session_.poll();
  if (progress.status != rvwmo::CheckStatus::Pass && progress.status != rvwmo::CheckStatus::Pending)
    return progress;
  const auto complete = validate_native_completion(evidence);
  if (!complete)
    return complete;
  auto result = session_.finalize(*evidence.completed_cycle);
  if (result.status == rvwmo::CheckStatus::Pending)
    return {rvwmo::CheckStatus::Incomplete, result.rule, result.message};
  finalized_ = result.status == rvwmo::CheckStatus::Pass && session_.finalized();
  return result;
}

ConversionResult install_native_session(Configuration configuration, SessionAdapter &adapter) {
  return install_native_verifier(std::move(configuration), [&adapter](const NativeCapture &capture) {
    const auto submitted = adapter.submit_complete_capture(capture);
    if (!submitted.accepted || (submitted.check.status != rvwmo::CheckStatus::Pass &&
                               submitted.check.status != rvwmo::CheckStatus::Pending))
      return NativeVerification{submitted.check, false};
    const auto result = adapter.finalize(capture.completion);
    return NativeVerification{result, adapter.finalized()};
  });
}

} // namespace blackparrot
