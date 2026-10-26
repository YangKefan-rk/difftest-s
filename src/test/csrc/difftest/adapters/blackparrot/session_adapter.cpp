#include "session_adapter.h"
#include "cache_geometry.h"
#include "native_bridge.h"
#include <algorithm>
#include <map>
#include <tuple>
#include <utility>

namespace blackparrot {
namespace {
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
  return {};
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
    const auto submitted = adapter.submit(capture);
    if (!submitted.accepted || (submitted.check.status != rvwmo::CheckStatus::Pass &&
                               submitted.check.status != rvwmo::CheckStatus::Pending))
      return NativeVerification{submitted.check, false};
    const auto result = adapter.finalize(capture.completion);
    return NativeVerification{result, adapter.finalized()};
  });
}

} // namespace blackparrot
