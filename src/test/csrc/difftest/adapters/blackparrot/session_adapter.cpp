#include "session_adapter.h"
#include "native_bridge.h"
#include <algorithm>
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
    return {CheckStatus::Incomplete, 0, "native finalization lacks physical store/cache/coherence drain proof"};
  const auto &pending = evidence.pending;
  if (pending.instructions || pending.writebacks || pending.load_samples || pending.unpublished_stores)
    return {CheckStatus::Incomplete, 0, "native finalization retains instructions, writebacks, samples or unpublished stores"};
  return {};
}
} // namespace

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
  const auto valid = validate_capture(capture);
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
  const auto complete = validate_completion(evidence);
  if (!complete)
    return complete;
  auto result = session_.finalize(*evidence.completed_cycle);
  if (result.status == rvwmo::CheckStatus::Pending)
    return {rvwmo::CheckStatus::Incomplete, result.rule, result.message};
  finalized_ = result.status == rvwmo::CheckStatus::Pass && session_.finalized();
  return result;
}

} // namespace blackparrot
