#include "host_session_adapter.h"
#include "native_bridge.h"
#include "../../rvwmo/host_session.h"
#include <set>
#include <utility>

namespace blackparrot {

HostSessionAdapter::HostSessionAdapter(rvwmo::HostSession &session) : session_(session) {}

rvwmo::SessionSubmitResult HostSessionAdapter::reject_capture(rvwmo::CheckResult result) {
  failure_ = std::move(result);
  finalized_ = false;
  rvwmo::SessionSubmitResult rejected;
  rejected.check = failure_;
  const auto status = failure_.status == rvwmo::CheckStatus::Unsupported ? rvwmo::EventValidationStatus::Unsupported
                      : failure_.status == rvwmo::CheckStatus::Incomplete ? rvwmo::EventValidationStatus::Incomplete
                                                                        : rvwmo::EventValidationStatus::Invalid;
  rejected.transport = {status, failure_.message};
  return rejected;
}

rvwmo::SessionSubmitResult HostSessionAdapter::submit(const NativeCapture &capture) {
  if (!failure_)
    return reject_capture(failure_);
  const auto valid = validate_native_capture(capture);
  if (!valid)
    return reject_capture(valid);
  std::vector<rvwmo::ArchitecturalRetirement> snapshots;
  const auto converted = capture_architectural_retirements(capture.converted, snapshots);
  if (!converted)
    return reject_capture(converted);
  return submit_closed(capture.converted.batch, snapshots);
}

rvwmo::SessionSubmitResult HostSessionAdapter::submit_closed(
    const rvwmo::EventBatch &batch, const std::vector<rvwmo::ArchitecturalRetirement> &retirements) {
  if (!failure_)
    return reject_capture(failure_);
  const auto result = session_.submit(batch, retirements);
  if (result.accepted)
    for (const auto &watermark : batch.watermarks)
      watermarks_[watermark.producer_id] = watermark.closed_through;
  if (result.check.status != rvwmo::CheckStatus::Pass)
    finalized_ = false;
  return result;
}

rvwmo::CheckResult HostSessionAdapter::finalize(const NativeCompletionEvidence &evidence) {
  finalized_ = false;
  if (!failure_)
    return failure_;
  const auto valid = validate_native_completion(evidence);
  if (!valid)
    return valid;
  if (!boundaries_submitted_) {
    if (evidence.harts.empty())
      return {rvwmo::CheckStatus::Incomplete, 0, "native host has no observed per-hart completion records"};
    std::set<uint32_t> harts;
    for (const auto &hart : evidence.harts)
      if (!hart.terminal_uid || hart.source_cycle > *evidence.completed_cycle || !harts.insert(hart.hart).second) {
        failure_ = {rvwmo::CheckStatus::Invalid, 0, "native hart completion identity or source boundary is invalid"};
        return failure_;
      }
    for (const auto &hart : evidence.harts) {
      const auto complete = session_.complete_hart({hart.hart, hart.source_cycle, 0});
      if (!complete)
        return complete;
    }
    // Each separately observed producer closes its own prefix. Hart completion
    // cannot close a cache source or invent a memory ordering rank.
    for (const auto &watermark : watermarks_) {
      const auto drain = session_.drain_producer(
          {watermark.first, watermark.second.cycle, evidence.memory_drained, evidence.observations_drained});
      if (!drain)
        return drain;
    }
    boundaries_submitted_ = true;
  }
  auto result = session_.finalize(*evidence.completed_cycle);
  if (result.status == rvwmo::CheckStatus::Pending)
    result.status = rvwmo::CheckStatus::Incomplete;
  finalized_ = result.status == rvwmo::CheckStatus::Pass && session_.finalized();
  return result;
}

ConversionResult install_native_host_session(Configuration configuration, HostSessionAdapter &adapter) {
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
