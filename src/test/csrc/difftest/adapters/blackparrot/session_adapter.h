#ifndef DIFFTEST_BLACKPARROT_SESSION_ADAPTER_H
#define DIFFTEST_BLACKPARROT_SESSION_ADAPTER_H

#include "adapter.h"
#include <cstddef>
#include <functional>
#include "../../rvwmo/session.h"
#include <vector>

namespace blackparrot {

inline constexpr size_t kMaximumCompleteCaptureBatchEvents = 32768;

struct NativeCapture;
struct NativeCompletionEvidence;

rvwmo::CheckResult validate_native_capture(const NativeCapture &capture);
rvwmo::CheckResult validate_native_completion(const NativeCompletionEvidence &evidence);

// Convert DUT actual snapshots only. The borrowed public session owns all REF
// execution, expected values, store audits, source-order ranks and checking.
rvwmo::CheckResult capture_architectural_retirements(
    const ConvertedOutput &converted, std::vector<rvwmo::ArchitecturalRetirement> &retirements);

using ClosedBatchSubmitter = std::function<rvwmo::SessionSubmitResult(
    const rvwmo::EventBatch &, const std::vector<rvwmo::ArchitecturalRetirement> &)>;
using SessionPoller = std::function<rvwmo::CheckResult()>;

// One-shot replay of a terminally complete capture in bounded source-cycle
// batches. Earlier batches may already be accepted when this returns failure;
// callers must not retry the full capture. The full native capture is retained.
rvwmo::SessionSubmitResult submit_converted_prefixes(
    const ConvertedOutput &converted, size_t max_events_per_batch,
    const ClosedBatchSubmitter &submit, const SessionPoller &poll);

class SessionAdapter {
public:
  // The session and its independent per-hart REF handles must outlive this object.
  explicit SessionAdapter(rvwmo::ObservationSession &session);

  // Gaps, malformed capture or unsupported metadata latch a failure. A caller
  // must not clear them merely to submit a capture. Watermarks in the exact
  // converted batch must close only genuinely delivered source prefixes.
  // Submit as one batch. The caller must keep this capture within stream capacity.
  rvwmo::SessionSubmitResult submit(const NativeCapture &capture);
  // Submit a completed capture in bounded prefixes; this remains a one-shot
  // terminal replay and does not release NativeBridge's full-run capture.
  rvwmo::SessionSubmitResult submit_complete_capture(const NativeCapture &capture);

  // For coordinator-prevalidated events/snapshots, including later source-prefix
  // closure or a selected sample delivered after its retirement. No watermark,
  // lifecycle event or architectural result is synthesized by this method.
  rvwmo::SessionSubmitResult submit_closed(
      const rvwmo::EventBatch &batch, const std::vector<rvwmo::ArchitecturalRetirement> &retirements);

  // Submit/check Pass is progress only. Only this method can record a final
  // Pass, after explicit native end proof and successful public finalization.
  rvwmo::CheckResult finalize(const NativeCompletionEvidence &evidence);
  bool finalized() const { return finalized_; }

private:
  rvwmo::ObservationSession &session_;
  rvwmo::CheckResult capture_failure_;
  bool finalized_ = false;

  rvwmo::SessionSubmitResult reject_capture(rvwmo::CheckResult failure);
};

// The borrowed adapter/session must outlive the native simulation.
ConversionResult install_native_session(Configuration configuration, SessionAdapter &adapter);

} // namespace blackparrot

#endif
