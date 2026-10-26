#ifndef DIFFTEST_BLACKPARROT_SESSION_ADAPTER_H
#define DIFFTEST_BLACKPARROT_SESSION_ADAPTER_H

#include "adapter.h"
#include "../../rvwmo/session.h"
#include <optional>
#include <vector>

namespace blackparrot {

struct NativeCapture;

// Convert DUT actual snapshots only. The borrowed public session owns all REF
// execution, expected values, store audits, source-order ranks and checking.
rvwmo::CheckResult capture_architectural_retirements(
    const ConvertedOutput &converted, std::vector<rvwmo::ArchitecturalRetirement> &retirements);

// The native coordinator must prove these facts for the whole configured hart
// and observation-producer roster. Counts, heartbeat and native finish alone do
// not establish completion, source closure or cache/coherence drain.
struct NativeCompletionEvidence {
  std::optional<uint64_t> completed_cycle;
  bool all_harts_completed = false;
  bool observations_drained = false;
  bool memory_drained = false;
  PendingState pending;
};

class SessionAdapter {
public:
  // The session and its independent per-hart REF handles must outlive this object.
  explicit SessionAdapter(rvwmo::ObservationSession &session);

  // Gaps, malformed capture or unsupported metadata latch a failure. A caller
  // must not clear them merely to submit a capture. Watermarks in the exact
  // converted batch must close only genuinely delivered source prefixes.
  rvwmo::SessionSubmitResult submit(const NativeCapture &capture);

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

} // namespace blackparrot

#endif
