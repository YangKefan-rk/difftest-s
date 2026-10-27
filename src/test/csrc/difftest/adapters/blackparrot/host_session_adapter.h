#ifndef DIFFTEST_BLACKPARROT_HOST_SESSION_ADAPTER_H
#define DIFFTEST_BLACKPARROT_HOST_SESSION_ADAPTER_H

#include "session_adapter.h"
#include <map>

namespace rvwmo {
class HostSession;
}

namespace blackparrot {

// The public host owns the fixed hart roster, references and completion state.
// This adapter supplies only the BlackParrot capture and observed end facts.
class HostSessionAdapter {
public:
  explicit HostSessionAdapter(rvwmo::HostSession &session);
  // Single-batch path; the caller must keep the capture within stream capacity.
  rvwmo::SessionSubmitResult submit(const NativeCapture &capture);
  // One-shot terminal replay in bounded event batches. NativeCapture stays resident.
  rvwmo::SessionSubmitResult submit_complete_capture(const NativeCapture &capture);
  rvwmo::SessionSubmitResult submit_closed(
      const rvwmo::EventBatch &batch, const std::vector<rvwmo::ArchitecturalRetirement> &retirements);
  rvwmo::CheckResult poll();
  rvwmo::CheckResult finalize(const NativeCompletionEvidence &evidence);
  rvwmo::CheckResult report_source_failure(rvwmo::CheckResult failure);
  bool finalized() const { return finalized_; }

private:
  rvwmo::HostSession &session_;
  rvwmo::CheckResult failure_;
  std::map<uint32_t, rvwmo::SourcePosition> watermarks_;
  bool boundaries_submitted_ = false;
  bool finalized_ = false;

  rvwmo::SessionSubmitResult reject_capture(rvwmo::CheckResult result);
};

// The adapter and its borrowed public host must outlive the native simulation.
ConversionResult install_native_host_session(Configuration configuration, HostSessionAdapter &adapter);
ConversionResult install_native_online_session(Configuration configuration, HostSessionAdapter &adapter);

} // namespace blackparrot

#endif
