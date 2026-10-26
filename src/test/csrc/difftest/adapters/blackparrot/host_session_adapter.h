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
  rvwmo::SessionSubmitResult submit(const NativeCapture &capture);
  rvwmo::SessionSubmitResult submit_closed(
      const rvwmo::EventBatch &batch, const std::vector<rvwmo::ArchitecturalRetirement> &retirements);
  rvwmo::CheckResult finalize(const NativeCompletionEvidence &evidence);
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

} // namespace blackparrot

#endif
