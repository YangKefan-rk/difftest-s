#ifndef DIFFTEST_RVWMO_HOST_SESSION_H
#define DIFFTEST_RVWMO_HOST_SESSION_H

#include "spike_reference_pool.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace rvwmo {

struct HostSessionConfiguration {
  std::string platform;
  uint32_t reference_profile = DIFFTEST_REF_PROFILE_ID_UNKNOWN;
  StreamContract stream;
  std::vector<ProducerCapability> producers;
  std::vector<difftest_ref_state_v1> initial_harts;
};

struct HartCompletion {
  uint32_t hart = 0;
  uint64_t source_cycle = 0;
  int32_t exit_code = 0;
};

struct ProducerDrain {
  uint32_t producer_id = 0;
  uint64_t source_cycle = 0;
  // Set only after the source observer and native adapter have delivered every
  // earlier fact and have no in-flight work that can generate a later fact.
  bool physically_idle = false;
  bool fully_delivered = false;
};

// Common native-host owner. DUT adapters provide typed events and explicit
// completion/drain evidence; this class owns REF instances and final checks.
// Its GlobalMem must be independently loaded before construction and outlive it.
class HostSession {
public:
  HostSession(GlobalMem &memory, HostSessionConfiguration configuration);
  const CheckResult &configuration() const { return failure_; }
  SessionSubmitResult submit(const EventBatch &batch,
                             const std::vector<ArchitecturalRetirement> &retirements = {});
  CheckResult complete_hart(const HartCompletion &completion);
  CheckResult drain_producer(const ProducerDrain &drain);
  CheckResult poll();
  CheckResult finalize(uint64_t completed_cycle);
  bool finalized() const { return finalized_; }
  const ObservationSession *session() const { return session_.get(); }

private:
  GlobalMem &memory_;
  HostSessionConfiguration configuration_;
  SpikeReferencePool references_;
  std::unique_ptr<ObservationSession> session_;
  std::map<uint32_t, HartCompletion> completed_harts_;
  std::map<uint32_t, ProducerDrain> drained_producers_;
  std::map<uint32_t, SourcePosition> source_watermarks_;
  std::map<uint32_t, uint64_t> last_source_cycles_;
  std::map<uint32_t, uint64_t> last_architectural_cycles_;
  CheckResult failure_;
  bool finalized_ = false;

  CheckResult reject(CheckResult result);
  CheckResult validate_batch(const EventBatch &batch) const;
  bool registered_hart(uint32_t hart) const;
};

} // namespace rvwmo

#endif
