#ifndef DIFFTEST_RVWMO_SPIKE_REFERENCE_POOL_H
#define DIFFTEST_RVWMO_SPIKE_REFERENCE_POOL_H

#include "../globalmem.h"
#include "spike_reference_stepper.h"
#include <memory>
#include <vector>

namespace rvwmo {

// Owns one reference per hart over independently initialized GlobalMem. Ordinary
// stores produce REF audit traces; only the checker publishes into GlobalMem.
// The backing memory must outlive this pool. Destroy sessions using its callback
// before destroying the pool.
class SpikeReferencePool {
public:
  SpikeReferencePool(GlobalMem &memory, uint32_t profile_id,
                     const std::vector<difftest_ref_state_v1> &initial_states);
  ~SpikeReferencePool();
  SpikeReferencePool(const SpikeReferencePool &) = delete;
  SpikeReferencePool &operator=(const SpikeReferencePool &) = delete;

  const CheckResult &configuration() const { return configuration_; }
  ObservationSession::ReferenceStepper callback();
  const difftest_ref_profile_v1 *profile(uint32_t hart) const;
  size_t hart_count() const { return references_.size(); }

private:
  struct ReferenceDeleter {
    void operator()(void *reference) const { difftest_ref_destroy(reference); }
  };
  using Reference = std::unique_ptr<void, ReferenceDeleter>;

  GlobalMem &memory_;
  std::vector<Reference> references_;
  // Destroyed before references so callbacks are removed before handle teardown.
  std::unique_ptr<SpikeReferenceStepper> stepper_;
  CheckResult configuration_;

  static bool contains(void *context, uint64_t address, size_t size);
  static bool read(void *context, uint64_t address, size_t size, uint8_t *bytes);
  static bool reject_write(void *context, uint64_t address, size_t size, const uint8_t *bytes);
};

} // namespace rvwmo

#endif
