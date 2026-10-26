#ifndef DIFFTEST_RVWMO_SPIKE_REFERENCE_STEPPER_H
#define DIFFTEST_RVWMO_SPIKE_REFERENCE_STEPPER_H

#include "session.h"
#include "difftest/ref_api.h"

#include <string>
#include <vector>

namespace rvwmo {

class SpikeReferenceStepper {
public:
  // Handles are borrowed and must remain alive until after this stepper is destroyed.
  SpikeReferenceStepper(std::vector<void *> hart_handles, uint32_t expected_profile_id);
  ~SpikeReferenceStepper();

  SpikeReferenceStepper(const SpikeReferenceStepper &) = delete;
  SpikeReferenceStepper &operator=(const SpikeReferenceStepper &) = delete;

  CheckResult initialize_hart(uint32_t hart, const difftest_ref_state_v1 &initial_state);
  const difftest_ref_profile_v1 *profile(uint32_t hart) const;
  ObservationSession::ReferenceStepper callback();

private:
  struct LoadRequest {
    OperationId id;
    uint32_t attempt = 0;
    uint64_t address = 0;
    std::vector<uint8_t> expected_bytes;
  };

  struct HartState {
    void *handle = nullptr;
    difftest_ref_profile_v1 profile{};
    difftest_ref_profile_id_v1 profile_id{};
    bool initialized = false;
    bool callbacks_installed = false;
    bool active = false;
    bool poisoned = false;
    CheckResult failure;
    std::vector<LoadRequest> expected_loads;
    size_t consumed_loads = 0;
    CheckStatus callback_status = CheckStatus::Invalid;
    std::string callback_error;
    bool observed_instruction = false;
    uint64_t observed_pc = 0;
    uint32_t observed_raw = 0;
    bool wrote_integer = false;
    uint8_t destination = 0;
    uint64_t value = 0;
    std::string setup_error;
  };

  std::vector<HartState> harts_;

  ReferenceStepResult step(const InstructionRetireEvent &retirement, const ArchitecturalRetirement &snapshot,
                           const std::vector<ReferenceLoadValue> &modeled_loads);
  static bool read_modeled_load(void *context, uint64_t address, size_t size, uint8_t *bytes);
  static void observe_retirement(void *context, uint64_t pc, uint32_t instruction, uint8_t wrote_integer,
                                 uint8_t destination, uint64_t value);
  static CheckResult collect_loads(const InstructionRetireEvent &retirement,
                                   const std::vector<ReferenceLoadValue> &modeled_loads,
                                   std::vector<LoadRequest> &requests);
  static CheckResult collect_store(void *handle, const MemoryOperation &operation, ReferenceStoreValue &store);
};

} // namespace rvwmo

#endif
