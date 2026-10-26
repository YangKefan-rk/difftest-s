#include "spike_reference_pool.h"
#include <utility>

namespace rvwmo {

SpikeReferencePool::SpikeReferencePool(GlobalMem &memory, uint32_t profile_id,
                                       const std::vector<difftest_ref_state_v1> &initial_states)
    : memory_(memory) {
  if (initial_states.empty() || initial_states.size() > 1024 || memory_.size() == 0) {
    configuration_ = {CheckStatus::Invalid, 0, "reference pool requires initialized memory and 1..1024 hart states"};
    return;
  }
  references_.reserve(initial_states.size());
  std::vector<void *> handles;
  handles.reserve(initial_states.size());
  for (size_t hart = 0; hart < initial_states.size(); ++hart) {
    DifftestRefOptions options{};
    options.struct_size = sizeof(options);
    options.hart_id = static_cast<uint32_t>(hart);
    options.memory_size = memory_.size();
    options.physical_memory = {this, contains, read, reject_write};
    Reference reference(difftest_ref_create(&options));
    if (!reference) {
      configuration_ = {CheckStatus::Incomplete, 0, "Spike could not create a hart reference"};
      return;
    }
    handles.push_back(reference.get());
    references_.push_back(std::move(reference));
  }
  stepper_ = std::make_unique<SpikeReferenceStepper>(std::move(handles), profile_id);
  for (size_t hart = 0; hart < initial_states.size(); ++hart) {
    auto initialized = stepper_->initialize_hart(static_cast<uint32_t>(hart), initial_states[hart]);
    if (!initialized) {
      configuration_ = std::move(initialized);
      return;
    }
  }
}

SpikeReferencePool::~SpikeReferencePool() = default;

ObservationSession::ReferenceStepper SpikeReferencePool::callback() {
  if (!configuration_ || !stepper_) {
    const auto failure = configuration_;
    return [failure](const InstructionRetireEvent &, const ArchitecturalRetirement &,
                     const std::vector<ReferenceLoadValue> &) {
      ReferenceStepResult result;
      result.check = failure;
      return result;
    };
  }
  return stepper_->callback();
}

const difftest_ref_profile_v1 *SpikeReferencePool::profile(uint32_t hart) const {
  return configuration_ && stepper_ ? stepper_->profile(hart) : nullptr;
}

bool SpikeReferencePool::contains(void *context, uint64_t address, size_t size) {
  return static_cast<SpikeReferencePool *>(context)->memory_.contains(address, size);
}

bool SpikeReferencePool::read(void *context, uint64_t address, size_t size, uint8_t *bytes) {
  return static_cast<SpikeReferencePool *>(context)->memory_.read(address, bytes, size);
}

bool SpikeReferencePool::reject_write(void *, uint64_t, size_t, const uint8_t *) {
  // An unexpected REF physical write (for example a page-table A/D update)
  // needs its own observed DUT protocol before it can modify shared memory.
  return false;
}

} // namespace rvwmo
