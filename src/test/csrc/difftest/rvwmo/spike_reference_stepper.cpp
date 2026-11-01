#include "spike_reference_stepper.h"
#include "dependency.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace rvwmo {
namespace {
CheckResult incomplete(const std::string &message) { return {CheckStatus::Incomplete, 0, message}; }
CheckResult invalid(const std::string &message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult violation(const std::string &message) { return {CheckStatus::Violation, 0, message}; }
CheckResult unsupported(const std::string &message) { return {CheckStatus::Unsupported, 0, message}; }

CheckResult operand_range(const MemoryOperation &operation, size_t &offset, size_t &width) {
  offset = 0;
  width = operation.byte_mask.size();
  if (operation.lr || operation.sc)
    return unsupported("Spike generic stepper requires a separate LR/SC reference contract");
  if (!operation.atomic) {
    if (width == 0 || width > sizeof(uint64_t) ||
        std::any_of(operation.byte_mask.begin(), operation.byte_mask.end(), [](uint8_t byte) { return byte != 1; }))
      return unsupported("Spike stepper requires a contiguous scalar operand");
    return {};
  }
  if (!operation.load || !operation.store || (operation.address & 7) || width != 8)
    return unsupported("Spike AMO reference requires one aligned W/D read-modify-write");
  uint8_t mask = 0;
  for (size_t byte = 0; byte < width; ++byte) {
    if (operation.byte_mask[byte] > 1)
      return invalid("AMO byte mask contains a value other than zero or one");
    mask |= operation.byte_mask[byte] << byte;
  }
  if (mask == 0xff)
    return {};
  if (mask != 0x0f && mask != 0xf0)
    return unsupported("Spike AMO reference requires low/high word or doubleword mask");
  offset = mask == 0xf0 ? 4 : 0;
  width = 4;
  return {};
}
} // namespace

SpikeReferenceStepper::SpikeReferenceStepper(std::vector<void *> hart_handles, uint32_t expected_profile_id)
    : harts_(hart_handles.size()) {
  for (size_t hart = 0; hart < hart_handles.size(); ++hart) {
    auto &state = harts_[hart];
    state.handle = hart_handles[hart];
    if (!state.handle) {
      state.setup_error = "Spike reference pool contains a null hart handle";
      continue;
    }
    if (difftest_ref_hart_id(state.handle) != hart) {
      state.setup_error = "Spike reference handle hart ID does not match its pool index";
      continue;
    }
    state.profile.abi_version = DIFFTEST_REF_PROFILE_ABI_VERSION_1;
    state.profile.struct_size = sizeof(state.profile);
    const int profile_status = difftest_ref_get_profile_v1(state.handle, &state.profile);
    state.profile_id.abi_version = DIFFTEST_REF_PROFILE_ID_ABI_VERSION_1;
    state.profile_id.struct_size = sizeof(state.profile_id);
    const int profile_id_status = difftest_ref_get_profile_id_v1(state.handle, &state.profile_id);
    const uint64_t required_capabilities = DIFFTEST_REF_CAP_EXTERNAL_MEMORY | DIFFTEST_REF_CAP_STATE_V1 |
                                           DIFFTEST_REF_CAP_OBSERVER_V2;
    if (profile_status != DIFFTEST_REF_API_OK || profile_id_status != DIFFTEST_REF_API_OK ||
        state.profile.hart_id != hart || state.profile_id.profile_id != expected_profile_id ||
        state.profile.xlen != 64 || state.profile.flen != 64 ||
        (state.profile.capabilities & required_capabilities) != required_capabilities ||
        !std::memchr(state.profile.isa, '\0', sizeof(state.profile.isa)) ||
        !std::memchr(state.profile_id.profile_name, '\0', sizeof(state.profile_id.profile_name))) {
      state.setup_error = "Spike profile does not support the versioned RV64 scalar reference API";
      continue;
    }
    if (difftest_ref_set_load_reader(state.handle, read_modeled_load, &state) != DIFFTEST_REF_API_OK) {
      state.setup_error = "Spike rejected a per-hart reference callback";
      continue;
    }
    if (difftest_ref_set_instruction_observer_v2(state.handle, observe_retirement, &state) != DIFFTEST_REF_API_OK) {
      difftest_ref_set_load_reader(state.handle, nullptr, nullptr);
      state.setup_error = "Spike rejected a per-hart reference callback";
      continue;
    }
    state.callbacks_installed = true;
  }
}

SpikeReferenceStepper::~SpikeReferenceStepper() {
  for (auto &state : harts_) {
    if (!state.handle || !state.callbacks_installed)
      continue;
    difftest_ref_set_load_reader(state.handle, nullptr, nullptr);
    difftest_ref_set_instruction_observer_v2(state.handle, nullptr, nullptr);
  }
}

CheckResult SpikeReferenceStepper::initialize_hart(uint32_t hart, const difftest_ref_state_v1 &initial_state) {
  if (hart >= harts_.size())
    return invalid("Spike reference initialization names an unregistered hart");
  auto &state = harts_[hart];
  if (!state.setup_error.empty())
    return incomplete(state.setup_error);
  if (state.initialized)
    return invalid("Spike hart state may only be initialized once per observation session");
  auto copy = initial_state;
  copy.abi_version = DIFFTEST_REF_STATE_ABI_VERSION_1;
  copy.struct_size = sizeof(copy);
  const int status = difftest_ref_set_state_v1(state.handle, &copy);
  if (status == DIFFTEST_REF_API_UNSUPPORTED)
    return unsupported("Spike profile does not support scalar reference-state initialization");
  if (status != DIFFTEST_REF_API_OK)
    return incomplete("Spike rejected the initial architectural state");
  state.initialized = true;
  return {};
}

const difftest_ref_profile_v1 *SpikeReferenceStepper::profile(uint32_t hart) const {
  if (hart >= harts_.size() || !harts_[hart].setup_error.empty())
    return nullptr;
  return &harts_[hart].profile;
}

ObservationSession::ReferenceStepper SpikeReferenceStepper::callback() {
  return [this](const InstructionRetireEvent &retirement, const ArchitecturalRetirement &snapshot,
                const std::vector<ReferenceLoadValue> &loads) { return step(retirement, snapshot, loads); };
}

bool SpikeReferenceStepper::read_modeled_load(void *context, uint64_t address, size_t size, uint8_t *bytes) {
  auto &state = *static_cast<HartState *>(context);
  if (!state.active || !bytes || state.consumed_loads >= state.expected_loads.size()) {
    state.callback_error = "Spike requested a load absent from the modeled retirement";
    return false;
  }
  const auto &request = state.expected_loads[state.consumed_loads];
  if (address != request.address || size != request.expected_bytes.size()) {
    state.callback_error = "Spike translated load address or width differs from the modeled read";
    state.callback_status = CheckStatus::Violation;
    return false;
  }
  std::copy(request.expected_bytes.begin(), request.expected_bytes.end(), bytes);
  ++state.consumed_loads;
  return true;
}

void SpikeReferenceStepper::observe_retirement(void *context, uint64_t pc, uint32_t instruction,
                                              uint8_t wrote_integer, uint8_t destination, uint64_t value) {
  auto &state = *static_cast<HartState *>(context);
  if (!state.active || state.observed_instruction || wrote_integer > 1 || destination > 31) {
    state.callback_error = "Spike produced an unexpected or duplicate instruction observation";
    return;
  }
  state.observed_instruction = true;
  state.observed_pc = pc;
  state.observed_raw = instruction;
  state.wrote_integer = wrote_integer && destination != 0;
  state.destination = state.wrote_integer ? destination : 0;
  state.value = state.wrote_integer ? value : 0;
}

CheckResult SpikeReferenceStepper::collect_loads(const InstructionRetireEvent &retirement,
                                                 const std::vector<ReferenceLoadValue> &modeled_loads,
                                                 std::vector<LoadRequest> &requests) {
  for (const auto &operation : retirement.instruction.memory) {
    if (!operation.load)
      continue;
    if (operation.store && !operation.atomic)
      return unsupported("Spike stepper requires an ordinary load or an AMO read");
    auto modeled = std::find_if(modeled_loads.begin(), modeled_loads.end(), [&](const auto &load) {
      return load.id == operation.id && load.attempt == operation.attempt;
    });
    if (modeled == modeled_loads.end() || modeled->expected_bytes.size() != operation.byte_mask.size())
      return incomplete("retired load has no exact modeled byte value");
    size_t offset = 0, width = 0;
    auto checked = operand_range(operation, offset, width);
    if (!checked)
      return checked;
    const auto first = modeled->expected_bytes.begin() + offset;
    requests.push_back({operation.id, operation.attempt, operation.address + offset,
                       std::vector<uint8_t>(first, first + width)});
  }
  if (requests.size() != modeled_loads.size())
    return invalid("modeled load list contains an operation absent from the retirement");
  return {};
}

CheckResult SpikeReferenceStepper::collect_store(void *handle, const MemoryOperation &operation,
                                                 ReferenceStoreValue &store) {
  if (!operation.store)
    return unsupported("Spike stepper requires a store effect");
  size_t operand_offset = 0, operand_width = 0;
  auto operand = operand_range(operation, operand_offset, operand_width);
  if (!operand)
    return operand;

  uint64_t trace_address = 0;
  uint64_t trace_data = 0;
  uint8_t trace_mask = 0;
  const auto take_trace = operation.atomic ? difftest_ref_take_atomic_store_trace_v1
                                           : difftest_ref_take_store_trace;
  if (take_trace(handle, &trace_address, &trace_data, &trace_mask) != 0)
    return incomplete("Spike produced no reference store trace for the retired store");
  if (operation.address < trace_address || operation.address - trace_address >= sizeof(uint64_t))
    return violation("Spike store trace address does not cover the retired store");

  const size_t offset = static_cast<size_t>(operation.address - trace_address);
  if (offset + operation.byte_mask.size() > sizeof(uint64_t))
    return unsupported("Spike store trace crosses its aligned reference word");
  uint8_t expected_mask = 0;
  for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte) {
    if (operation.byte_mask[byte] > 1)
      return invalid("store byte mask contains a value other than zero or one");
    expected_mask |= static_cast<uint8_t>(operation.byte_mask[byte] << (offset + byte));
  }
  if (trace_mask != expected_mask)
    return violation("Spike store byte mask differs from the retired store operation");

  store.id = operation.id;
  store.address = operation.address;
  store.byte_mask = operation.byte_mask;
  store.bytes.resize(operation.byte_mask.size());
  for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte)
    store.bytes[byte] = static_cast<uint8_t>(trace_data >> ((offset + byte) * 8));

  if (take_trace(handle, &trace_address, &trace_data, &trace_mask) == 0)
    return unsupported("Spike store instruction generated more than one store trace");
  return {};
}

ReferenceStepResult SpikeReferenceStepper::step(const InstructionRetireEvent &retirement,
                                               const ArchitecturalRetirement &snapshot,
                                               const std::vector<ReferenceLoadValue> &modeled_loads) {
  ReferenceStepResult result;
  const auto hart = retirement.instruction.hart;
  if (hart >= harts_.size()) {
    result.check = invalid("retirement hart has no Spike reference handle");
    return result;
  }
  auto &state = harts_[hart];
  if (!state.setup_error.empty()) {
    result.check = incomplete(state.setup_error);
    return result;
  }
  if (!state.initialized) {
    result.check = incomplete("Spike hart reference has not received its initial architectural state");
    return result;
  }
  if (state.poisoned) {
    result.check = state.failure;
    return result;
  }
  if (snapshot.id.hart != hart || snapshot.id.epoch != retirement.instruction.epoch ||
      snapshot.id.uid != retirement.instruction.uid || snapshot.pc != retirement.instruction.pc ||
      snapshot.instruction != retirement.instruction.instruction) {
    result.check = invalid("architectural snapshot does not match the retirement identity");
    return result;
  }
  for (const auto &operation : retirement.instruction.memory) {
    if (!operation.atomic && !operation.lr && !operation.sc)
      continue;
    if (operation.atomic && !(state.profile.capabilities & DIFFTEST_REF_CAP_ATOMIC_STORE_TRACE_V1)) {
      result.check = unsupported("Spike profile lacks independent atomic store trace support");
      return result;
    }
    size_t offset = 0, width = 0;
    result.check = operand_range(operation, offset, width);
    if (!result.check)
      return result;
  }

  FloatingPointInstruction floating;
  const auto decoded_fp = decode_floating_point_instruction(retirement.instruction.instruction, floating);
  if (!decoded_fp) {
    result.check = decoded_fp;
    return result;
  }

  difftest_ref_state_v1 before{};
  before.abi_version = DIFFTEST_REF_STATE_ABI_VERSION_1;
  before.struct_size = sizeof(before);
  const int before_status = difftest_ref_get_state_v1(state.handle, &before);
  if (before_status == DIFFTEST_REF_API_UNSUPPORTED) {
    result.check = unsupported("Spike profile does not expose scalar reference state");
    return result;
  }
  if (before_status != DIFFTEST_REF_API_OK) {
    result.check = incomplete("Spike failed to expose its pre-step architectural state");
    return result;
  }
  if (before.pc != retirement.instruction.pc) {
    result.check = violation("Spike reference PC is not at the DUT retirement PC");
    return result;
  }

  state.expected_loads.clear();
  state.consumed_loads = 0;
  state.callback_error.clear();
  state.callback_status = CheckStatus::Invalid;
  state.observed_instruction = false;
  state.observed_pc = 0;
  state.observed_raw = 0;
  state.wrote_integer = false;
  state.destination = 0;
  state.value = 0;
  auto loads = collect_loads(retirement, modeled_loads, state.expected_loads);
  if (!loads) {
    result.check = loads;
    return result;
  }

  size_t stores = 0, atomic_stores = 0;
  for (const auto &operation : retirement.instruction.memory) {
    if (!operation.store)
      continue;
    if (operation.atomic)
      ++atomic_stores;
    else
      ++stores;
  }
  if (stores + atomic_stores > 1) {
    result.check = unsupported("generic Spike reference step supports at most one store per instruction");
    return result;
  }

  uint64_t pending_stores = 0;
  if (difftest_ref_pending_store_traces_v1(state.handle, &pending_stores) != DIFFTEST_REF_API_OK) {
    result.check = incomplete("Spike could not report pending reference store traces");
    return result;
  }
  uint64_t pending_atomics = 0;
  const bool atomic_trace_capability = state.profile.capabilities & DIFFTEST_REF_CAP_ATOMIC_STORE_TRACE_V1;
  if (atomic_trace_capability &&
      difftest_ref_pending_atomic_store_traces_v1(state.handle, &pending_atomics) != DIFFTEST_REF_API_OK) {
    result.check = incomplete("Spike could not report pending atomic store traces");
    return result;
  }
  if (pending_stores != 0 || pending_atomics != 0) {
    state.poisoned = true;
    state.failure = incomplete("Spike reference has an unassociated store trace before this retirement");
    result.check = state.failure;
    return result;
  }

  state.active = true;
  const int stepped = difftest_ref_step(state.handle, 1);
  state.active = false;
  auto fail_after_step = [&](CheckResult failure) {
    state.poisoned = true;
    state.failure = failure;
    result.check = std::move(failure);
    return result;
  };
  if (!state.callback_error.empty()) {
    return fail_after_step({state.callback_status, 0, state.callback_error});
  }
  if (stepped != 0) {
    return fail_after_step(unsupported("Spike step failed; trap, interrupt, MMIO, or unsupported execution is outside this profile"));
  }
  if (state.consumed_loads != state.expected_loads.size()) {
    return fail_after_step(incomplete("Spike did not consume every modeled load exactly once"));
  }
  if (!state.observed_instruction) {
    return fail_after_step(incomplete("Spike did not report a committed instruction for the single step"));
  }
  if (state.observed_pc != retirement.instruction.pc ||
      state.observed_raw != retirement.instruction.instruction || state.observed_raw != snapshot.instruction) {
    return fail_after_step(violation("Spike executed a different PC or instruction than the DUT retirement"));
  }
  result.reference_pc = state.observed_pc;
  result.reference_instruction = state.observed_raw;
  if (state.wrote_integer)
    result.integer_write = ReferenceIntegerWrite{state.destination, state.value};

  difftest_ref_state_v1 after{};
  after.abi_version = DIFFTEST_REF_STATE_ABI_VERSION_1;
  after.struct_size = sizeof(after);
  const int after_status = difftest_ref_get_state_v1(state.handle, &after);
  if (after_status == DIFFTEST_REF_API_UNSUPPORTED)
    return fail_after_step(unsupported("Spike profile does not expose scalar reference state"));
  if (after_status != DIFFTEST_REF_API_OK) {
    return fail_after_step(incomplete("Spike failed to expose its post-step architectural state"));
  }
  if (state.wrote_integer && after.gpr[state.destination] != state.value) {
    return fail_after_step(invalid("Spike retirement observer differs from its post-step integer register state"));
  }
  if (floating.recognized) {
    if (state.wrote_integer != floating.writes_integer ||
        (state.wrote_integer && state.destination != floating.destination))
      return fail_after_step(invalid("Spike floating-point instruction write class differs from its decoded effects"));
    if (floating.writes_floating_point)
      result.floating_point_write = ReferenceFloatingPointWrite{floating.destination, after.fpr[floating.destination]};
  }
  if (after.fcsr > UINT64_C(0xff))
    return fail_after_step(invalid("Spike exposed FCSR bits outside its architectural width"));
  result.fcsr = static_cast<uint8_t>(after.fcsr);
  if (difftest_ref_pending_store_traces_v1(state.handle, &pending_stores) != DIFFTEST_REF_API_OK) {
    return fail_after_step(incomplete("Spike could not report post-step reference store traces"));
  }
  if (atomic_trace_capability &&
      difftest_ref_pending_atomic_store_traces_v1(state.handle, &pending_atomics) != DIFFTEST_REF_API_OK)
    return fail_after_step(incomplete("Spike could not report post-step atomic store traces"));
  if (pending_stores != stores || pending_atomics != atomic_stores) {
    return fail_after_step(violation("Spike ordinary/atomic store trace counts differ from retired memory effects"));
  }
  for (const auto &operation : retirement.instruction.memory) {
    if (!operation.store)
      continue;
    ReferenceStoreValue store;
    auto checked = collect_store(state.handle, operation, store);
    if (!checked) {
      return fail_after_step(checked);
    }
    result.stores.push_back(std::move(store));
  }
  return result;
}

} // namespace rvwmo
