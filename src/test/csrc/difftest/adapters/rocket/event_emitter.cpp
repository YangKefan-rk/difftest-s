#include "event_emitter.h"
#include "../../rvwmo/producer_ids.h"
#include "../../rvwmo/stream.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace rocket_difftest {
using namespace rvwmo;

EventEmitter::EventEmitter(EmitterConfiguration configuration) : configuration_(configuration) {
  if (!configuration_.producer || configuration_.producer != hart_producer_id(configuration_.hart) ||
      configuration_.capacity < 3)
    reject(CheckStatus::Invalid, "Rocket emitter requires its registered hart producer and capacity >= 3");
  if (configuration_.publication_producer && configuration_.publication_producer < kMemoryFabricProducerBase)
    reject(CheckStatus::Invalid, "Rocket publications require a registered memory-fabric producer");
  if (configuration_.xlen != 64)
    reject(CheckStatus::Unsupported, "Rocket emitter currently requires an RV64 configuration");
}

CheckResult EventEmitter::reject(CheckStatus status, const char *message) {
  failure_ = {status, 0, message};
  return failure_;
}

CheckResult EventEmitter::validate_source(const SourcePosition &source) {
  if (!failure_)
    return failure_;
  if (source.qualified_phase == SourcePosition::cycle_closed_phase || !source.producer_sequence)
    return reject(CheckStatus::Invalid, "Rocket observation uses an invalid source position");
  if (closed_cycle_ && source.cycle <= *closed_cycle_)
    return reject(CheckStatus::Invalid, "Rocket observation arrived after its source prefix was closed");
  return {};
}

CheckResult EventEmitter::validate_access(uint64_t address, const std::vector<uint8_t> &bytes,
                                         const std::vector<uint8_t> &mask) {
  if (bytes.empty() || bytes.size() > 8 || mask.size() != bytes.size() ||
      std::none_of(mask.begin(), mask.end(), [](uint8_t byte) { return byte != 0; }) ||
      std::any_of(mask.begin(), mask.end(), [](uint8_t byte) { return byte > 1; }) ||
      address > std::numeric_limits<uint64_t>::max() - (bytes.size() - 1))
    return reject(CheckStatus::Invalid, "Rocket scalar access has invalid byte extent or mask");
  return {};
}

EventEmitter::MemoryKind EventEmitter::memory_kind(uint32_t instruction, uint8_t length) {
  if (length == 2) {
    const auto quadrant = instruction & 3;
    const auto function = (instruction >> 13) & 7;
    if ((quadrant == 0 || quadrant == 2) && (function == 2 || function == 3))
      return MemoryKind::Load;
    if ((quadrant == 0 || quadrant == 2) && (function == 6 || function == 7))
      return MemoryKind::Store;
    if ((quadrant == 0 || quadrant == 2) && function == 1)
      return MemoryKind::Load; // RV64D C.FLD and C.FLDSP.
    if ((quadrant == 0 || quadrant == 2) && function == 5)
      return MemoryKind::Store; // RV64D C.FSD and C.FSDSP.
    return MemoryKind::None;
  }
  if (length != 4)
    return MemoryKind::Unsupported;
  if (((instruction & 0x7f) == 0x73 && ((instruction >> 25) & 0x7f) == 0x7e) ||
      ((instruction & 0x7f) == 0x0f && ((instruction >> 12) & 7) == 2))
    return MemoryKind::Unsupported; // Cache-block maintenance instructions.
  switch (instruction & 0x7f) {
  case 0x03: return ((instruction >> 12) & 7) <= 6 ? MemoryKind::Load : MemoryKind::Unsupported;
  case 0x23: return ((instruction >> 12) & 7) <= 3 ? MemoryKind::Store : MemoryKind::Unsupported;
  case 0x07: return ((instruction >> 12) & 7) == 2 || ((instruction >> 12) & 7) == 3
                     ? MemoryKind::Load : MemoryKind::Unsupported;
  case 0x27: return ((instruction >> 12) & 7) == 2 || ((instruction >> 12) & 7) == 3
                     ? MemoryKind::Store : MemoryKind::Unsupported;
  case 0x2f: return ((instruction >> 12) & 7) == 2 || ((instruction >> 12) & 7) == 3
                     ? MemoryKind::Atomic : MemoryKind::Unsupported;
  case 0x0f: return ((instruction >> 12) & 7) == 2 ? MemoryKind::Unsupported : MemoryKind::None;
  case 0x73: {
    const auto funct3 = (instruction >> 12) & 7;
    const auto funct7 = (instruction >> 25) & 0x7f;
    return funct7 == 0x7e || (funct3 == 4 && funct7 >= 0x30 && funct7 <= 0x37) ? MemoryKind::Unsupported
                                                                 : MemoryKind::None;
  }
  default: return MemoryKind::None;
  }
}

size_t EventEmitter::memory_width(uint32_t instruction, uint8_t length) {
  if (length == 2) {
    const auto quadrant = instruction & 3;
    const auto function = (instruction >> 13) & 7;
    if ((quadrant == 0 || quadrant == 2) && (function == 2 || function == 6))
      return 4;
    if ((quadrant == 0 || quadrant == 2) &&
        (function == 1 || function == 3 || function == 5 || function == 7))
      return 8;
    return 0;
  }
  const auto opcode = instruction & 0x7f;
  const auto function = (instruction >> 12) & 7;
  if (opcode == 0x03 || opcode == 0x23 || opcode == 0x07 || opcode == 0x27)
    return size_t{1} << (function & 3);
  if (opcode == 0x2f && (function == 2 || function == 3))
    return size_t{1} << function;
  return 0;
}

void EventEmitter::append(RuntimeEventKind kind, RuntimeEventPayload payload, SourcePosition source) {
  RuntimeEvent event;
  event.producer_id = kind == RuntimeEventKind::StorePublish ? configuration_.publication_producer
                                                           : configuration_.producer;
  event.source = source;
  event.kind = kind;
  event.payload = std::move(payload);
  batch_.events.push_back(std::move(event));
}

CheckResult EventEmitter::begin(const InstructionObservation &allocation, OperationId &id) {
  auto result = validate_source(allocation.source);
  if (!result)
    return result;
  if (allocation.pc & 1)
    return reject(CheckStatus::Invalid, "Rocket instruction PC is not halfword-aligned");
  const bool compressed = (allocation.instruction & 3) != 3;
  const bool extended = (allocation.length == 6 && (allocation.instruction & 0x3f) == 0x1f) ||
                        (allocation.length == 8 && (allocation.instruction & 0x7f) == 0x3f) ||
                        (allocation.length >= 10 && allocation.length <= 24 && allocation.length % 2 == 0 &&
                         (allocation.instruction & 0x7f) == 0x7f &&
                         allocation.length == 10 + 2 * ((allocation.instruction >> 12) & 7));
  const bool standard_length = (allocation.length == 2 && compressed) ||
                               (allocation.length == 4 && !compressed &&
                                (allocation.instruction & 0x1f) != 0x1f);
  if (!standard_length && !extended)
    return reject(CheckStatus::Invalid, "Rocket raw instruction length does not match its encoding");
  if (last_token_ && allocation.token <= *last_token_)
    return reject(CheckStatus::Invalid, "Rocket native instruction tokens must increase without reuse");
  const auto kind = (allocation.instruction & 0x1f) == 0x1f
                      ? MemoryKind::Unsupported : memory_kind(allocation.instruction, allocation.length);
  const auto opcode = allocation.instruction & 0x7f;
  const auto funct3 = (allocation.instruction >> 12) & 7;
  const auto funct7 = (allocation.instruction >> 25) & 0x7f;
  const bool raw_load = kind == MemoryKind::Load;
  const bool raw_store = kind == MemoryKind::Store;
  if ((raw_load || raw_store) && !allocation.memory)
    return reject(CheckStatus::Invalid, "Rocket raw memory opcode disagrees with decode memory qualifier");
  if (raw_load && allocation.memory_command != 0)
    return reject(CheckStatus::Invalid, "Rocket scalar load has a non-load memory command");
  if (raw_store && allocation.memory_command != 1)
    return reject(CheckStatus::Invalid, "Rocket scalar store has a non-store memory command");
  const bool base_fence = opcode == 0x0f && funct3 <= 1;
  const bool supervisor_fence = opcode == 0x73 && funct3 == 0 &&
                                 (funct7 == 0x09 || funct7 == 0x11 || funct7 == 0x31);
  const bool fence = base_fence || supervisor_fence;
  if (allocation.memory && kind == MemoryKind::None && !fence)
    return reject(CheckStatus::Invalid, "Rocket decode marks a non-memory instruction as memory");
  const auto classified_kind = kind;
  if (instructions_.size() >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket instruction capture capacity reached"};
  if (next_uid_ == std::numeric_limits<uint64_t>::max())
    return reject(CheckStatus::Invalid, "Rocket logical instruction UID exhausted");
  Instruction instruction;
  instruction.id = {configuration_.hart, configuration_.epoch, next_uid_++, 0};
  instruction.allocation = allocation;
  if (allocation.length == 2)
    instruction.allocation.instruction &= 0xffff;
  instruction.kind = classified_kind;
  id = instruction.id;
  instructions_.emplace(allocation.token, std::move(instruction));
  unretired_tokens_.insert(allocation.token);
  last_token_ = allocation.token;
  return {};
}

CheckResult EventEmitter::sample_load(const LoadObservation &load) {
  auto result = validate_source(load.source);
  if (!result || !(result = validate_access(load.address, load.bytes, load.mask)))
    return result;
  auto found = instructions_.find(load.token);
  if (found == instructions_.end() || found->second.retired)
    return reject(CheckStatus::Invalid, "Rocket load has no live instruction");
  // Unsupported speculative instructions can still be squashed. Their data is
  // not modeled or exported; confirmation at retirement fails closed.
  if (found->second.kind == MemoryKind::Unsupported)
    return {};
  if (found->second.kind != MemoryKind::Load)
    return reject(CheckStatus::Invalid, "Rocket load does not belong to an integer-load instruction");
  auto &instruction = found->second;
  const auto allocation_order = compare_source_position(configuration_.producer, instruction.allocation.source,
                                                        configuration_.producer, load.source);
  if (allocation_order == SourceOrder::After || allocation_order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket load sample does not follow its instruction allocation");
  if (allocation_order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket allocation and load source are unordered in one cycle");
  if (instruction.load || load.attempt != instruction.next_attempt ||
      load.bytes.size() != memory_width(instruction.allocation.instruction, instruction.allocation.length) ||
      std::any_of(load.mask.begin(), load.mask.end(), [](uint8_t byte) { return byte != 1; }))
    return reject(CheckStatus::Invalid, "Rocket load disagrees with its instruction, mask or attempt");
  instruction.load = load;
  return {};
}

CheckResult EventEmitter::atomic(uint64_t token, const AtomicLifecycleEvent &record,
                                    const SourcePosition &source) {
  auto result = validate_source(source);
  if (!result)
    return result;
  auto found = instructions_.find(token);
  if (found == instructions_.end() || found->second.retired)
    return reject(CheckStatus::Invalid, "Rocket atomic lifecycle has no live instruction");
  auto &instruction = found->second;
  if (instruction.kind != MemoryKind::Atomic)
    return reject(CheckStatus::Invalid, "Rocket atomic lifecycle for a non-atomic instruction");
  if (record.id != instruction.id || record.id.subaccess != 0)
    return reject(CheckStatus::Invalid, "Rocket atomic lifecycle identity differs from its instruction");
  const auto allocation_order = compare_source_position(configuration_.producer, instruction.allocation.source,
                                                        configuration_.producer, source);
  if (allocation_order == SourceOrder::After || allocation_order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket atomic lifecycle does not follow its allocation");
  if (allocation_order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket allocation and atomic lifecycle are unordered in one cycle");
  auto &atomic = instruction.atomic;
  switch (record.phase) {
  case AtomicObservationPhase::Begin:
    if (atomic.begun)
      return reject(CheckStatus::Invalid, "Rocket duplicate atomic Begin");
    atomic = {};
    atomic.begun = true;
    atomic.attempt = record.attempt;
    atomic.lr = record.fuop == 2 || record.fuop == 3;
    atomic.sc = record.fuop == 6 || record.fuop == 7;
    atomic.rmw = !atomic.lr && !atomic.sc;
    break;
  case AtomicObservationPhase::Request:
    if (!atomic.begun)
      return reject(CheckStatus::Invalid, "Rocket atomic Request lacks Begin");
    atomic.address = record.address;
    atomic.mask = record.mask;
    atomic.attempt = record.attempt;
    atomic.request = true;
    atomic.read = false;
    atomic.write = false;
    atomic.has_old = false;
    break;
  case AtomicObservationPhase::ReadEffect:
    if (!atomic.request)
      return reject(CheckStatus::Invalid, "Rocket atomic ReadEffect lacks Request");
    atomic.read = true;
    atomic.has_old = true;
    atomic.old_data = record.data;
    break;
  case AtomicObservationPhase::WriteEffect:
    if (!atomic.request)
      return reject(CheckStatus::Invalid, "Rocket atomic WriteEffect lacks Request");
    atomic.write = true;
    break;
  case AtomicObservationPhase::Response:
    atomic.response = true;
    atomic.success = record.success;
    break;
  case AtomicObservationPhase::Replay:
    atomic.request = false;
    atomic.read = false;
    atomic.write = false;
    atomic.has_old = false;
    break;
  case AtomicObservationPhase::Finish:
    break;
  case AtomicObservationPhase::Cancel:
    atomic = {};
    break;
  }
  append(RuntimeEventKind::AtomicLifecycle, record, source);
  return {};
}

CheckResult EventEmitter::cancel_load(uint64_t token, uint32_t attempt) {
  if (!failure_)
    return failure_;
  auto found = instructions_.find(token);
  if (found == instructions_.end() || found->second.retired)
    return reject(CheckStatus::Invalid, "Rocket cancellation has no live instruction");
  if (found->second.kind == MemoryKind::Unsupported)
    return {};
  if (found->second.kind != MemoryKind::Load)
    return reject(CheckStatus::Invalid, "Rocket cancellation is not an integer-load attempt");
  auto &instruction = found->second;
  if (attempt != instruction.next_attempt || attempt == std::numeric_limits<uint32_t>::max())
    return reject(CheckStatus::Invalid, "Rocket cancellation has a stale or exhausted attempt");
  instruction.load.reset();
  ++instruction.next_attempt;
  return {};
}

CheckResult EventEmitter::commit_store(const StoreObservation &store) {
  auto result = validate_source(store.source);
  if (!result || !(result = validate_access(store.address, store.bytes, store.mask)))
    return result;
  auto found = instructions_.find(store.token);
  if (found != instructions_.end() && found->second.kind == MemoryKind::Unsupported)
    return reject(CheckStatus::Unsupported, "Committed Rocket store exceeds the scalar capture profile");
  if (found == instructions_.end() || found->second.retired || found->second.kind != MemoryKind::Store ||
      found->second.store)
    return reject(CheckStatus::Invalid, "Rocket local store has no matching uncommitted instruction");
  const auto allocation_order = compare_source_position(configuration_.producer, found->second.allocation.source,
                                                        configuration_.producer, store.source);
  if (allocation_order == SourceOrder::After || allocation_order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket local store does not follow instruction allocation");
  if (allocation_order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket allocation and local store are unordered in one cycle");
  if (store.bytes.size() != memory_width(found->second.allocation.instruction, found->second.allocation.length) ||
      std::any_of(store.mask.begin(), store.mask.end(), [](uint8_t byte) { return byte != 1; }))
    return reject(CheckStatus::Invalid, "Rocket store disagrees with its instruction width or byte mask");
  found->second.store = store;
  return {};
}

CheckResult EventEmitter::retire(uint64_t token, SourcePosition source) {
  auto result = validate_source(source);
  if (!result)
    return result;
  auto found = instructions_.find(token);
  if (found == instructions_.end() || found->second.retired)
    return reject(CheckStatus::Invalid, "Rocket retirement has no live instruction");
  if (unretired_tokens_.empty() || *unretired_tokens_.begin() != token)
    return {CheckStatus::Pending, 0, "Rocket retirement awaits an older instruction"};
  auto &instruction = found->second;
  if (instruction.kind == MemoryKind::Unsupported)
    return reject(CheckStatus::Unsupported, "Retired Rocket instruction exceeds the scalar capture profile");
  const auto allocation_order = compare_source_position(configuration_.producer, instruction.allocation.source,
                                                        configuration_.producer, source);
  if (allocation_order == SourceOrder::After || allocation_order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket retirement predates allocation");
  if (allocation_order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket allocation and retirement are unordered in one cycle");
  if ((instruction.kind == MemoryKind::Load && !instruction.load) ||
      (instruction.kind == MemoryKind::Store && !instruction.store))
    return {CheckStatus::Pending, 0, "Rocket retirement awaits its accepted memory observation"};
  // A scoreboarded load can leave WB before its data returns. Preserve the
  // original retirement timestamp; the consumer must retry a retirement that
  // arrives before its sample instead of turning delivery order into GMO.
  if (instruction.store) {
    const auto store_order = compare_source_position(configuration_.producer, instruction.store->source,
                                                     configuration_.producer, source);
    if (store_order == SourceOrder::After || store_order == SourceOrder::Equal)
      return reject(CheckStatus::Invalid, "Rocket retirement does not follow its LocalStore event");
    if (store_order == SourceOrder::Unordered)
      return reject(CheckStatus::Incomplete, "Rocket LocalStore and retirement are unordered in one cycle");
  }
  const auto event_count = 2 + (instruction.kind != MemoryKind::None);
  if (batch_.events.size() + event_count > configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket output batch capacity reached"};

  const auto &allocation = instruction.allocation;
  append(RuntimeEventKind::InstructionAllocate,
         InstructionAllocateEvent{instruction.id, allocation.pc, allocation.instruction, allocation.length},
         allocation.source);
  RetiredInstruction retired;
  retired.hart = instruction.id.hart;
  retired.epoch = instruction.id.epoch;
  retired.uid = instruction.id.uid;
  retired.pc = allocation.pc;
  retired.instruction = allocation.instruction;
  InstructionRetireEvent retirement{retired, {}};
  if (instruction.kind == MemoryKind::Atomic) {
    const auto &atomic = instruction.atomic;
    if (!atomic.begun || !atomic.request || !atomic.response)
      return reject(CheckStatus::Incomplete, "Rocket atomic retirement lacks a complete lifecycle");
    if (!atomic.lr && !atomic.sc && (!atomic.read || !atomic.write))
      return reject(CheckStatus::Incomplete, "Rocket AMO retirement lacks its read/write effects");
    if (atomic.lr && !atomic.read)
      return reject(CheckStatus::Incomplete, "Rocket LR retirement lacks its read effect");
    if (atomic.sc && atomic.success && !atomic.write)
      return reject(CheckStatus::Incomplete, "Rocket successful SC retirement lacks its write effect");
    if (atomic.sc && !atomic.success && atomic.write)
      return reject(CheckStatus::Invalid, "Rocket failed SC retirement carries a write effect");
    MemoryOperation operation;
    operation.id = instruction.id;
    operation.attempt = atomic.attempt;
    operation.address = atomic.address;
    operation.byte_mask.assign(8, 0);
    for (unsigned byte = 0; byte < 8; ++byte)
      operation.byte_mask[byte] = (atomic.mask >> byte) & 1;
    if (atomic.lr) {
      operation.load = true;
      operation.lr = true;
    } else if (atomic.sc) {
      operation.sc = true;
      operation.store = atomic.success;
    } else {
      operation.atomic = true;
      operation.load = true;
      operation.store = true;
    }
    if (operation.load) {
      if (!atomic.has_old)
        return reject(CheckStatus::Incomplete, "Rocket atomic retirement lacks its lifecycle read effect");
      std::vector<uint8_t> actual(8);
      for (unsigned byte = 0; byte < 8; ++byte)
        actual[byte] = static_cast<uint8_t>(atomic.old_data >> (8 * byte));
      retirement.loads.push_back({instruction.id, atomic.attempt, actual});
    }
    retirement.instruction.failed_sc = atomic.sc && !atomic.success;
    retirement.instruction.memory.push_back(operation);
  }
  if (instruction.load) {
    const auto &load = *instruction.load;
    MemoryOperation operation;
    operation.id = instruction.id;
    operation.attempt = load.attempt;
    operation.address = load.address;
    operation.byte_mask = load.mask;
    operation.load = true;
    operation.source_kind = ReadSourceKind::ModeledWitness;
    append(RuntimeEventKind::LoadSample, LoadSampleEvent{operation, load.bytes, {}}, load.source);
    retirement.instruction.memory.push_back(operation);
    retirement.loads.push_back({instruction.id, load.attempt, load.bytes});
  }
  if (instruction.store) {
    const auto &store = *instruction.store;
    append(RuntimeEventKind::LocalStore,
           LocalStoreEvent{instruction.id, store.address, store.bytes, store.mask}, store.source);
    MemoryOperation operation;
    operation.id = instruction.id;
    operation.address = store.address;
    operation.byte_mask = store.mask;
    operation.store = true;
    retirement.instruction.memory.push_back(operation);
  }
  append(RuntimeEventKind::InstructionRetire, std::move(retirement), source);
  instruction.retired = true;
  unretired_tokens_.erase(token);
  if (instruction.kind != MemoryKind::Store)
    instructions_.erase(found);
  return {};
}

CheckResult EventEmitter::publish_store(const StoreObservation &store, uint64_t transaction) {
  if (!failure_)
    return failure_;
  if (!transaction)
    return reject(CheckStatus::Invalid, "Rocket publication requires a nonzero transaction ID");
  if (!configuration_.publication_producer)
    return reject(CheckStatus::Unsupported, "Rocket publication has no registered memory-fabric producer");
  // The hart watermark cannot close this separate source channel. The shared
  // ObservationStream validates publication lateness against the fabric prefix.
  if (store.source.qualified_phase == SourcePosition::cycle_closed_phase || !store.source.producer_sequence)
    return reject(CheckStatus::Invalid, "Rocket publication uses an invalid fabric source position");
  auto result = validate_access(store.address, store.bytes, store.mask);
  if (!result)
    return result;
  auto found = instructions_.find(store.token);
  if (found == instructions_.end() || found->second.kind != MemoryKind::Store)
    return reject(CheckStatus::Invalid, "Rocket publication has no matching store instruction");
  if (!found->second.retired)
    return {CheckStatus::Pending, 0, "Rocket publication awaits architectural store commit"};
  const auto allocation_order = compare_source_position(configuration_.producer, found->second.allocation.source,
                                                        configuration_.publication_producer, store.source);
  if (allocation_order == SourceOrder::After || allocation_order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket publication does not follow its instruction allocation");
  if (allocation_order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket allocation and publication lack qualified source order");
  if (batch_.events.size() >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket output batch capacity reached"};
  StorePublishEvent publication;
  publication.transaction_id = transaction;
  publication.address = store.address;
  publication.bytes = store.bytes;
  publication.byte_mask = store.mask;
  publication.byte_writers.assign(store.bytes.size(), found->second.id);
  publication.members.push_back({found->second.id, store.source});
  append(RuntimeEventKind::StorePublish, std::move(publication), store.source);
  instructions_.erase(found);
  return {};
}

CheckResult EventEmitter::publish_store_group(const StorePublicationGroup &group) {
  if (!failure_)
    return failure_;
  const bool grouped = group.member_tokens.size() > 1;
  if (!group.transaction || group.member_tokens.empty() || group.bytes.empty() ||
      group.bytes.size() != group.mask.size() || group.byte_writer_tokens.size() != group.bytes.size() ||
      group.bytes.size() - 1 > std::numeric_limits<uint64_t>::max() - group.address ||
      std::none_of(group.mask.begin(), group.mask.end(), [](uint8_t byte) { return byte == 1; }) ||
      std::any_of(group.mask.begin(), group.mask.end(), [](uint8_t byte) { return byte > 1; }))
    return reject(CheckStatus::Invalid, "Rocket merged publication has invalid transaction or source evidence");
  if (!configuration_.publication_producer)
    return reject(CheckStatus::Unsupported, "Rocket publication has no registered memory-fabric producer");
  if (group.source.qualified_phase == SourcePosition::cycle_closed_phase || !group.source.producer_sequence)
    return reject(CheckStatus::Invalid, "Rocket merged publication uses an invalid physical drain source");

  std::vector<Instruction *> members;
  members.reserve(group.member_tokens.size());
  std::set<uint64_t> unique_tokens;
  uint32_t member_hart = 0;
  uint64_t member_epoch = 0;
  uint64_t previous_uid = 0;
  for (size_t index = 0; index < group.member_tokens.size(); ++index) {
    const uint64_t token = group.member_tokens[index];
    auto found = instructions_.find(token);
    if (!unique_tokens.insert(token).second || found == instructions_.end() ||
        found->second.kind != MemoryKind::Store)
      return reject(CheckStatus::Invalid, "Rocket merged publication has a missing or duplicate logical store");
    auto &instruction = found->second;
    if (!instruction.store || !instruction.retired)
      return {CheckStatus::Pending, 0, "Rocket merged publication awaits every member LocalStore and retirement"};
    if (index == 0) {
      member_hart = instruction.id.hart;
      member_epoch = instruction.id.epoch;
    } else if (instruction.id.hart != member_hart || instruction.id.epoch != member_epoch ||
               instruction.id.uid <= previous_uid) {
      return reject(CheckStatus::Invalid, "Rocket merged store members are not in one hart's program order");
    }
    previous_uid = instruction.id.uid;
    const auto order = compare_source_position(configuration_.producer, instruction.allocation.source,
                                               configuration_.publication_producer, group.source);
    if (order == SourceOrder::After || order == SourceOrder::Equal)
      return reject(CheckStatus::Invalid, "Rocket merged publication predates a logical store allocation");
    if (order == SourceOrder::Unordered)
      return reject(CheckStatus::Incomplete, "Rocket allocation and merged publication lack common phase evidence");
    members.push_back(&instruction);
  }

  std::vector<std::optional<uint64_t>> latest_writer(group.bytes.size());
  for (size_t member_index = 0; member_index < members.size(); ++member_index) {
    const auto &store = *members[member_index]->store;
    for (size_t byte = 0; byte < store.mask.size(); ++byte) {
      if (!store.mask[byte])
        continue;
      const uint64_t address = store.address + byte;
      if (address < group.address || address - group.address >= group.bytes.size())
        return reject(CheckStatus::Invalid, "Rocket merged transaction omits a member byte");
      latest_writer[address - group.address] = group.member_tokens[member_index];
    }
  }

  rvwmo::StorePublishEvent publication;
  publication.transaction_id = group.transaction;
  publication.address = group.address;
  publication.bytes = group.bytes;
  publication.byte_mask = group.mask;
  publication.coalesced_program_order = grouped;
  publication.physical_write = group.physical_write;
  for (size_t index = 0; index < members.size(); ++index)
    publication.members.push_back({members[index]->id, group.source});
  publication.byte_writers.reserve(group.bytes.size());
  for (size_t byte = 0; byte < group.bytes.size(); ++byte) {
    if (group.mask[byte] != static_cast<uint8_t>(latest_writer[byte].has_value()) ||
        group.byte_writer_tokens[byte] != latest_writer[byte])
      return reject(CheckStatus::Invalid, "Rocket merged transaction mask or byte-writer identity is inconsistent");
    if (!group.mask[byte]) {
      publication.byte_writers.push_back({});
      continue;
    }
    const auto member = std::find(group.member_tokens.begin(), group.member_tokens.end(), *latest_writer[byte]);
    const auto member_index = static_cast<size_t>(member - group.member_tokens.begin());
    const auto &store = *members[member_index]->store;
    const auto offset = group.address + byte - store.address;
    if (offset >= store.bytes.size() || !store.mask[offset])
      return reject(CheckStatus::Invalid, "Rocket merged byte writer does not cover its final lane");
    if (group.bytes[byte] != store.bytes[offset])
      return reject(CheckStatus::Violation, "Rocket merged SRAM bytes differ from retained logical stores");
    publication.byte_writers.push_back(members[member_index]->id);
  }

  if (batch_.events.size() >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket output batch capacity reached"};
  append(RuntimeEventKind::StorePublish, std::move(publication), group.source);
  for (const auto token : group.member_tokens)
    instructions_.erase(token);
  return {};
}

CheckResult EventEmitter::squash(uint64_t token) {
  if (!failure_)
    return failure_;
  auto found = instructions_.find(token);
  if (found == instructions_.end()) {
    if (std::find(terminated_tokens_.begin(), terminated_tokens_.end(), token) != terminated_tokens_.end())
      return {};
    return reject(CheckStatus::Invalid, "Rocket squash has no live or recently terminated instruction");
  }
  if (found->second.retired || found->second.store)
    return reject(CheckStatus::Invalid, "Rocket squash cannot retract a committed instruction");
  instructions_.erase(found);
  unretired_tokens_.erase(token);
  terminated_tokens_.push_back(token);
  if (terminated_tokens_.size() > pipeline_kill_history)
    terminated_tokens_.pop_front();
  return {};
}

CheckResult EventEmitter::close_through(uint64_t source_cycle) {
  if (!failure_)
    return failure_;
  if (closed_cycle_ && source_cycle < *closed_cycle_)
    return reject(CheckStatus::Invalid, "Rocket producer watermark moved backwards");
  for (const auto &event : batch_.events) {
    if (event.producer_id == configuration_.producer && event.source.cycle > source_cycle)
      return {CheckStatus::Pending, 0, "Rocket batch contains an event beyond the requested hart watermark"};
  }
  for (const auto token : unretired_tokens_)
    if (instructions_.at(token).allocation.source.cycle <= source_cycle)
      return {CheckStatus::Pending, 0, "Rocket watermark awaits unresolved speculative instructions"};
  closed_cycle_ = source_cycle;
  batch_.watermarks = {{configuration_.producer, SourcePosition::end_of_cycle(source_cycle)}};
  return {};
}

EventBatch EventEmitter::take_batch() {
  auto batch = std::move(batch_);
  batch_ = {};
  return batch;
}

CheckResult EventEmitter::finalize() const {
  if (!failure_)
    return failure_;
  if (!instructions_.empty() || !batch_.events.empty() || !batch_.watermarks.empty())
    return {CheckStatus::Pending, 0, "Rocket capture has live instructions, pending stores or undelivered events"};
  return {};
}

} // namespace rocket_difftest
