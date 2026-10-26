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
    if ((quadrant == 0 || quadrant == 2) && (function == 1 || function == 5))
      return MemoryKind::Unsupported;
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
  case 0x07:
  case 0x27:
  case 0x2f: return MemoryKind::Unsupported;
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
    if ((quadrant == 0 || quadrant == 2) && (function == 3 || function == 7))
      return 8;
    return 0;
  }
  const auto opcode = instruction & 0x7f;
  const auto function = (instruction >> 12) & 7;
  if (opcode == 0x03 || opcode == 0x23)
    return size_t{1} << (function & 3);
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
  const bool raw_integer_load = kind == MemoryKind::Load;
  const bool raw_integer_store = kind == MemoryKind::Store;
  if ((raw_integer_load || raw_integer_store) && !allocation.memory)
    return reject(CheckStatus::Invalid, "Rocket raw memory opcode disagrees with decode memory qualifier");
  if (raw_integer_load && allocation.memory_command != 0)
    return reject(CheckStatus::Invalid, "Rocket integer load has a non-load memory command");
  if (raw_integer_store && allocation.memory_command != 1)
    return reject(CheckStatus::Invalid, "Rocket integer store has a non-store memory command");
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
  for (auto older = instructions_.begin(); older != found; ++older)
    if (!older->second.retired)
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
  const auto store_order = compare_source_position(configuration_.producer, found->second.store->source,
                                                   configuration_.publication_producer, store.source);
  if (store_order == SourceOrder::After || store_order == SourceOrder::Equal)
    return reject(CheckStatus::Invalid, "Rocket publication does not follow local store commit");
  if (store_order == SourceOrder::Unordered)
    return reject(CheckStatus::Incomplete, "Rocket local commit and publication lack qualified source order");
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
  for (const auto &entry : instructions_)
    if (!entry.second.retired && entry.second.allocation.source.cycle <= source_cycle)
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
