#include "event_emitter.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace rocket_difftest {
using namespace rvwmo;

EventEmitter::EventEmitter(EmitterConfiguration configuration) : configuration_(configuration) {
  if (!configuration_.producer || configuration_.capacity < 3)
    reject(CheckStatus::Invalid, "Rocket emitter requires a registered producer and capacity >= 3");
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
  if (source.qualified_phase == SourcePosition::cycle_closed_phase)
    return reject(CheckStatus::Invalid, "Rocket observation uses a watermark sentinel");
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
    if (quadrant == 0 || quadrant == 2) {
      if (function == 2 || function == 3)
        return MemoryKind::Load;
      if (function == 6 || function == 7)
        return MemoryKind::Store;
      if (function == 1 || function == 5)
        return MemoryKind::Unsupported;
    }
    return MemoryKind::None;
  }
  switch (instruction & 0x7f) {
  case 0x03: return MemoryKind::Load;
  case 0x23: return MemoryKind::Store;
  case 0x07:
  case 0x27:
  case 0x2f: return MemoryKind::Unsupported;
  default: return MemoryKind::None;
  }
}

void EventEmitter::append(RuntimeEventKind kind, RuntimeEventPayload payload, SourcePosition source) {
  RuntimeEvent event;
  event.producer_id = configuration_.producer;
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
  if ((allocation.length != 2 && allocation.length != 4) ||
      ((allocation.instruction & 3) == 3) != (allocation.length == 4))
    return reject(CheckStatus::Invalid, "Rocket raw instruction length does not match its encoding");
  if ((allocation.instruction & 0x1f) == 0x1f)
    return reject(CheckStatus::Unsupported, "Rocket emitter does not support extended-length instructions");
  if (last_token_ && allocation.token <= *last_token_)
    return reject(CheckStatus::Invalid, "Rocket native instruction tokens must increase without reuse");
  const auto kind = memory_kind(allocation.instruction, allocation.length);
  if (kind == MemoryKind::Unsupported)
    return reject(CheckStatus::Unsupported, "Rocket emitter supports RV64 integer scalar memory only");
  if (instructions_.size() >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket instruction capture capacity reached"};
  if (next_uid_ == std::numeric_limits<uint64_t>::max())
    return reject(CheckStatus::Invalid, "Rocket logical instruction UID exhausted");
  Instruction instruction;
  instruction.id = {configuration_.hart, configuration_.epoch, next_uid_++, 0};
  instruction.allocation = allocation;
  instruction.kind = kind;
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
  if (found == instructions_.end() || found->second.retired || found->second.kind != MemoryKind::Load)
    return reject(CheckStatus::Invalid, "Rocket load has no live integer-load instruction");
  auto &instruction = found->second;
  if (instruction.load || load.attempt != instruction.next_attempt ||
      load.source.cycle < instruction.allocation.source.cycle)
    return reject(CheckStatus::Invalid, "Rocket load is duplicate, stale or predates allocation");
  instruction.load = load;
  return {};
}

CheckResult EventEmitter::cancel_load(uint64_t token, uint32_t attempt) {
  if (!failure_)
    return failure_;
  auto found = instructions_.find(token);
  if (found == instructions_.end() || found->second.retired || found->second.kind != MemoryKind::Load)
    return reject(CheckStatus::Invalid, "Rocket cancellation has no live integer-load instruction");
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
  if (found == instructions_.end() || found->second.retired || found->second.kind != MemoryKind::Store ||
      found->second.store || store.source.cycle < found->second.allocation.source.cycle)
    return reject(CheckStatus::Invalid, "Rocket local store has no matching uncommitted instruction");
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
  if (source.cycle < instruction.allocation.source.cycle)
    return reject(CheckStatus::Invalid, "Rocket retirement predates allocation");
  if ((instruction.kind == MemoryKind::Load && !instruction.load) ||
      (instruction.kind == MemoryKind::Store && !instruction.store))
    return {CheckStatus::Pending, 0, "Rocket retirement awaits its accepted memory observation"};
  // A scoreboarded load can leave WB before its data returns. Preserve the
  // original retirement timestamp; the consumer must retry a retirement that
  // arrives before its sample instead of turning delivery order into GMO.
  if (instruction.store && source.cycle < instruction.store->source.cycle)
    return reject(CheckStatus::Invalid, "Rocket retirement predates local store commit");
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
  auto result = validate_source(store.source);
  if (!result || !(result = validate_access(store.address, store.bytes, store.mask)))
    return result;
  auto found = instructions_.find(store.token);
  if (found == instructions_.end() || found->second.kind != MemoryKind::Store)
    return reject(CheckStatus::Invalid, "Rocket publication has no matching store instruction");
  if (!found->second.retired)
    return {CheckStatus::Pending, 0, "Rocket publication awaits architectural store commit"};
  if (store.source.cycle < found->second.store->source.cycle)
    return reject(CheckStatus::Invalid, "Rocket publication predates local store commit");
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
  if (found == instructions_.end() || found->second.retired || found->second.store)
    return reject(CheckStatus::Invalid, "Rocket squash cannot retract a committed or unknown instruction");
  instructions_.erase(found);
  return {};
}

CheckResult EventEmitter::close_through(uint64_t source_cycle) {
  if (!failure_)
    return failure_;
  if (closed_cycle_ && source_cycle < *closed_cycle_)
    return reject(CheckStatus::Invalid, "Rocket producer watermark moved backwards");
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
