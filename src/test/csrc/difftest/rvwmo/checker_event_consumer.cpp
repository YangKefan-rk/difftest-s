#include "checker_event_consumer.h"
#include <algorithm>
#include <limits>
#include <stdexcept>

namespace rvwmo {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }
CheckResult unsupported(const char *message) { return {CheckStatus::Unsupported, 0, message}; }
CheckResult pending(const char *message) { return {CheckStatus::Pending, 0, message}; }

bool same_parent(const OperationId &operation, const OperationId &instruction) {
  return operation.hart == instruction.hart && operation.epoch == instruction.epoch &&
         operation.uid == instruction.uid;
}

} // namespace

CheckerEventConsumer::CheckerEventConsumer(Memory::ReadGlobal read_global, Memory::WriteGlobal write_global,
                                           RankResolver rank_resolver, size_t max_live_instructions,
                                           size_t max_pending_retirements)
    : memory_(std::move(read_global), std::move(write_global)), checker_(memory_),
      rank_resolver_(std::move(rank_resolver)), max_live_instructions_(max_live_instructions),
      max_pending_retirements_(max_pending_retirements) {
  if (!rank_resolver_)
    throw std::invalid_argument("CheckerEventConsumer requires an explicit source-rank resolver");
  if (!max_live_instructions_)
    throw std::invalid_argument("CheckerEventConsumer requires a nonzero live-instruction limit");
  if (!max_pending_retirements_)
    throw std::invalid_argument("CheckerEventConsumer requires a nonzero pending-retirement limit");
}

OperationId CheckerEventConsumer::instruction_id(const OperationId &operation) {
  return {operation.hart, operation.epoch, operation.uid, 0};
}

CheckResult CheckerEventConsumer::remember_failure(CheckResult result) {
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    failure_ = result;
  return result;
}

CheckResult CheckerEventConsumer::require_rank(const RuntimeEvent &event, ObservationTime &time) const {
  const auto resolved = rank_resolver_(event);
  if (!resolved || !resolved->valid || resolved->rank == 0)
    return incomplete("memory event has no hardware-justified GMO rank");
  if (last_memory_rank_ && resolved->rank <= *last_memory_rank_)
    return incomplete("memory event rank is not a strictly increasing observed order");
  time = *resolved;
  return {};
}

CheckResult CheckerEventConsumer::consume_allocate(const InstructionAllocateEvent &event) {
  if (!event.id.uid || event.id.subaccess != 0 || event.pc % 2)
    return remember_failure(invalid("invalid parent instruction allocation"));
  if (event.length == 6 || event.length == 8)
    return remember_failure(unsupported("extended-length instructions exceed this scalar consumer's decode width"));
  if (event.length != 2 && event.length != 4)
    return remember_failure(invalid("instruction length must be 2 or 4 bytes"));

  const bool encoded_as_compressed = (event.instruction & 3) != 3;
  if (encoded_as_compressed != (event.length == 2))
    return remember_failure(invalid("allocated instruction length differs from its encoding"));
  if (event.length == 4 && ((event.instruction >> 2) & 7) == 7)
    return remember_failure(unsupported("instruction encoding declares an extended-length instruction"));
  if (allocations_.size() >= max_live_instructions_)
    return pending("live instruction limit reached; retain and retry the allocation event after retirement");
  auto hart = hart_epoch_and_uid_.find(event.id.hart);
  if (hart != hart_epoch_and_uid_.end()) {
    if (hart->second.first != event.id.epoch)
      return remember_failure(unsupported("instruction epoch changes require a fresh checker session"));
    if (hart->second.second >= event.id.uid)
      return remember_failure(invalid("instruction allocation UID is not strictly increasing per hart"));
  }
  if (!allocations_.emplace(event.id, Allocation{event.pc, event.instruction, event.length}).second)
    return remember_failure(invalid("duplicate instruction allocation identity"));
  hart_epoch_and_uid_[event.id.hart] = {event.id.epoch, event.id.uid};
  return {};
}

CheckResult CheckerEventConsumer::consume_local_store(const LocalStoreEvent &event) {
  const auto parent = instruction_id(event.id);
  if (!allocations_.count(parent))
    return remember_failure(incomplete("local store has no closed parent instruction allocation"));
  if (event.id.subaccess != 0)
    return remember_failure(unsupported("split or vector LocalStore is not covered by this consumer"));
  if (stores_.size() >= max_live_instructions_)
    return pending("live store limit reached; retain and retry the LocalStore event after retirement");
  if (stores_.count(event.id) || event.bytes.empty() || event.bytes.size() != event.byte_mask.size() ||
      std::none_of(event.byte_mask.begin(), event.byte_mask.end(), [](uint8_t enabled) { return enabled != 0; }))
    return remember_failure(invalid("invalid or duplicate LocalStore"));

  MemoryWriter writer;
  auto result = checker_.memory_writer(event.id, writer);
  if (!result)
    return remember_failure(result);

  MemoryStore store{writer, event.id.uid, event.address, event.bytes, event.byte_mask};
  MemoryOperation operation;
  operation.id = event.id;
  operation.address = event.address;
  operation.byte_mask = event.byte_mask;
  operation.store = true;
  result = checker_.record_store(store, operation, StoreVerification::Provisional);
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return remember_failure(result);
  stores_.emplace(event.id, StoreRecord{operation, std::move(store), false, false, false});
  return result;
}

CheckResult CheckerEventConsumer::consume_load_sample(const RuntimeEvent &event, const LoadSampleEvent &sample) {
  auto operation = sample.operation;
  const auto parent = instruction_id(operation.id);
  if (!allocations_.count(parent))
    return remember_failure(incomplete("load sample has no closed parent instruction allocation"));
  if (operation.id.subaccess != 0)
    return remember_failure(unsupported("split or vector LoadSample is not covered by this consumer"));
  if (loads_.size() + cancelled_loads_.size() >= max_live_instructions_)
    return pending("live load-attempt limit reached; retain and retry the sample after retirement");
  const LoadKey key{operation.id, operation.attempt};
  if (cancelled_loads_.count(key) || loads_.count(key))
    return remember_failure(invalid("load sample is cancelled or duplicated"));
  if (!operation.load || operation.byte_mask.empty() || sample.actual_bytes.size() != operation.byte_mask.size())
    return remember_failure(invalid("invalid load sample shape"));

  ObservationTime time;
  auto result = require_rank(event, time);
  if (!result)
    return result;
  operation.read_time = time;
  operation.write_time = {};
  operation.source_kind = ReadSourceKind::ModeledWitness;
  operation.read_sources.clear();
  // DUT forwarding tags are diagnostic only in the modeled-witness profile.
  result = checker_.observe_load(operation, operation.id.uid, {});
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return remember_failure(result);
  last_memory_rank_ = time.rank;
  loads_.emplace(key, LoadRecord{std::move(operation), sample.actual_bytes});
  return result;
}

CheckResult CheckerEventConsumer::consume_store_publish(const RuntimeEvent &event, const StorePublishEvent &publish) {
  if (publish.members.size() != 1)
    return remember_failure(unsupported("semantic consumer currently requires one logical store per publish event"));
  const auto &member = publish.members.front();
  const auto &member_position = member.publish_position;
  if (member_position.cycle != event.source.cycle ||
      member_position.qualified_phase != event.source.qualified_phase ||
      member_position.producer_sequence != event.source.producer_sequence ||
      member_position.order_qualified != event.source.order_qualified)
    return remember_failure(incomplete("single-store publish member has no matching envelope source position"));
  auto store = stores_.find(member.id);
  if (store == stores_.end())
    return remember_failure(incomplete("store publication has no closed LocalStore record"));
  if (store->second.published || publish.address != store->second.operation.address ||
      publish.bytes.size() != store->second.operation.byte_mask.size() ||
      publish.byte_mask != store->second.operation.byte_mask || publish.byte_writers.size() != publish.bytes.size())
    return remember_failure(invalid("StorePublish differs from its LocalStore record"));
  for (size_t byte = 0; byte < publish.byte_mask.size(); ++byte)
    if (publish.byte_mask[byte] && publish.byte_writers[byte] != member.id)
      return remember_failure(unsupported("single-store publication names another byte writer"));

  ObservationTime time;
  auto result = require_rank(event, time);
  if (!result)
    return result;
  MemoryWriter writer;
  result = checker_.memory_writer(member.id, writer);
  if (!result)
    return remember_failure(result);
  result = checker_.observe_global(publish.address, publish.bytes, publish.byte_mask,
                                   std::vector<MemoryWriter>(publish.byte_writers.size(), writer), {writer},
                                   std::vector<ObservationTime>{time});
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return remember_failure(result);
  last_memory_rank_ = time.rank;
  store->second.published = true;
  collect_store_metadata();
  return result;
}

CheckResult CheckerEventConsumer::consume_cancel(const InstructionCancelAttemptEvent &event) {
  if (!allocations_.count(instruction_id(event.id)))
    return remember_failure(incomplete("attempt cancellation has no closed parent allocation"));
  if (event.id.subaccess != 0)
    return remember_failure(unsupported("split or vector load cancellation is not covered by this consumer"));
  if (!cancelled_loads_.count({event.id, event.attempt}) &&
      loads_.size() + cancelled_loads_.size() >= max_live_instructions_)
    return pending("live load-attempt limit reached; retain and retry cancellation after retirement");
  const LoadKey key{event.id, event.attempt};
  if (!cancelled_loads_.insert(key).second)
    return remember_failure(invalid("duplicate load-attempt cancellation"));
  auto load = loads_.find(key);
  if (load == loads_.end())
    return {};
  auto result = checker_.cancel_load(event.id, event.attempt);
  if (!result)
    return remember_failure(result);
  loads_.erase(load);
  return {};
}

CheckResult CheckerEventConsumer::consume_retire(const InstructionRetireEvent &event) {
  auto instruction = event.instruction;
  const OperationId id{instruction.hart, instruction.epoch, instruction.uid, 0};
  if (instruction.failed_sc)
    return remember_failure(unsupported("failed SC retirement requires the atomic lifecycle checker"));
  auto allocation = allocations_.find(id);
  if (allocation == allocations_.end())
    return remember_failure(invalid("retirement has no live parent instruction allocation"));
  auto last_retired = last_retired_.find(instruction.hart);
  if (last_retired != last_retired_.end() &&
      (last_retired->second.first != instruction.epoch || last_retired->second.second >= instruction.uid))
    return remember_failure(invalid("retirement UID or epoch is not increasing per hart"));
  if (instruction.pc != allocation->second.pc ||
      instruction.instruction != allocation->second.instruction)
    return remember_failure(invalid("retirement identity or instruction differs from allocation"));

  DependencyMetadata decoded_dependencies;
  auto dependency_result = decode_dependencies(instruction.instruction, decoded_dependencies);
  if (!dependency_result)
    return remember_failure(dependency_result);
  // Retire-provided metadata is not an oracle. The v1 consumer reconstructs
  // scalar dependencies from the instruction and rejects undecodable opcodes.
  instruction.dependencies = std::move(decoded_dependencies);

  const bool has_load = std::any_of(instruction.memory.begin(), instruction.memory.end(),
                                    [](const MemoryOperation &operation) { return operation.load; });
  const bool has_store = std::any_of(instruction.memory.begin(), instruction.memory.end(),
                                     [](const MemoryOperation &operation) { return operation.store; });
  if (allocation->second.length == 2) {
    const unsigned quadrant = instruction.instruction & 3;
    const unsigned funct3 = (instruction.instruction >> 13) & 7;
    if ((quadrant == 0 || quadrant == 2) && (funct3 == 1 || funct3 == 5))
      return remember_failure(unsupported("floating compressed memory instruction needs a wider REF adapter"));
    const bool compressed_load = (quadrant == 0 || quadrant == 2) && (funct3 == 2 || funct3 == 3);
    const bool compressed_store = (quadrant == 0 || quadrant == 2) && (funct3 == 6 || funct3 == 7);
    if ((compressed_load && (!has_load || has_store)) || (compressed_store && (!has_store || has_load)))
      return remember_failure(incomplete("compressed scalar load/store lacks its matching memory event"));
    if (!compressed_load && !compressed_store && !instruction.memory.empty())
      return remember_failure(invalid("compressed non-memory opcode carries a memory effect"));
  } else {
    const uint32_t opcode = instruction.instruction & 0x7f;
    if (opcode == 0x07 || opcode == 0x27 || opcode == 0x2f)
      return remember_failure(unsupported("floating/vector or atomic memory opcode needs a richer consumer"));
    if ((opcode == 0x03 && (!has_load || has_store)) || (opcode == 0x23 && (!has_store || has_load)))
      return remember_failure(incomplete("scalar load/store retirement lacks its matching memory event"));
    if (opcode != 0x03 && opcode != 0x23 && !instruction.memory.empty())
      return remember_failure(invalid("non-load/store opcode carries a memory effect"));
    if (opcode == 0x0f && ((instruction.instruction >> 12) & 7) == 2)
      return remember_failure(unsupported("cache-block operation is not modeled by this consumer"));
  }

  std::vector<RetiredLoad> actual_loads;
  std::set<LoadKey> selected_loads;
  std::set<OperationId> selected_stores;
  for (auto &operation : instruction.memory) {
    if (operation.atomic || operation.lr || operation.sc)
      return remember_failure(unsupported("atomic retirement requires the atomic lifecycle checker"));
    if (operation.load && operation.store)
      return remember_failure(unsupported("split read/write effects are not represented by this consumer"));
    if (!same_parent(operation.id, id))
      return remember_failure(invalid("retired memory operation has a different instruction identity"));
    if (operation.id.subaccess != 0)
      return remember_failure(unsupported("split or vector retirement is not covered by this consumer"));
    operation.read_time = {};
    operation.write_time = {};
    operation.source_kind = ReadSourceKind::ModeledWitness;
    operation.read_sources.clear();
    if (operation.load) {
      const LoadKey key{operation.id, operation.attempt};
      auto sample = loads_.find(key);
      if (cancelled_loads_.count(key))
        return remember_failure(invalid("retirement selected a cancelled load attempt"));
      if (sample == loads_.end())
        return remember_failure(incomplete("retirement has no sample for its selected load attempt"));
      if (sample->second.operation.address != operation.address ||
          sample->second.operation.byte_mask != operation.byte_mask || !selected_loads.insert(key).second)
        return remember_failure(invalid("retired load differs from or duplicates its sampled operation"));
      auto actual = std::find_if(event.loads.begin(), event.loads.end(), [&](const ActualLoadValue &value) {
        return value.id == operation.id && value.attempt == operation.attempt;
      });
      if (actual == event.loads.end() || actual->bytes.size() != operation.byte_mask.size())
        return remember_failure(incomplete("retirement has no actual bytes for its selected load attempt"));
      for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte)
        if (operation.byte_mask[byte] && actual->bytes[byte] != sample->second.actual_bytes[byte])
          return remember_failure(
              {CheckStatus::Violation, 0, "retired load bytes differ from its sampled DUT bytes"});
      actual_loads.push_back({operation.id, actual->bytes});
    }
    if (operation.store) {
      auto store = stores_.find(operation.id);
      if (store == stores_.end())
        return remember_failure(incomplete("retirement has no LocalStore record for its store"));
      if (store->second.operation.address != operation.address ||
          store->second.operation.byte_mask != operation.byte_mask || !selected_stores.insert(operation.id).second)
        return remember_failure(invalid("retired store differs from or duplicates its LocalStore"));
    }
  }
  if (event.loads.size() != actual_loads.size())
    return remember_failure(invalid("retirement contains an unreferenced or duplicate load value"));
  for (const auto &sample : loads_)
    if (same_parent(sample.first.first, id) && !selected_loads.count(sample.first))
      return remember_failure(invalid("retirement left an uncancelled load attempt unselected"));

  auto progress = checker_.poll();
  if (!progress && progress.status != CheckStatus::Pending)
    return remember_failure(progress);
  if (checker_.pending_retirements() >= max_pending_retirements_)
    return pending("pending retirement limit reached; retain and retry the retirement event after checker progress");
  auto result = checker_.retire(instruction, actual_loads);
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return remember_failure(result);
  last_retired_[instruction.hart] = {instruction.epoch, instruction.uid};
  allocations_.erase(allocation);
  for (const auto &key : selected_loads) {
    loads_.erase(key);
    cancelled_loads_.erase(key);
  }
  for (const auto &store_id : selected_stores) {
    auto store = stores_.find(store_id);
    if (store != stores_.end()) {
      store->second.retired = true;
      if (store->second.audited && store->second.published)
        stores_.erase(store);
    }
  }
  for (auto cancelled = cancelled_loads_.begin(); cancelled != cancelled_loads_.end();) {
    if (same_parent(cancelled->first, id))
      cancelled = cancelled_loads_.erase(cancelled);
    else
      ++cancelled;
  }
  // Checker::retire may return Pending after enqueuing the retirement. From
  // this point the event is consumed; poll() reports semantic progress.
  return {};
}

void CheckerEventConsumer::collect_store_metadata() {
  for (auto store = stores_.begin(); store != stores_.end();) {
    if (store->second.audited && store->second.published && store->second.retired)
      store = stores_.erase(store);
    else
      ++store;
  }
}

CheckResult CheckerEventConsumer::consume_closed(const RuntimeEvent &event) {
  if (!failure_)
    return failure_;
  if (!event.producer_id)
    return remember_failure(invalid("closed event has no producer identity"));
  if (event.payload.index() != static_cast<size_t>(event.kind))
    return remember_failure(invalid("event kind differs from its typed payload"));
  switch (event.kind) {
  case RuntimeEventKind::InstructionAllocate:
    return consume_allocate(std::get<InstructionAllocateEvent>(event.payload));
  case RuntimeEventKind::InstructionCancelAttempt:
    return consume_cancel(std::get<InstructionCancelAttemptEvent>(event.payload));
  case RuntimeEventKind::LocalStore:
    return consume_local_store(std::get<LocalStoreEvent>(event.payload));
  case RuntimeEventKind::LoadSample:
    return consume_load_sample(event, std::get<LoadSampleEvent>(event.payload));
  case RuntimeEventKind::StorePublish:
    return consume_store_publish(event, std::get<StorePublishEvent>(event.payload));
  case RuntimeEventKind::InstructionRetire:
    return consume_retire(std::get<InstructionRetireEvent>(event.payload));
  case RuntimeEventKind::AtomicLifecycle:
    return remember_failure(unsupported("generic atomic lifecycle is not integrated with the semantic consumer"));
  case RuntimeEventKind::HartDone:
  case RuntimeEventKind::Trap:
    return remember_failure(unsupported("hart completion and trap events are not semantic memory events"));
  }
  return remember_failure(invalid("unknown event kind"));
}

CheckResult CheckerEventConsumer::candidate_load(const OperationId &id, uint32_t attempt,
                                                 std::vector<uint8_t> &bytes) {
  if (!failure_)
    return failure_;
  return checker_.get_reference_candidate_load(id, attempt, bytes);
}

CheckResult CheckerEventConsumer::audit_store(const OperationId &id, uint64_t address,
                                               const std::vector<uint8_t> &bytes,
                                               const std::vector<uint8_t> &mask) {
  if (!failure_)
    return failure_;
  auto store = stores_.find(id);
  if (store == stores_.end())
    return pending("reference store audit awaits its LocalStore event");
  if (store->second.audited || address != store->second.store.address || mask != store->second.store.mask ||
      bytes.size() != store->second.store.bytes.size())
    return remember_failure(invalid("reference store audit identity, address, mask or size differs"));
  auto reference = store->second.store;
  reference.bytes = bytes;
  auto result = checker_.verify_store(id, reference);
  if (!result)
    return remember_failure(result);
  store->second.audited = true;
  collect_store_metadata();
  return result;
}

CheckResult CheckerEventConsumer::poll() {
  if (!failure_)
    return failure_;
  auto result = checker_.poll();
  if (!result && result.status != CheckStatus::Pending)
    return remember_failure(result);
  return result;
}

CheckResult CheckerEventConsumer::finalize() {
  if (!failure_)
    return failure_;
  if (!allocations_.empty())
    return remember_failure(
        incomplete("unretired allocations remain; instruction squash is not represented by this consumer"));
  if (!cancelled_loads_.empty())
    return remember_failure(incomplete("cancelled attempts remain without a retired parent instruction"));
  return checker_.finalize();
}

} // namespace rvwmo
