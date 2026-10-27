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

CheckResult CheckerEventConsumer::require_rank(const RuntimeEvent &event, ObservationTime &time,
                                               RankCertificate certificate) const {
  const auto resolved = rank_resolver_(event);
  if (!resolved || !resolved->valid || resolved->rank == 0)
    return incomplete("memory event has no hardware-justified GMO rank");
  if (resolved->unordered_read_group != (certificate == RankCertificate::ReadOnly) ||
      resolved->unordered_effect_group != (certificate == RankCertificate::IndependentEffects))
    return incomplete("memory-group rank certificate is unavailable outside its private session group");
  if (last_memory_rank_ && resolved->rank <= *last_memory_rank_) {
    if (certificate == RankCertificate::None || !last_group_ || resolved->rank != *last_memory_rank_ ||
        last_group_->rank != resolved->rank || last_group_->cycle != event.source.cycle ||
        last_group_->certificate != certificate)
      return incomplete("memory event rank is not strictly increasing or part of one certified group");
    OperationId id;
    uint32_t attempt = 0;
    if (const auto *sample = std::get_if<LoadSampleEvent>(&event.payload)) {
      id = sample->operation.id;
      attempt = sample->operation.attempt;
    } else if (const auto *publish = std::get_if<StorePublishEvent>(&event.payload)) {
      if (certificate != RankCertificate::IndependentEffects || publish->members.size() != 1)
        return incomplete("equal-rank publication is not a certified independent effect");
      id = publish->members.front().id;
    } else {
      return incomplete("certified memory group contains an unsupported event kind");
    }
    if (last_group_->members.count({id, attempt}) ||
        (certificate == RankCertificate::IndependentEffects &&
         (last_group_->harts.count(id.hart) || last_group_->producers.count(event.producer_id))))
      return invalid("certified memory group repeats an operation, hart or producer");
  }
  time = *resolved;
  return {};
}

void CheckerEventConsumer::remember_rank(const RuntimeEvent &event, ObservationTime time,
                                         RankCertificate certificate, const OperationId &id, uint32_t attempt) {
  last_memory_rank_ = time.rank;
  if (certificate == RankCertificate::None) {
    last_group_.reset();
    return;
  }
  if (!last_group_ || last_group_->rank != time.rank)
    last_group_ = GroupReceipt{time.rank, event.source.cycle, certificate, {}, {}, {}};
  last_group_->members.insert({id, attempt});
  last_group_->harts.insert(id.hart);
  last_group_->producers.insert(event.producer_id);
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

CheckResult CheckerEventConsumer::consume_load_sample(const RuntimeEvent &event, const LoadSampleEvent &sample,
                                                      RankCertificate certificate, bool source_prefix_closed) {
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
  auto result = require_rank(event, time, certificate);
  if (!result)
    return result;
  operation.read_time = time;
  operation.write_time = {};
  operation.source_kind = ReadSourceKind::ModeledWitness;
  operation.read_sources.clear();
  // DUT forwarding tags are diagnostic only in the modeled-witness profile.
  result = checker_.observe_load(operation, operation.id.uid, {}, source_prefix_closed);
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return remember_failure(result);
  remember_rank(event, time, certificate, operation.id, operation.attempt);
  loads_.emplace(key, LoadRecord{std::move(operation), sample.actual_bytes});
  return result;
}

CheckResult CheckerEventConsumer::consume_read_group_member(const RuntimeEvent &event, bool source_prefix_closed) {
  if (!failure_)
    return failure_;
  const auto *sample = std::get_if<LoadSampleEvent>(&event.payload);
  if (!event.producer_id || event.kind != RuntimeEventKind::LoadSample || !sample ||
      !sample->operation.load || sample->operation.store || sample->operation.atomic || sample->operation.lr ||
      sample->operation.sc || sample->operation.acquire || sample->operation.release || sample->operation.rcsc)
    return remember_failure(invalid("certified read group contains a non-scalar load effect"));
  return consume_load_sample(event, *sample, RankCertificate::ReadOnly, source_prefix_closed);
}

CheckResult CheckerEventConsumer::consume_independent_group_member(const RuntimeEvent &event,
                                                                   bool source_prefix_closed) {
  if (!failure_)
    return failure_;
  if (!event.producer_id)
    return remember_failure(invalid("independent memory group has no producer"));
  if (event.kind == RuntimeEventKind::LoadSample) {
    const auto *sample = std::get_if<LoadSampleEvent>(&event.payload);
    if (!sample || !sample->operation.load || sample->operation.store || sample->operation.atomic ||
        sample->operation.lr || sample->operation.sc || sample->operation.acquire || sample->operation.release ||
        sample->operation.rcsc || sample->operation.has_paired_lr)
      return remember_failure(invalid("independent memory group contains a non-ordinary load"));
    return consume_load_sample(event, *sample, RankCertificate::IndependentEffects, source_prefix_closed);
  }
  if (event.kind == RuntimeEventKind::StorePublish) {
    const auto *publish = std::get_if<StorePublishEvent>(&event.payload);
    if (publish)
      return consume_store_publish(event, *publish, RankCertificate::IndependentEffects);
  }
  return remember_failure(invalid("independent memory group contains an unsupported effect"));
}

CheckResult CheckerEventConsumer::consume_store_publish(const RuntimeEvent &event, const StorePublishEvent &publish,
                                                        RankCertificate certificate) {
  if (publish.members.empty())
    return remember_failure(invalid("store publication has no logical store member"));
  if (publish.members.size() != 1) {
    if (certificate != RankCertificate::None)
      return remember_failure(incomplete("coalesced publication cannot share an unordered memory-group rank"));
    return consume_coalesced_store_publish(event, publish);
  }
  const auto &member = publish.members.front();
  if (!publish.transaction_id || !member.id.uid || publish.bytes.empty() ||
      publish.bytes.size() != publish.byte_mask.size() || publish.byte_writers.size() != publish.bytes.size() ||
      publish.bytes.size() - 1 > std::numeric_limits<uint64_t>::max() - publish.address ||
      std::none_of(publish.byte_mask.begin(), publish.byte_mask.end(), [](uint8_t byte) { return byte == 1; }) ||
      std::any_of(publish.byte_mask.begin(), publish.byte_mask.end(), [](uint8_t byte) { return byte > 1; }))
    return remember_failure(invalid("invalid single-store publication identity, byte range or mask"));
  if (member.id.subaccess != 0)
    return remember_failure(unsupported("split or vector store publication is not covered by this consumer"));
  const auto &member_position = member.publish_position;
  if (member_position.cycle != event.source.cycle ||
      member_position.qualified_phase != event.source.qualified_phase ||
      member_position.producer_sequence != event.source.producer_sequence ||
      member_position.order_qualified != event.source.order_qualified)
    return remember_failure(invalid("single-store publish member has no matching envelope source position"));
  for (size_t byte = 0; byte < publish.byte_mask.size(); ++byte)
    if (publish.byte_mask[byte] && publish.byte_writers[byte] != member.id)
      return remember_failure(invalid("single-store publication names another byte writer"));
  auto store = stores_.find(member.id);
  if (store == stores_.end())
    return pending("store publication awaits its LocalStore record");
  if (store->second.published || publish.address != store->second.operation.address ||
      publish.bytes.size() != store->second.operation.byte_mask.size() ||
      publish.byte_mask != store->second.operation.byte_mask || publish.byte_writers.size() != publish.bytes.size())
    return remember_failure(invalid("StorePublish differs from its LocalStore record"));
  ObservationTime time;
  auto result = require_rank(event, time, certificate);
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
  remember_rank(event, time, certificate, member.id, 0);
  store->second.published = true;
  collect_store_metadata();
  return result;
}

CheckResult CheckerEventConsumer::consume_coalesced_store_publish(const RuntimeEvent &event,
                                                                  const StorePublishEvent &publish) {
  if (!publish.coalesced_program_order)
    return remember_failure(unsupported("merged publication lacks a complete coalesced program-order certificate"));
  if (!event.source.order_qualified)
    return remember_failure(incomplete("coalesced publication lacks a qualified common source point"));
  if (!publish.transaction_id || publish.bytes.empty() || publish.bytes.size() != publish.byte_mask.size() ||
      publish.byte_writers.size() != publish.bytes.size() ||
      publish.bytes.size() - 1 > std::numeric_limits<uint64_t>::max() - publish.address ||
      std::none_of(publish.byte_mask.begin(), publish.byte_mask.end(), [](uint8_t byte) { return byte == 1; }) ||
      std::any_of(publish.byte_mask.begin(), publish.byte_mask.end(), [](uint8_t byte) { return byte > 1; }))
    return remember_failure(invalid("invalid coalesced publication transaction, byte range or mask"));

  std::map<OperationId, StoreRecord *> members;
  const auto &first = publish.members.front().id;
  for (const auto &member : publish.members) {
    if (!member.id.uid || member.id.hart != first.hart || member.id.epoch != first.epoch)
      return remember_failure(unsupported("coalesced publication members must belong to one hart and epoch"));
    if (member.id.subaccess != 0)
      return remember_failure(unsupported("split or vector coalesced publication is outside scalar coverage"));
    const auto &position = member.publish_position;
    if (position.cycle != event.source.cycle || position.qualified_phase != event.source.qualified_phase ||
        position.producer_sequence != event.source.producer_sequence ||
        position.order_qualified != event.source.order_qualified)
      return remember_failure(incomplete("coalesced publication member differs from the common source point"));
    auto found = stores_.find(member.id);
    if (found == stores_.end())
      return pending("coalesced publication awaits every LocalStore member");
    if (found->second.published || !members.emplace(member.id, &found->second).second)
      return remember_failure(invalid("coalesced publication repeats an already published or duplicate member"));
  }

  // The producer certifies one complete physical effect. Program-order
  // linearization is a model witness for its logical stores, not vector order
  // or a fabricated order between independent harts or publication sources.
  std::vector<std::optional<OperationId>> final_writers(publish.bytes.size());
  for (const auto &member : members) {
    const auto &store = member.second->store;
    if (store.address < publish.address || store.address - publish.address >= publish.bytes.size() ||
        store.mask.size() > publish.bytes.size() - (store.address - publish.address))
      return remember_failure(invalid("coalesced publication does not contain a member's byte range"));
    const size_t offset = store.address - publish.address;
    for (size_t byte = 0; byte < store.mask.size(); ++byte) {
      if (store.mask[byte] > 1)
        return remember_failure(invalid("coalesced LocalStore contains a nonbinary byte mask"));
      if (store.mask[byte])
        final_writers[offset + byte] = member.first;
    }
  }
  for (size_t byte = 0; byte < publish.byte_mask.size(); ++byte) {
    if (bool(publish.byte_mask[byte]) != final_writers[byte].has_value())
      return remember_failure(invalid("coalesced publication mask differs from its logical member union"));
    if (!publish.byte_mask[byte])
      continue;
    if (publish.byte_writers[byte] != *final_writers[byte])
      return remember_failure(invalid("coalesced byte writer is not the latest enabled program-order member"));
    const auto &store = members.at(*final_writers[byte])->store;
    if (publish.bytes[byte] != store.bytes[publish.address + byte - store.address])
      return remember_failure(invalid("coalesced publication byte differs from its final LocalStore writer"));
  }

  ObservationTime first_time;
  auto result = require_rank(event, first_time);
  if (!result)
    return result;
  if (members.size() - 1 > std::numeric_limits<uint64_t>::max() - first_time.rank)
    return remember_failure(invalid("coalesced publication logical rank space exhausted"));
  std::map<OperationId, MemoryWriter> writer_ids;
  std::vector<MemoryWriter> completed;
  std::vector<ObservationTime> times;
  for (const auto &member : members) {
    MemoryWriter writer;
    result = checker_.memory_writer(member.first, writer);
    if (!result)
      return remember_failure(result);
    writer_ids.emplace(member.first, writer);
    completed.push_back(writer);
    times.push_back({first_time.rank + times.size(), true});
  }
  std::vector<MemoryWriter> byte_writers(publish.bytes.size());
  for (size_t byte = 0; byte < publish.byte_mask.size(); ++byte)
    if (publish.byte_mask[byte])
      byte_writers[byte] = writer_ids.at(publish.byte_writers[byte]);
  result = checker_.observe_global(publish.address, publish.bytes, publish.byte_mask, byte_writers, completed, times);
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return remember_failure(result);
  remember_rank(event, times.back(), RankCertificate::None, members.rbegin()->first, 0);
  for (const auto &member : members)
    member.second->published = true;
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

CheckResult CheckerEventConsumer::consume_squash(const InstructionSquashEvent &event) {
  if (event.id.subaccess != 0)
    return remember_failure(unsupported("split instruction squash is not covered by this consumer"));
  const auto parent = instruction_id(event.id);
  auto allocation = allocations_.find(parent);
  if (allocation == allocations_.end())
    return remember_failure(invalid("instruction squash has no live allocation"));
  for (const auto &store : stores_)
    if (same_parent(store.first, parent))
      return remember_failure(invalid("architecturally committed LocalStore cannot be squashed"));

  for (auto load = loads_.begin(); load != loads_.end();) {
    if (!same_parent(load->first.first, parent)) {
      ++load;
      continue;
    }
    auto result = checker_.cancel_load(load->first.first, load->first.second);
    if (!result)
      return remember_failure(result);
    load = loads_.erase(load);
  }
  for (auto cancelled = cancelled_loads_.begin(); cancelled != cancelled_loads_.end();) {
    if (same_parent(cancelled->first, parent))
      cancelled = cancelled_loads_.erase(cancelled);
    else
      ++cancelled;
  }
  allocations_.erase(allocation);
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
        return pending("retirement awaits the selected load-attempt sample");
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

CheckResult CheckerEventConsumer::consume_closed(const RuntimeEvent &event, bool source_prefix_closed) {
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
  case RuntimeEventKind::InstructionSquash:
    return consume_squash(std::get<InstructionSquashEvent>(event.payload));
  case RuntimeEventKind::LocalStore:
    return consume_local_store(std::get<LocalStoreEvent>(event.payload));
  case RuntimeEventKind::LoadSample:
    return consume_load_sample(event, std::get<LoadSampleEvent>(event.payload), RankCertificate::None,
                               source_prefix_closed);
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
