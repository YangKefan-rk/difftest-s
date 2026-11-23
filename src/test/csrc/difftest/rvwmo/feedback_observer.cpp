#include "feedback_observer.h"
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace rvwmo {
namespace {
OperationId instruction_id(OperationId operation) {
  operation.subaccess = 0;
  return operation;
}

bool ordinary_scalar(const MemoryOperation &operation) {
  return (operation.load != operation.store) && !operation.atomic && !operation.lr && !operation.sc &&
         operation.id.subaccess == 0 && !operation.byte_mask.empty() && operation.byte_mask.size() <= 8;
}

struct RetiredMemory {
  const MemoryOperation *operation;
  const FeedbackRetirement *retirement;
};

FeedbackMemoryEffect effect_for(const RetiredMemory &memory, const RuntimeEvent &event,
                                ObservationTime order) {
  return {*memory.operation, memory.retirement->instruction.pc, event.producer_id,
          event.source, memory.retirement->producer_id, memory.retirement->source, order,
          0, 0, false, 0, {}, {}};
}
} // namespace

FeedbackEvidenceCollector::FeedbackEvidenceCollector(size_t max_records) : max_records_(max_records) {
  if (!max_records_)
    throw std::invalid_argument("feedback evidence requires a positive record bound");
}

void FeedbackEvidenceCollector::observe(const RuntimeEvent &event, const ObservationTime &order) {
  if (event.kind != RuntimeEventKind::InstructionRetire && event.kind != RuntimeEventKind::LoadSample &&
      event.kind != RuntimeEventKind::StorePublish)
    return;
  if (retirements_.size() + memory_.size() >= max_records_)
    throw std::runtime_error("feedback evidence exhausted its case-local record bound");
  if (event.kind == RuntimeEventKind::InstructionRetire) {
    if (order.valid)
      throw std::runtime_error("retirement feedback cannot carry a memory-order rank");
    retirements_.push_back({std::get<InstructionRetireEvent>(event.payload).instruction,
                           event.producer_id, event.source});
  } else {
    if (!order.valid || !order.rank)
      throw std::runtime_error("memory feedback lacks its accepted checker rank");
    memory_.push_back({event, order});
  }
}

std::vector<FeedbackMemoryEffect> FeedbackEvidenceCollector::scalar_memory_effects() const {
  std::map<OperationId, RetiredMemory> retired;
  std::set<OperationId> instructions;
  for (const auto &retirement : retirements_) {
    const auto &instruction = retirement.instruction;
    const OperationId owner{instruction.hart, instruction.epoch, instruction.uid, 0};
    if (!instructions.insert(owner).second)
      throw std::runtime_error("feedback repeats a retired instruction identity");
    for (const auto &operation : instruction.memory) {
      if (instruction_id(operation.id) != owner ||
          !retired.emplace(operation.id, RetiredMemory{&operation, &retirement}).second)
        throw std::runtime_error("feedback retired memory identity does not identify its instruction");
    }
  }

  std::vector<FeedbackMemoryEffect> effects;
  std::set<OperationId> loads, stores;
  for (const auto &observed : memory_) {
    const auto &event = observed.event;
    if (event.kind == RuntimeEventKind::LoadSample) {
      const auto &sample = std::get<LoadSampleEvent>(event.payload).operation;
      const auto found = retired.find(sample.id);
      if (found == retired.end() || sample.attempt != found->second.operation->attempt)
        continue; // Accepted sampling can precede cancellation or a final replay.
      const auto &operation = *found->second.operation;
      if (!ordinary_scalar(operation))
        continue;
      if (!operation.load || sample.address != operation.address || sample.byte_mask != operation.byte_mask ||
          !loads.insert(operation.id).second)
        throw std::runtime_error("feedback final load differs from its retired source operation");
      effects.push_back(effect_for(found->second, event, observed.order));
      continue;
    }

    const auto &publication = std::get<StorePublishEvent>(event.payload);
    auto members = publication.members;
    if (members.empty())
      throw std::runtime_error("feedback publication has no logical writer members");
    if (members.size() > 1 && (!publication.coalesced_program_order || !observed.order.isolated_store_group))
      throw std::runtime_error("feedback coalesced publication lacks its checker program-order witness");
    std::sort(members.begin(), members.end(), [](const auto &left, const auto &right) {
      return left.id < right.id;
    });
    for (size_t index = 0; index < members.size(); ++index) {
      const auto &member = members[index];
      const auto found = retired.find(member.id);
      if (found == retired.end())
        throw std::runtime_error("feedback store publication has no retired source instruction");
      const auto &operation = *found->second.operation;
      if (!ordinary_scalar(operation))
        throw std::runtime_error("feedback publication is outside ordinary scalar load/store scope");
      if (!operation.store || operation.attempt != member.attempt || !stores.insert(operation.id).second)
        throw std::runtime_error("feedback store publication repeats or changes its final writer attempt");
      if (index > std::numeric_limits<uint64_t>::max() - observed.order.rank)
        throw std::runtime_error("feedback publication rank offset overflowed");
      auto order = observed.order;
      order.rank += index;
      auto effect = effect_for(found->second, event, order);
      effect.publication_transaction = publication.transaction_id;
      effect.publication_generation = publication.allocation_generation;
      effect.coalesced_program_order = publication.coalesced_program_order;
      effect.publication_address = publication.address;
      effect.publication_byte_mask = publication.byte_mask;
      effect.publication_byte_writers = publication.byte_writers;
      effects.push_back(std::move(effect));
    }
  }
  for (const auto &[id, memory] : retired) {
    const auto &operation = *memory.operation;
    if (!ordinary_scalar(operation))
      continue;
    if ((operation.load && !loads.count(id)) || (operation.store && !stores.count(id)))
      throw std::runtime_error("feedback omitted a final retired scalar memory effect");
  }
  return effects;
}

} // namespace rvwmo
