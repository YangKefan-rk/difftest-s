#include "native_adapter.h"
#include <algorithm>
#include <limits>
#include <utility>

namespace rocket_difftest {
using namespace rvwmo;
namespace {
bool ordinary_store(const InstructionObservation &instruction) {
  return instruction.memory && instruction.memory_command == 1;
}
CheckResult pending(const char *message) { return {CheckStatus::Pending, 0, message}; }
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }

bool scalar_width_matches(const InstructionObservation &instruction, uint8_t size) {
  const auto raw = instruction.instruction;
  if (instruction.length == 4 && ((raw & 0x7f) == 0x03 || (raw & 0x7f) == 0x23 ||
      (raw & 0x7f) == 0x07 || (raw & 0x7f) == 0x27))
    return size == ((raw >> 12) & 3);
  if (instruction.length == 2 && ((raw & 3) == 0 || (raw & 3) == 2)) {
    const auto function = (raw >> 13) & 7;
    if (function == 2 || function == 6)
      return size == 2;
    if (function == 1 || function == 3 || function == 5 || function == 7)
      return size == 3;
  }
  return true; // Opaque speculative extensions are rejected at retirement.
}
} // namespace

NativeAdapter::NativeAdapter(NativeConfiguration configuration)
    : configuration_(configuration), emitter_(configuration.emitter), cache_(configuration.cache),
      capture_({configuration.emitter.hart, configuration.emitter.epoch, configuration.emitter.capacity}) {
  remember(emitter_.finalize());
  remember(cache_.finalize());
  remember(capture_.finalize());
}

CheckResult NativeAdapter::remember(CheckResult result) {
  if (failure_ && !result && result.status != CheckStatus::Pending)
    failure_ = result;
  return failure_ ? result : failure_;
}

CaptureResult NativeAdapter::finish_input(CheckResult result) {
  if (!result && result.status != CheckStatus::Pending)
    return {remember(std::move(result)), true};
  auto progress = poll();
  if (!progress)
    return {std::move(progress), true};
  return {std::move(result), true};
}

CaptureResult NativeAdapter::allocate(const InstructionObservation &allocation) {
  if (!failure_)
    return {failure_, false};
  // Every subordinate live record belongs to this bounded union, so neither
  // begin nor capture allocation can hit capacity after this admission check.
  if (instructions_.size() >= configuration_.emitter.capacity)
    return {pending("Rocket native instruction capacity reached"), false};
  OperationId id;
  auto result = emitter_.begin(allocation, id);
  if (!result)
    return {remember(std::move(result)), false};
  result = capture_.allocate(allocation, id);
  if (!result) {
    if (result.status == CheckStatus::Pending)
      result = invalid("Rocket capture capacity disagrees with native instruction admission");
    return finish_input(std::move(result));
  }
  instructions_.emplace(allocation.token,
    Instruction{allocation, id, std::nullopt, std::nullopt, std::nullopt, 0, false, false, false, false});
  tokens_by_uid_.emplace(id.uid, allocation.token);
  return finish_input({});
}

CaptureResult NativeAdapter::bind_request(const CoreRequest &core, const CacheRequest &cache) {
  if (!failure_)
    return {failure_, false};
  auto instruction = instructions_.find(core.token);
  if (instruction == instructions_.end() || instruction->second.request ||
      instruction->second.semantic_retire_done || core.attempt != instruction->second.next_attempt)
    return {remember(invalid("Rocket native request has an unknown token or stale attempt")), false};
  const auto &allocation = instruction->second.allocation;
  if (!allocation.memory || core.request.command != allocation.memory_command ||
      !scalar_width_matches(allocation, core.request.size))
    return {remember(invalid("Rocket native request disagrees with allocation memory decode or scalar width")), false};
  if (requests_.size() >= configuration_.cache.capacity)
    return {pending("Rocket native cache request capacity reached"), false};
  auto result = cache_.bind(core, cache);
  if (!result)
    return {remember(std::move(result)), false};
  requests_.emplace(cache.request_id, Request{core, false, false, std::nullopt, std::nullopt});
  instruction->second.request = cache.request_id;
  return finish_input({});
}

CaptureResult NativeAdapter::cancel_request(uint64_t request_id) {
  if (!failure_)
    return {failure_, false};
  auto request = requests_.find(request_id);
  if (request == requests_.end())
    return {remember(invalid("Rocket native cancellation has no live request")), false};
  auto &instruction = instructions_.at(request->second.core.token);
  if (instruction.retirement || request->second.store_accepted || request->second.publication ||
      request->second.publication_group ||
      instruction.next_attempt == std::numeric_limits<uint32_t>::max())
    return {remember(invalid("Rocket native cancellation retracts a committed or exhausted attempt")), false};
  if (request->second.core.request.command == 0) {
    auto result = emitter_.cancel_load(request->second.core.token, request->second.core.attempt);
    if (!result)
      return finish_input(std::move(result));
    result = capture_.cancel_load_attempt(request->second.core.token);
    if (!result)
      return finish_input(std::move(result));
  }
  auto result = cache_.release(request_id);
  if (!result)
    return finish_input(std::move(result));
  instruction.request.reset();
  ++instruction.next_attempt;
  requests_.erase(request);
  return finish_input({});
}

CaptureResult NativeAdapter::sample_load(const CacheLoadResult &load) {
  if (!failure_)
    return {failure_, false};
  auto request = requests_.find(load.request_id);
  if (request == requests_.end() || request->second.sampled)
    return {remember(invalid("Rocket native load sample is unknown or duplicated")), false};
  LoadObservation observation;
  auto result = cache_.load_sample(load, observation);
  if (result) {
    result = emitter_.sample_load(observation);
    if (!result)
      return finish_input(std::move(result));
  } else if (result.status != CheckStatus::Pending) {
    return finish_input(std::move(result));
  }
  // Opaque wrong-path data stays private; its eventual retirement is rejected.
  request->second.sampled = true;
  return finish_input(std::move(result));
}

CaptureResult NativeAdapter::atomic(const rvwmo::AtomicLifecycleEvent &record,
                                        const rvwmo::SourcePosition &source) {
  if (!failure_)
    return {failure_, false};
  auto token = tokens_by_uid_.find(record.id.uid);
  if (token == tokens_by_uid_.end())
    return {remember(invalid("Rocket atomic lifecycle has no live instruction")), false};
  auto instruction = instructions_.find(token->second);
  if (instruction == instructions_.end() || instruction->second.semantic_retire_done)
    return {remember(invalid("Rocket atomic lifecycle has no live instruction")), false};
  auto result = emitter_.atomic(token->second, record, source);
  if (!result)
    return finish_input(std::move(result));
  if (record.phase == AtomicObservationPhase::WriteEffect &&
      record.fuop != 2 && record.fuop != 3 && record.fuop != 6 && record.fuop != 7)
    instruction->second.publication_done = true;
  return finish_input({});
}

CaptureResult NativeAdapter::atomic_candidate(uint64_t token, const AtomicCommitCandidateEvent &candidate,
                                                const SourcePosition &source) {
  if (!failure_)
    return {failure_, false};
  auto instruction = instructions_.find(token);
  if (instruction == instructions_.end() || !instruction->second.request ||
      instruction->second.semantic_retire_done || instruction->second.publication_done ||
      instruction->second.id != candidate.id || *instruction->second.request != candidate.request_id ||
      instruction->second.next_attempt != candidate.attempt)
    return {remember(invalid("Rocket AMO candidate has no matching live final cache attempt")), false};
  auto request = requests_.find(candidate.request_id);
  if (request == requests_.end() || request->second.core.token != token ||
      request->second.core.attempt != candidate.attempt || request->second.publication ||
      request->second.publication_group)
    return {remember(invalid("Rocket AMO candidate changed its final request identity")), false};
  auto result = emitter_.atomic_candidate(token, candidate, source);
  if (!result)
    return finish_input(std::move(result));
  request->second.store_accepted = true;
  instruction->second.publication_done = true;
  return finish_input({});
}

CaptureResult NativeAdapter::accept_store(const CacheStoreValue &store) {
  if (!failure_)
    return {failure_, false};
  auto request = requests_.find(store.request_id);
  if (request == requests_.end() || request->second.store_accepted)
    return {remember(invalid("Rocket native store acceptance is unknown or duplicated")), false};
  auto result = cache_.accept_store(store);
  if (!result && result.status != CheckStatus::Pending)
    return finish_input(std::move(result));
  request->second.store_accepted = true;
  return finish_input(std::move(result));
}

CheckResult NativeAdapter::store_member(uint64_t request_id, CacheStoreMember &member) const {
  if (!failure_)
    return failure_;
  return cache_.store_member(request_id, member);
}

CaptureResult NativeAdapter::publish_group(const StoreGroupObservation &group, uint64_t transaction) {
  if (!failure_)
    return {failure_, false};
  if (!transaction || group.members.empty() ||
      group.members.size() > configuration_.cache.capacity || pending_publication_groups_.count(transaction))
    return {remember(invalid("Rocket merged publication has invalid transaction or group evidence")), false};

  PendingStoreGroup pending_group;
  pending_group.observation = group;
  pending_group.transaction = transaction;
  for (const auto &member : group.members) {
    auto request = requests_.find(member.request_id);
    if (request == requests_.end() || !request->second.store_accepted || request->second.publication ||
        request->second.publication_group || request->second.core.token != member.store.token ||
        request->second.core.attempt != member.attempt)
      return {remember(invalid("Rocket merged publication member has no matching accepted cache request")), false};
    pending_group.request_ids.push_back(member.request_id);
  }
  for (const auto request_id : pending_group.request_ids)
    requests_.at(request_id).publication_group = transaction;
  pending_publication_groups_.emplace(transaction, std::move(pending_group));
  return finish_input({});
}

CaptureResult NativeAdapter::retire(const NativeRetireFact &fact) {
  if (!failure_)
    return {failure_, false};
  auto instruction = instructions_.find(fact.retirement.token);
  if (instruction == instructions_.end() || instruction->second.retirement)
    return {remember(invalid("Rocket native retirement is unknown or duplicated")), false};
  auto result = capture_.retire(fact.retirement);
  if (!result)
    return finish_input(std::move(result));
  instruction->second.retirement = fact;
  if (instruction->second.late_write) {
    result = capture_.late_write(*instruction->second.late_write);
    if (!result)
      return finish_input(std::move(result));
  }
  pending_retirements_.insert(fact.retirement.token);
  return finish_input({});
}

CaptureResult NativeAdapter::late_write(const NativeLateWrite &write) {
  if (!failure_)
    return {failure_, false};
  if (!write.identity_known)
    return {remember({CheckStatus::Incomplete, 0, "Rocket native late writeback lacks instruction identity"}), false};
  auto instruction = instructions_.find(write.token);
  if (instruction == instructions_.end() || instruction->second.late_write || instruction->second.snapshot_done)
    return {remember(invalid("Rocket native late writeback is unknown or duplicated")), false};
  instruction->second.late_write = write;
  if (!instruction->second.retirement)
    return finish_input(pending("Rocket native late writeback awaits its original retirement fact"));
  return finish_input(capture_.late_write(write));
}

CaptureResult NativeAdapter::floating_write(const NativeFpWrite &write) {
  if (!failure_)
    return {failure_, false};
  const auto instruction = instructions_.find(write.token);
  if (!write.identity_known || instruction == instructions_.end() || instruction->second.snapshot_done)
    return {remember({CheckStatus::Incomplete, 0,
        "Rocket native floating-point writeback lacks a live instruction identity"}), false};
  return finish_input(capture_.floating_write(write));
}

CaptureResult NativeAdapter::squash(uint64_t token) {
  if (!failure_)
    return {failure_, false};
  auto instruction = instructions_.find(token);
  if (instruction != instructions_.end() && instruction->second.retirement)
    return {remember(invalid("Rocket native squash cannot retract architectural retirement")), false};
  auto result = emitter_.squash(token);
  if (!result)
    return finish_input(std::move(result));
  result = capture_.squash(token);
  if (!result)
    return finish_input(std::move(result));
  if (instruction != instructions_.end() && instruction->second.request) {
    const auto request_id = *instruction->second.request;
    auto request = requests_.find(request_id);
    if (request != requests_.end() && (request->second.store_accepted || request->second.publication))
      return finish_input(invalid("Rocket native squash retracts an accepted physical store"));
    cache_.discard_instruction(token);
    pending_publications_.erase(request_id);
    requests_.erase(request_id);
  }
  if (instruction != instructions_.end())
    tokens_by_uid_.erase(instruction->second.id.uid);
  instructions_.erase(token);
  return finish_input({});
}

CaptureResult NativeAdapter::publish(const QualifiedStorePublication &publication) {
  if (!failure_)
    return {failure_, false};
  auto request = requests_.find(publication.actual.request_id);
  if (request == requests_.end() || request->second.publication || !publication.transaction)
    return {remember(invalid("Rocket native publication is unknown, duplicated or lacks a transaction")), false};
  if (request->second.publication_group)
    return {remember(invalid("Rocket store already belongs to a merged publication")), false};
  if (request->second.core.request.command != 1)
    return {remember({CheckStatus::Unsupported, 0, "Rocket native publication is not an ordinary store"}), false};
  request->second.publication = publication;
  pending_publications_.insert(publication.actual.request_id);
  return finish_input({});
}

CheckResult NativeAdapter::flush_retirements() {
  while (!pending_retirements_.empty()) {
    const auto token = *pending_retirements_.begin();
    auto &instruction = instructions_.at(token);
    const auto &fact = *instruction.retirement;
    const uint32_t raw = instruction.allocation.instruction;
    const bool rmw = (raw & 0x7f) == 0x2f && (raw >> 27) != 2 && (raw >> 27) != 3;
    if (rmw && !instruction.publication_done)
      return pending("Rocket AMO retirement awaits its final physical-drain candidate");
    if (ordinary_store(instruction.allocation) && !instruction.local_store_done) {
      if (!instruction.request)
        return pending("Rocket native store retirement awaits its request and data");
      StoreObservation store;
      auto result = cache_.local_store(token, fact.local_store_source, store);
      if (!result)
        return remember(std::move(result));
      result = emitter_.commit_store(store);
      if (!result)
        return remember(std::move(result));
      instruction.local_store_done = true;
    }
    auto result = emitter_.retire(token, fact.retirement.source);
    if (!result)
      return remember(std::move(result));
    instruction.semantic_retire_done = true;
    pending_retirements_.erase(token);
    if (!ordinary_store(instruction.allocation) && instruction.request) {
      const auto request_id = *instruction.request;
      result = cache_.release(request_id);
      if (!result)
        return remember(std::move(result));
      requests_.erase(request_id);
      instruction.request.reset();
    }
    collect_instruction(token);
  }
  return {};
}

CheckResult NativeAdapter::flush_publications() {
  for (auto next = pending_publication_groups_.begin(); next != pending_publication_groups_.end();) {
    auto &group = next->second;
    StorePublicationGroup publication;
    publication.transaction = group.transaction;
    size_t first_lane = group.observation.actual_bytes.size();
    size_t last_lane = 0;
    for (size_t lane = 0; lane < group.observation.actual_bytes.size(); ++lane)
      if (group.observation.logical_mask & (1u << lane)) {
        first_lane = std::min(first_lane, lane);
        last_lane = lane;
      }
    if (first_lane >= group.observation.actual_bytes.size())
      return remember(invalid("Rocket store group has no logical written byte"));
    const size_t interval = last_lane - first_lane + 1;
    publication.address = group.observation.word_address + first_lane;
    publication.bytes.assign(group.observation.actual_bytes.begin() + first_lane,
                             group.observation.actual_bytes.begin() + last_lane + 1);
    publication.mask.resize(interval);
    publication.byte_writer_tokens.resize(interval);
    publication.source = group.observation.source;
    if (group.observation.physical_mask & ~group.observation.logical_mask) {
      rvwmo::PhysicalStoreWrite physical;
      physical.address = group.observation.word_address;
      physical.bytes.assign(group.observation.actual_bytes.begin(), group.observation.actual_bytes.end());
      for (size_t lane = 0; lane < physical.bytes.size(); ++lane)
        physical.byte_mask.push_back((group.observation.physical_mask >> lane) & 1);
      publication.physical_write = std::move(physical);
    }
    for (size_t byte = 0; byte < interval; ++byte) {
      const size_t lane = first_lane + byte;
      publication.mask[byte] = (group.observation.logical_mask >> lane) & 1;
      if (!publication.mask[byte])
        continue;
      if (!group.observation.byte_writer_requests[lane])
        return remember(invalid("Rocket merged publication omits a final byte-writer identity"));
      auto request = requests_.find(*group.observation.byte_writer_requests[lane]);
      if (request == requests_.end() || request->second.publication_group != group.transaction)
        return remember(invalid("Rocket merged publication writer is not a retained group member"));
      publication.byte_writer_tokens[byte] = request->second.core.token;
    }
    for (const auto request_id : group.request_ids) {
      auto request = requests_.find(request_id);
      if (request == requests_.end() || request->second.publication_group != group.transaction)
        return remember(invalid("Rocket merged publication lost a logical request before output"));
      publication.member_tokens.push_back(request->second.core.token);
    }
    auto result = emitter_.publish_store_group(publication);
    if (result.status == CheckStatus::Pending) {
      ++next;
      continue;
    }
    if (!result)
      return remember(std::move(result));

    for (const auto request_id : group.request_ids) {
      auto request = requests_.find(request_id);
      const auto token = request->second.core.token;
      result = cache_.release(request_id);
      if (!result)
        return remember(std::move(result));
      auto &instruction = instructions_.at(token);
      instruction.publication_done = true;
      instruction.request.reset();
      requests_.erase(request);
      collect_instruction(token);
    }
    next = pending_publication_groups_.erase(next);
  }

  for (auto next = pending_publications_.begin(); next != pending_publications_.end();) {
    const auto request_id = *next;
    auto &request = requests_.at(request_id);
    if (!request.store_accepted) {
      ++next;
      continue;
    }
    const auto token = request.core.token;
    const auto &fact = *request.publication;
    StoreObservation store;
    auto result = cache_.publication(fact.actual, store);
    if (result)
      result = emitter_.publish_store(store, fact.transaction);
    if (result.status == CheckStatus::Pending) {
      ++next;
      continue;
    }
    if (!result)
      return remember(std::move(result));
    result = cache_.release(request_id);
    if (!result)
      return remember(std::move(result));
    auto &instruction = instructions_.at(token);
    instruction.publication_done = true;
    instruction.request.reset();
    requests_.erase(request_id);
    next = pending_publications_.erase(next);
    collect_instruction(token);
  }
  return {};
}

void NativeAdapter::collect_instruction(uint64_t token) {
  auto found = instructions_.find(token);
  if (found == instructions_.end())
    return;
  const auto &instruction = found->second;
  if (instruction.semantic_retire_done && instruction.snapshot_done &&
      (!ordinary_store(instruction.allocation) || instruction.publication_done)) {
    tokens_by_uid_.erase(instruction.id.uid);
    instructions_.erase(found);
  }
}

void NativeAdapter::collect_output() {
  if (output_.serial)
    return;
  auto batch = emitter_.take_batch();
  auto captured = capture_.take_ready();
  if (batch.events.empty() && batch.watermarks.empty() && captured.empty())
    return;
  if (!next_output_serial_) {
    remember(invalid("Rocket native output serial exhausted"));
    return;
  }
  output_.serial = next_output_serial_++;
  output_.batch = std::move(batch);
  for (const auto &snapshot : captured) {
    auto destination = ArchitecturalDestination::None;
    if (snapshot.floating_write)
      destination = ArchitecturalDestination::FloatingPoint;
    else if (snapshot.integer_write)
      destination = ArchitecturalDestination::Integer;
    output_.retirements.push_back({snapshot.id, snapshot.pc, snapshot.instruction,
      destination, snapshot.destination, snapshot.value, snapshot.fcsr});
    const auto token = tokens_by_uid_.find(snapshot.id.uid);
    if (token == tokens_by_uid_.end()) {
      remember(invalid("Rocket native snapshot has no logical-to-native identity mapping"));
      return;
    }
    const auto native_token = token->second;
    instructions_.at(native_token).snapshot_done = true;
    collect_instruction(native_token);
  }
}

CheckResult NativeAdapter::poll() {
  if (!failure_)
    return failure_;
  collect_output();
  if (!failure_)
    return failure_;
  auto retirements = flush_retirements();
  if (!retirements && retirements.status != CheckStatus::Pending)
    return retirements;
  auto publications = flush_publications();
  if (!publications)
    return publications;
  collect_output();
  if (!failure_)
    return failure_;
  if (!pending_retirements_.empty() || !pending_publications_.empty() || !pending_publication_groups_.empty())
    return pending("Rocket native joins await a final sample, store, retirement or output capacity");
  return {};
}

CheckResult NativeAdapter::close_hart_prefix(uint64_t cycle) {
  auto result = poll();
  if (!result && result.status != CheckStatus::Pending)
    return result;
  result = emitter_.close_through(cycle);
  if (!result)
    return remember(std::move(result));
  collect_output();
  return failure_;
}

const NativeOutput *NativeAdapter::output() const { return output_.serial ? &output_ : nullptr; }

CheckResult NativeAdapter::acknowledge_output(uint64_t serial) {
  if (!failure_)
    return failure_;
  if (!serial || serial != output_.serial)
    return remember(invalid("Rocket native output acknowledgement is stale or unknown"));
  output_ = {};
  return poll();
}

CheckResult NativeAdapter::finalize() const {
  if (!failure_)
    return failure_;
  if (output_.serial || !instructions_.empty() || !requests_.empty() || !pending_retirements_.empty() ||
      !pending_publications_.empty() || !pending_publication_groups_.empty())
    return pending("Rocket native adapter has live facts, joins or undelivered output");
  for (const auto &result : {emitter_.finalize(), cache_.finalize(), capture_.finalize()})
    if (!result)
      return result;
  return {};
}

} // namespace rocket_difftest
