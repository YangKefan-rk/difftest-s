#include "store_groups.h"
#include <algorithm>
#include <utility>

namespace rocket_difftest {
using namespace rvwmo;

StoreGroupTracker::StoreGroupTracker(StoreGroupConfiguration configuration) : configuration_(configuration) {
  const auto bytes = configuration_.ecc_bytes;
  if (!configuration_.capacity || !bytes || bytes > 8 || (bytes & (bytes - 1)))
    reject(CheckStatus::Invalid, "Rocket store groups require an RV64 ECC granule and nonzero capacity");
}

CheckResult StoreGroupTracker::reject(CheckStatus status, const char *message) {
  failure_ = {status, 0, message};
  return failure_;
}

bool StoreGroupTracker::valid_source(SourcePosition source) const {
  return source.producer_sequence && source.qualified_phase != SourcePosition::cycle_closed_phase &&
         (!last_source_cycle_ || source.cycle >= *last_source_cycle_);
}

uint8_t StoreGroupTracker::physical_mask(uint8_t logical_mask) const {
  unsigned expanded = 0;
  const unsigned granule = (1U << configuration_.ecc_bytes) - 1;
  for (unsigned first = 0; first < 8; first += configuration_.ecc_bytes) {
    const unsigned lanes = granule << first;
    if (logical_mask & lanes)
      expanded |= lanes;
  }
  return expanded;
}

void StoreGroupTracker::append_member(Group &group, const CacheStoreMember &member) {
  auto &observation = group.observation;
  observation.members.push_back(member);
  const auto first = member.store.address & 7;
  for (size_t byte = 0; byte < member.store.bytes.size(); ++byte) {
    const auto lane = first + byte;
    observation.logical_mask |= 1U << lane;
    observation.byte_writer_requests[lane] = member.request_id;
    group.expected_bytes[lane] = member.store.bytes[byte];
  }
}

CheckResult StoreGroupTracker::accept(const CacheStoreMember &member) {
  if (!failure_)
    return failure_;
  const auto &store = member.store;
  const auto bytes = store.bytes.size();
  if (!member.request_id || (last_request_ && member.request_id <= *last_request_) ||
      !bytes || bytes > 8 || (bytes & (bytes - 1)) || store.address & (bytes - 1) ||
      bytes != store.mask.size() || (store.address & 7) + bytes > 8 ||
      std::any_of(store.mask.begin(), store.mask.end(), [](uint8_t mask) { return mask != 1; }) ||
      !valid_source(store.source) || (last_accept_cycle_ && store.source.cycle == *last_accept_cycle_))
    return reject(CheckStatus::Invalid, "Rocket store group member identity, extent, mask or source is invalid");
  if (first_slot_)
    return reject(CheckStatus::Invalid, "Rocket store acceptance overwrites an occupied first pstore slot");
  if (live_members_ >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket store group member capacity reached"};
  Group group;
  group.observation.anchor_request_id = member.request_id;
  group.observation.word_address = store.address & ~uint64_t{7};
  group.latest_transition = store.source;
  append_member(group, member);
  groups_.emplace(member.request_id, std::move(group));
  first_slot_ = member.request_id;
  last_request_ = member.request_id;
  ++live_members_;
  last_source_cycle_ = store.source.cycle;
  last_accept_cycle_ = store.source.cycle;
  return {};
}

CheckResult StoreGroupTracker::advance(uint64_t request_id, SourcePosition source) {
  if (!failure_)
    return failure_;
  if (!first_slot_ || *first_slot_ != request_id || second_slot_ || !valid_source(source))
    return reject(CheckStatus::Invalid, "Rocket pstore advance has no matching free-slot transition");
  auto &group = groups_.at(request_id);
  if (source.cycle < group.latest_transition.cycle)
    return reject(CheckStatus::Invalid, "Rocket pstore advance predates accepted store data");
  group.latest_transition = source;
  group.transitioned = true;
  second_slot_ = request_id;
  first_slot_.reset();
  last_source_cycle_ = source.cycle;
  return {};
}

CheckResult StoreGroupTracker::merge(uint64_t request_id, uint64_t target_request_id, SourcePosition source) {
  if (!failure_)
    return failure_;
  if (configuration_.ecc_bytes == 1)
    return reject(CheckStatus::Unsupported, "Rocket one-byte ECC granules do not support pstore merging");
  if (!first_slot_ || *first_slot_ != request_id || !second_slot_ || *second_slot_ != target_request_id ||
      request_id == target_request_id || !valid_source(source))
    return reject(CheckStatus::Invalid, "Rocket pstore merge has no matching member and second-slot target");
  auto &target = groups_.at(target_request_id);
  auto &incoming = groups_.at(request_id);
  const auto &member = incoming.observation.members.front();
  if (target.drained || incoming.drained || incoming.observation.members.size() != 1 ||
      incoming.observation.word_address != target.observation.word_address ||
      member.store.token <= target.observation.members.back().store.token ||
      source.cycle <= target.latest_transition.cycle || source.cycle < incoming.latest_transition.cycle ||
      (physical_mask(incoming.observation.logical_mask) & ~physical_mask(target.observation.logical_mask)))
    return reject(CheckStatus::Invalid, "Rocket pstore merge changes its word, local order or stored ECC granules");
  append_member(target, member);
  target.latest_transition = source;
  target.transitioned = true;
  groups_.erase(request_id);
  first_slot_.reset();
  last_source_cycle_ = source.cycle;
  return {};
}

CheckResult StoreGroupTracker::capture_drain(const CacheStoreDrain &drain, StoreGroupObservation &observation) {
  if (!failure_)
    return failure_;
  const auto &slot = drain.second_slot ? second_slot_ : first_slot_;
  const auto found = groups_.find(drain.actual.request_id);
  if (!slot || *slot != drain.actual.request_id || found == groups_.end() || found->second.drained ||
      (!drain.second_slot && second_slot_) || !valid_source(drain.actual.source) ||
      (last_drain_cycle_ && drain.actual.source.cycle == *last_drain_cycle_))
    return reject(CheckStatus::Invalid, "Rocket pstore drain has no matching live physical slot");
  auto &group = found->second;
  if (!drain.second_slot && group.observation.members.front().store.bytes.size() < configuration_.ecc_bytes)
    return reject(CheckStatus::Invalid, "Rocket partial ECC store requires pstore2 read-modify-write before drain");
  if (drain.actual.physical_address != group.observation.members.front().store.address ||
      drain.actual.source.cycle < group.latest_transition.cycle ||
      (group.transitioned && drain.actual.source.cycle == group.latest_transition.cycle) ||
      drain.actual.mask != group.observation.logical_mask ||
      drain.physical_mask != physical_mask(group.observation.logical_mask))
    return reject(CheckStatus::Invalid, "Rocket pstore drain changes its address, source, logical or ECC mask");
  for (unsigned lane = 0; lane < 8; ++lane) {
    const auto actual = static_cast<uint8_t>(drain.actual.data >> (8 * lane));
    if ((drain.actual.mask & (1U << lane)) && actual != group.expected_bytes[lane])
      return reject(CheckStatus::Violation, "Rocket pstore drain bytes differ from retained logical members");
    group.observation.actual_bytes[lane] = actual;
  }
  group.observation.physical_mask = drain.physical_mask;
  group.observation.source = drain.actual.source;
  observation = group.observation;
  group.drained = true;
  if (drain.second_slot)
    second_slot_.reset();
  else
    first_slot_.reset();
  last_source_cycle_ = drain.actual.source.cycle;
  last_drain_cycle_ = drain.actual.source.cycle;
  return {};
}

CheckResult StoreGroupTracker::acknowledge_drain(uint64_t anchor_request_id) {
  if (!failure_)
    return failure_;
  const auto found = groups_.find(anchor_request_id);
  if (found == groups_.end() || !found->second.drained)
    return reject(CheckStatus::Invalid, "Rocket store group acknowledgement has no captured drain");
  live_members_ -= found->second.observation.members.size();
  groups_.erase(found);
  return {};
}

CheckResult StoreGroupTracker::finalize() const {
  if (!failure_)
    return failure_;
  if (first_slot_ || second_slot_ || !groups_.empty())
    return {CheckStatus::Pending, 0, "Rocket store groups have physical slots or undelivered members"};
  return {};
}

} // namespace rocket_difftest
