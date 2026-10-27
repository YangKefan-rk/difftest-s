#include "cache_tracker.h"
#include <limits>
#include <utility>

namespace rocket_difftest {
using namespace rvwmo;
namespace {
constexpr uint8_t integer_load = 0;  // Rocket MemoryOpConstants.M_XRD
constexpr uint8_t integer_store = 1; // Rocket MemoryOpConstants.M_XWR

unsigned requestor_bits(uint32_t requestors) {
  unsigned bits = 0;
  for (uint32_t remaining = requestors - 1; remaining; remaining >>= 1)
    ++bits;
  return bits;
}

bool valid_extent(uint64_t address, uint8_t size) {
  if (size > 3)
    return false;
  const uint64_t bytes = uint64_t{1} << size;
  return !(address & (bytes - 1)) && address <= std::numeric_limits<uint64_t>::max() - (bytes - 1);
}
} // namespace

CacheTracker::CacheTracker(CacheConfiguration configuration) : configuration_(configuration) {
  if (!configuration_.requestors || configuration_.core_requestor >= configuration_.requestors ||
      !configuration_.capacity)
    reject(CheckStatus::Invalid, "Rocket cache tracker has an invalid requestor roster or capacity");
}

CheckResult CacheTracker::reject(CheckStatus status, const char *message) {
  failure_ = {status, 0, message};
  return failure_;
}

CheckResult CacheTracker::bind(const CoreRequest &core, const CacheRequest &cache) {
  if (!failure_)
    return failure_;
  const auto bits = requestor_bits(configuration_.requestors);
  const uint64_t mask = (uint64_t{1} << bits) - 1;
  if ((cache.request.tag & mask) != configuration_.core_requestor ||
      (cache.request.tag >> bits) != core.request.tag)
    return reject(CheckStatus::Invalid, "Rocket cache request does not belong to this core handshake");
  if (!cache.request_id || (last_request_ && cache.request_id <= *last_request_) ||
      core.source.cycle != cache.source.cycle || core.request.address != cache.request.address ||
      core.request.command != cache.request.command || core.request.size != cache.request.size ||
      core.source.qualified_phase == SourcePosition::cycle_closed_phase ||
      cache.source.qualified_phase == SourcePosition::cycle_closed_phase ||
      !core.source.producer_sequence || !cache.source.producer_sequence)
    return reject(CheckStatus::Invalid, "Rocket core/cache request identity or source edge disagrees");
  // Retain non-scalar speculative requests as opaque identities. Conversion is
  // deferred until a committed operation is known to need scalar semantics.
  if (requests_.size() >= configuration_.capacity)
    return {CheckStatus::Pending, 0, "Rocket cache association capacity reached"};
  requests_.emplace(cache.request_id, Request{core, cache, std::nullopt});
  last_request_ = cache.request_id;
  return {};
}

CheckResult CacheTracker::load_sample(const CacheLoadResult &result, LoadObservation &load) {
  if (!failure_)
    return failure_;
  auto found = requests_.find(result.request_id);
  if (found == requests_.end())
    return reject(CheckStatus::Invalid, "Rocket cache load has no matching request");
  if (found->second.core.request.command == integer_load && found->second.core.request.size > 3)
    return {CheckStatus::Pending, 0, "Wide Rocket load awaits retirement or squash"};
  if (found->second.core.request.command != integer_load) {
    if (found->second.core.request.command == integer_store)
      return reject(CheckStatus::Invalid, "Rocket cache load refers to an ordinary store request");
    return {CheckStatus::Pending, 0, "Opaque Rocket load awaits retirement or squash"};
  }
  const auto &request = found->second;
  if (!request.cache.array_read)
    return reject(CheckStatus::Unsupported, "Rocket load lacks an observed SRAM read source edge");
  if (!valid_extent(result.physical_address, request.core.request.size))
    return reject(CheckStatus::Invalid, "Rocket load result has an invalid physical byte extent");
  constexpr uint64_t page_offset_mask = 0xfff;
  if ((result.physical_address & page_offset_mask) != (request.core.request.address & page_offset_mask))
    return reject(CheckStatus::Invalid, "Rocket physical load address changed the page offset");
  load = {};
  load.token = request.core.token;
  load.attempt = request.core.attempt;
  load.address = result.physical_address;
  load.source = request.cache.source;
  const size_t bytes = size_t{1} << request.core.request.size;
  load.mask.assign(bytes, 1);
  for (size_t byte = 0; byte < bytes; ++byte)
    load.bytes.push_back((result.data >> (8 * byte)) & 0xff);
  return {};
}

CheckResult CacheTracker::store_bytes(const Request &request, const CacheStoreValue &value,
                                      StoreObservation &store) {
  const auto size = request.core.request.size;
  if (!valid_extent(value.physical_address, size) ||
      value.source.qualified_phase == SourcePosition::cycle_closed_phase)
    return reject(CheckStatus::Invalid, "Rocket store has an invalid physical byte extent or source");
  const size_t bytes = size_t{1} << size;
  const unsigned first_lane = value.physical_address & 7;
  const uint64_t expected_mask = ((uint64_t{1} << bytes) - 1) << first_lane;
  if (value.mask != expected_mask || !value.source.producer_sequence)
    return reject(CheckStatus::Invalid, "Rocket ordinary store mask or source sequence is invalid");
  store = {};
  store.token = request.core.token;
  store.address = value.physical_address;
  store.source = value.source;
  store.mask.assign(bytes, 1);
  for (size_t byte = 0; byte < bytes; ++byte)
    store.bytes.push_back((value.data >> (8 * (first_lane + byte))) & 0xff);
  return {};
}

CheckResult CacheTracker::accept_store(const CacheStoreValue &value) {
  if (!failure_)
    return failure_;
  auto found = requests_.find(value.request_id);
  if (found == requests_.end() || found->second.accepted_store)
    return reject(CheckStatus::Invalid, "Rocket store acceptance is unknown or duplicate");
  if (found->second.core.request.command == integer_store && found->second.core.request.size > 3)
    return {CheckStatus::Pending, 0, "Wide Rocket store awaits retirement or squash"};
  if (found->second.core.request.command == integer_store) {
    constexpr uint64_t page_offset_mask = 0xfff;
    if ((value.physical_address & page_offset_mask) !=
        (found->second.core.request.address & page_offset_mask))
      return reject(CheckStatus::Invalid, "Rocket physical store address changed the page offset");
  }
  if (found->second.core.request.command != integer_store) {
    if (found->second.core.request.command == integer_load)
      return reject(CheckStatus::Invalid, "Rocket store acceptance refers to an ordinary load request");
    return {CheckStatus::Pending, 0, "Opaque Rocket store awaits retirement or squash"};
  }
  StoreObservation store;
  auto result = store_bytes(found->second, value, store);
  if (!result)
    return result;
  found->second.accepted_store = std::move(store);
  return {};
}

CheckResult CacheTracker::store_member(uint64_t request_id, CacheStoreMember &member) const {
  if (!failure_)
    return failure_;
  const auto found = requests_.find(request_id);
  if (found == requests_.end())
    return {CheckStatus::Invalid, 0, "Rocket store member has no matching cache request"};
  if (!found->second.accepted_store)
    return {CheckStatus::Pending, 0, "Rocket store member awaits accepted scalar store data"};
  member = {request_id, found->second.core.attempt, *found->second.accepted_store};
  return {};
}

CheckResult CacheTracker::local_store(uint64_t token, SourcePosition commit, StoreObservation &store) {
  if (!failure_)
    return failure_;
  Request *selected = nullptr;
  for (auto &entry : requests_) {
    if (entry.second.core.token != token)
      continue;
    if (selected)
      return reject(CheckStatus::Invalid, "Rocket logical store has multiple uncancelled cache attempts");
    selected = &entry.second;
  }
  if (!selected)
    return reject(CheckStatus::Invalid, "Rocket local store has no observed core/cache request");
  if (selected->core.request.command != integer_store || selected->core.request.size > 3)
    return reject(CheckStatus::Unsupported, "Rocket committed store exceeds the ordinary integer profile");
  if (!selected->accepted_store)
    return {CheckStatus::Pending, 0, "Rocket local store awaits accepted cache data"};
  if (commit.qualified_phase == SourcePosition::cycle_closed_phase || !commit.producer_sequence ||
      commit.cycle < selected->core.source.cycle)
    return reject(CheckStatus::Invalid, "Rocket local store commit has an invalid source position");
  store = *selected->accepted_store;
  store.source = commit;
  return {};
}

CheckResult CacheTracker::publication(const CacheStoreValue &value, StoreObservation &store) {
  if (!failure_)
    return failure_;
  auto found = requests_.find(value.request_id);
  if (found == requests_.end())
    return reject(CheckStatus::Invalid, "Rocket publication has no matching cache request");
  if (found->second.core.request.command != integer_store || found->second.core.request.size > 3)
    return reject(CheckStatus::Unsupported, "Rocket published store exceeds the ordinary integer profile");
  if (!found->second.accepted_store)
    return {CheckStatus::Pending, 0, "Rocket publication awaits accepted store identity"};
  if (value.physical_address != found->second.accepted_store->address)
    return reject(CheckStatus::Invalid, "Rocket pstore drain changed its physical store address");
  // Re-read actual drain bytes. Reusing accepted bytes here would hide a cache
  // corruption between acceptance and publication from the common checker.
  return store_bytes(found->second, value, store);
}

CheckResult CacheTracker::observe_merge() {
  if (!failure_)
    return failure_;
  return reject(CheckStatus::Unsupported, "Rocket cache tracker does not model merged pstore groups");
}

CheckResult CacheTracker::release(uint64_t request_id) {
  if (!failure_)
    return failure_;
  if (!requests_.erase(request_id))
    return reject(CheckStatus::Invalid, "Rocket cache release has no live request");
  return {};
}

void CacheTracker::discard_instruction(uint64_t token) {
  if (!failure_)
    return;
  for (auto request = requests_.begin(); request != requests_.end();)
    if (request->second.core.token == token)
      request = requests_.erase(request);
    else
      ++request;
}

CheckResult CacheTracker::finalize() const {
  if (!failure_)
    return failure_;
  if (!requests_.empty())
    return {CheckStatus::Pending, 0, "Rocket cache associations have not drained"};
  return {};
}

} // namespace rocket_difftest
