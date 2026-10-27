#include "checker.h"
#include <limits>
#include <algorithm>
#include <stdexcept>

namespace rvwmo {
namespace {
CheckResult invalid(const std::string &message) {
  return {CheckStatus::Invalid, 0, message};
}
CheckResult pending(const std::string &message) {
  return {CheckStatus::Pending, 0, message};
}
MemoryOperation lrsc_operand(const MemoryOperation &operation) {
  auto operand = operation;
  auto first = std::find_if(operand.byte_mask.begin(), operand.byte_mask.end(), [](uint8_t byte) { return byte != 0; });
  auto last = std::find_if(operand.byte_mask.rbegin(), operand.byte_mask.rend(), [](uint8_t byte) { return byte != 0; });
  if (first == operand.byte_mask.end())
    return operand;
  const size_t offset = first - operand.byte_mask.begin();
  operand.address += offset;
  operand.byte_mask = std::vector<uint8_t>(first, last.base());
  return operand;
}

CheckResult accepted_event(CheckResult result) {
  return result.status == CheckStatus::Pending ? CheckResult{} : result;
}
bool memory_free_dependencies(const RetiredInstruction &instruction, DependencyMetadata &metadata) {
  if (!instruction.memory.empty() || instruction.failed_sc)
    return false;
  metadata = instruction.dependencies;
  if (!metadata.provided && !decode_dependencies(instruction.instruction, metadata))
    return false;
  return metadata.provided && metadata.complete && !metadata.fence && metadata.address_sources.empty() &&
         metadata.data_sources.empty();
}

bool ordinary_store(const MemoryOperation &operation) {
  return operation.store && !operation.load && !operation.atomic && !operation.lr && !operation.sc &&
         !operation.acquire && !operation.release && !operation.rcsc;
}

bool statistics_fit(const CheckMemoryStatistics &current, const CheckMemoryStatistics &delta) {
  constexpr auto maximum = std::numeric_limits<uint64_t>::max();
  return delta.verified_load_operations <= maximum - current.verified_load_operations &&
         delta.verified_store_operations <= maximum - current.verified_store_operations &&
         delta.cross_hart_reads <= maximum - current.cross_hart_reads &&
         delta.store_audits <= maximum - current.store_audits;
}
} // namespace

Checker::Checker(Memory &memory, size_t max_statistics_harts)
    : memory_(memory), max_statistics_harts_(max_statistics_harts) {
  if (!max_statistics_harts_ || max_statistics_harts_ > 4096)
    throw std::invalid_argument("Checker statistics require a hart bound in 1..4096");
}

CheckResult Checker::ensure_statistics_hart(uint32_t hart) {
  if (!memory_statistics_.count(hart)) {
    if (memory_statistics_.size() >= max_statistics_harts_)
      return invalid("checker memory-statistics hart bound exceeded");
    memory_statistics_.emplace(hart, CheckMemoryStatistics{});
  }
  return {};
}

CheckResult Checker::verified_memory_delta(const RetiredInstruction &instruction,
                                            CheckMemoryStatistics &delta) const {
  for (const auto &operation : instruction.memory) {
    if (operation.store && operation.write_time.valid)
      ++delta.verified_store_operations;
    if (!operation.load)
      continue;
    ++delta.verified_load_operations;
    const auto &snapshot = loads_.at({operation.id, operation.attempt}).snapshot;
    for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte) {
      if (!operation.byte_mask[byte] || !snapshot.bytes[byte].writer)
        continue;
      const auto source = writers_.find(*snapshot.bytes[byte].writer);
      if (source == writers_.end())
        return invalid("verified load snapshot lost its canonical store identity");
      if (source->second.hart != operation.id.hart) {
        ++delta.cross_hart_reads;
        break;
      }
    }
  }
  return {};
}

CheckResult Checker::remember_failure(CheckResult result) {
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    failure_ = result;
  return result;
}

OperationId Checker::initialization_writer(uint64_t address) {
  return {std::numeric_limits<uint32_t>::max(), 0, address, 0};
}

CheckResult Checker::memory_writer(const OperationId &operation, MemoryWriter &writer) {
  if (!failure_)
    return failure_;
  auto statistics = ensure_statistics_hart(operation.hart);
  if (!statistics)
    return remember_failure(statistics);
  auto found = operation_writers_.find(operation);
  if (found != operation_writers_.end()) {
    writer = found->second;
    return {};
  }
  if (exhausted_writer_harts_.count(operation.hart))
    return remember_failure(invalid("memory writer identity space exhausted"));
  auto &next = next_writer_uid_[operation.hart];
  if (!next)
    next = 1; // Memory reserves zero for unavailable provenance.
  while (writers_.count({operation.hart, next})) {
    if (next == std::numeric_limits<uint64_t>::max())
      return remember_failure(invalid("memory writer identity space exhausted"));
    ++next;
  }
  writer = {operation.hart, next};
  operation_writers_[operation] = writer;
  writers_[writer] = operation;
  if (next == std::numeric_limits<uint64_t>::max())
    exhausted_writer_harts_.insert(operation.hart);
  else
    ++next;
  return {};
}

CheckResult Checker::record_store(const MemoryStore &store, const MemoryOperation &operation,
                                  StoreVerification verification) {
  if (!failure_)
    return failure_;
  if (!operation.store || store.writer.hart != operation.id.hart)
    return remember_failure(invalid("store model identity differs from observed operation"));
  if (store.address != operation.address || store.mask != operation.byte_mask)
    return remember_failure(invalid("store model address/mask differs from observed operation"));
  auto prior_writer = writers_.find(store.writer);
  auto prior_operation = operation_writers_.find(operation.id);
  if (stores_.count(operation.id) || (prior_writer != writers_.end() && prior_writer->second != operation.id) ||
      (prior_operation != operation_writers_.end() && !(prior_operation->second == store.writer)))
    return remember_failure(invalid("duplicate store identity or MemoryWriter identity collision"));
  auto statistics = ensure_statistics_hart(operation.id.hart);
  if (!statistics)
    return remember_failure(statistics);
  auto error = memory_.commit_local(store);
  if (!error.empty())
    return remember_failure(invalid(error));
  writers_[store.writer] = operation.id;
  operation_writers_[operation.id] = store.writer;
  auto &next = next_writer_uid_[store.writer.hart];
  if (store.writer.uid >= next) {
    if (store.writer.uid == std::numeric_limits<uint64_t>::max())
      exhausted_writer_harts_.insert(store.writer.hart);
    else
      next = store.writer.uid + 1;
  }
  stores_[operation.id] = operation;
  if (verification == StoreVerification::Provisional)
    unverified_stores_[operation.id] = store;
  return accepted_event(poll());
}

CheckResult Checker::verify_store(const OperationId &operation, const MemoryStore &reference) {
  if (!failure_)
    return failure_;
  auto found = unverified_stores_.find(operation);
  if (found == unverified_stores_.end())
    return remember_failure(invalid("store verification references an unknown or already verified operation"));
  const auto &candidate = found->second;
  bool matches = reference.writer == candidate.writer && reference.po == candidate.po &&
                 reference.address == candidate.address && reference.mask == candidate.mask &&
                 reference.bytes.size() == candidate.bytes.size();
  if (matches)
    for (size_t byte = 0; byte < candidate.mask.size(); ++byte)
      if (candidate.mask[byte] && candidate.bytes[byte] != reference.bytes[byte])
        matches = false;
  if (!matches)
    return remember_failure({CheckStatus::Violation, 0,
                             "REF store differs from provisional store hart " + std::to_string(operation.hart) +
                                 " uid " + std::to_string(operation.uid)});
  auto &statistics = memory_statistics_.at(operation.hart);
  if (statistics.store_audits == std::numeric_limits<uint64_t>::max())
    return remember_failure(invalid("checker store-audit counter exhausted"));
  unverified_stores_.erase(found);
  ++statistics.store_audits;
  return accepted_event(poll());
}

CheckResult Checker::get_expected_load(const OperationId &operation, uint32_t attempt, std::vector<uint8_t> &bytes) {
  if (!failure_)
    return failure_;
  auto found = loads_.find({operation, attempt});
  if (found == loads_.end())
    return pending("expected load awaits its observed final-attempt sample");
  auto error = memory_.resolve_modeled(found->second.snapshot);
  if (error.find("modeled read awaits") != std::string::npos)
    return pending(error);
  if (!error.empty())
    return remember_failure({CheckStatus::Violation, 0, error});
  auto result = require_verified_sources(found->second.snapshot);
  if (!result)
    return remember_failure(result);
  bytes.clear();
  for (const auto &byte: found->second.snapshot.bytes)
    bytes.push_back(byte.value);
  return {};
}

CheckResult Checker::get_reference_candidate_load(const OperationId &operation, uint32_t attempt,
                                                  std::vector<uint8_t> &bytes) {
  if (!failure_)
    return failure_;
  auto found = loads_.find({operation, attempt});
  if (found == loads_.end())
    return pending("reference candidate awaits load observation");
  auto error = memory_.resolve_candidate(found->second.snapshot);
  if (error.find("candidate read awaits") != std::string::npos)
    return pending(error);
  if (!error.empty())
    return remember_failure({CheckStatus::Violation, 0, error});
  bytes.clear();
  for (const auto &byte: found->second.snapshot.bytes)
    bytes.push_back(byte.value);
  return {};
}

CheckResult Checker::observe_global(uint64_t address, const std::vector<uint8_t> &bytes,
                                    const std::vector<uint8_t> &mask, const std::vector<MemoryWriter> &writers,
                                    const std::vector<MemoryWriter> &completed, ObservationTime time) {
  if (completed.size() > 1)
    return remember_failure(invalid("merged completion requires one logical timestamp per store"));
  return observe_global(address, bytes, mask, writers, completed, std::vector<ObservationTime>(completed.size(), time));
}

CheckResult Checker::observe_global(uint64_t address, const std::vector<uint8_t> &bytes,
                                    const std::vector<uint8_t> &mask, const std::vector<MemoryWriter> &writers,
                                    const std::vector<MemoryWriter> &completed,
                                    const std::vector<ObservationTime> &completion_times) {
  if (!failure_)
    return failure_;
  if (completed.size() != completion_times.size())
    return remember_failure(invalid("logical completion timestamp count differs from completed stores"));
  for (size_t i = 0; i < completed.size(); ++i) {
    const auto &writer = completed[i];
    const auto &time = completion_times[i];
    if (!time.valid)
      return pending("global store completion has no observation rank");
    auto found = writers_.find(writer);
    if (found == writers_.end())
      return pending("global completion precedes local store record");
    const auto &operation = stores_.at(found->second);
    if (operation.write_time.valid && operation.write_time.rank != time.rank)
      return remember_failure(invalid("store has inconsistent global-completion timestamps"));
  }
  std::vector<uint64_t> ranks;
  for (const auto &time: completion_times)
    ranks.push_back(time.rank);
  auto error = memory_.commit_global(address, bytes, mask, writers, completed, ranks);
  if (!error.empty())
    return remember_failure(invalid(error));
  for (size_t i = 0; i < completed.size(); ++i) {
    const auto &operation = writers_.at(completed[i]);
    stores_.at(operation).write_time = completion_times[i];
    completed_stores_.insert(operation);
    auto deferred = retired_pending_publication_.find(operation);
    if (deferred != retired_pending_publication_.end()) {
      auto resolved = ppo_.observe_store(operation, completion_times[i]);
      if (!resolved)
        return remember_failure(resolved);
      auto &statistics = memory_statistics_.at(operation.hart);
      if (statistics.verified_store_operations == std::numeric_limits<uint64_t>::max())
        return remember_failure(invalid("verified-store counter exhausted"));
      ++statistics.verified_store_operations;
      retired_pending_publication_.erase(deferred);
    }
  }
  std::vector<size_t> ordered(completed.size());
  for (size_t i = 0; i < ordered.size(); ++i)
    ordered[i] = i;
  std::sort(ordered.begin(), ordered.end(), [&](size_t a, size_t b) {
    return completion_times[a].rank < completion_times[b].rank;
  });
  for (size_t i : ordered) {
    const auto &operation = stores_.at(writers_.at(completed[i]));
    if (operation.sc) {
      StoreConditionalEvidence evidence;
      auto result = lrsc_.capture_sc(lrsc_operand(operation), evidence);
      if (!result)
        return remember_failure(result);
      if (!sc_evidence_.emplace(operation.id, std::move(evidence)).second)
        return remember_failure(invalid("duplicate successful-SC evidence"));
    }
    auto result = lrsc_.observe_store(operation);
    if (!result)
      return remember_failure(result);
  }
  return accepted_event(poll());
}

CheckResult Checker::observe_load(const MemoryOperation &operation, uint64_t po,
                                  const std::vector<std::optional<MemoryWriter>> &forwarded, bool source_prefix_closed) {
  if (!failure_)
    return failure_;
  if (!operation.load)
    return remember_failure(invalid("load observation lacks read effect"));
  if (!operation.read_time.valid)
    return pending("load observation has no rank");
  LoadKey key{operation.id, operation.attempt};
  if (loads_.count(key))
    return remember_failure(invalid("duplicate load attempt observation"));
  auto statistics = ensure_statistics_hart(operation.id.hart);
  if (!statistics)
    return remember_failure(statistics);
  MemorySnapshot snapshot;
  auto error = memory_.sample(operation.id.hart, po, operation.read_time.rank, operation.address, operation.byte_mask,
                              forwarded, snapshot, source_prefix_closed);
  if (!error.empty())
    return remember_failure(invalid(error));
  loads_.emplace(key, LoadSample{operation, std::move(snapshot)});
  return accepted_event(poll());
}

CheckResult Checker::cancel_load(const OperationId &operation, uint32_t attempt) {
  if (!failure_)
    return failure_;
  auto found = loads_.find({operation, attempt});
  if (found == loads_.end())
    return remember_failure(invalid("cancellation references unknown load attempt"));
  auto error = memory_.release(found->second.snapshot.id);
  if (!error.empty())
    return remember_failure(invalid(error));
  loads_.erase(found);
  return {};
}

CheckResult Checker::release_store(const OperationId &operation) {
  if (!failure_)
    return failure_;
  if (unverified_stores_.count(operation))
    return pending("store still awaits independent REF verification");
  if (ppo_.has_pending_reference(operation))
    return pending("store still participates in deferred PPO obligations");
  if (!checked_stores_.count(operation) || !completed_stores_.count(operation))
    return remember_failure(invalid("writer release requires global completion and checked retirement"));
  if (memory_.has_global_reference(operation_writers_.at(operation)))
    return pending("writer still supplies one or more GlobalMem bytes");
  if (memory_.has_snapshot_reference(operation_writers_.at(operation)))
    return pending("writer still referenced by a snapshot candidate or baseline");
  auto references = [&](const MemoryOperation &sample) {
    if (sample.id == operation)
      return true;
    for (const auto &source: sample.read_sources)
      if (source == operation)
        return true;
    return false;
  };
  for (auto &sample: loads_) {
    if (references(sample.second.operation))
      return pending("writer still referenced by a captured load");
  }
  for (const auto &hart: retirements_)
    for (const auto &retirement: hart.second)
      for (const auto &sample: retirement.instruction.memory)
        if (references(sample))
          return pending("writer still referenced by queued retirement");
  ppo_.release_writer(operation);
  released_stores_.push_back(operation);
  stores_.erase(operation);
  writers_.erase(operation_writers_.at(operation));
  operation_writers_.erase(operation);
  checked_stores_.erase(operation);
  completed_stores_.erase(operation);
  return {};
}

CheckResult Checker::collect_garbage() {
  if (!failure_)
    return failure_;
  for (const auto &writer: memory_.take_reclaimable_writers())
    reclaim_candidates_.insert(writer);
  for (auto candidate = reclaim_candidates_.begin(); candidate != reclaim_candidates_.end();) {
    auto writer = writers_.find(*candidate);
    if (writer == writers_.end()) {
      candidate = reclaim_candidates_.erase(candidate);
      continue;
    }
    const auto operation = writer->second;
    if (ppo_.has_pending_reference(operation) || unverified_stores_.count(operation) || !checked_stores_.count(operation) ||
        !completed_stores_.count(operation) || memory_.has_global_reference(*candidate) ||
        memory_.has_snapshot_reference(*candidate)) {
      ++candidate;
      continue;
    }
    auto result = release_store(operation);
    if (result.status == CheckStatus::Pending) {
      ++candidate;
      continue;
    }
    if (!result)
      return result;
    candidate = reclaim_candidates_.erase(candidate);
  }
  return {};
}

std::vector<OperationId> Checker::take_released_stores() {
  auto released = std::move(released_stores_);
  released_stores_.clear();
  return released;
}

CheckResult Checker::require_verified_sources(const MemorySnapshot &snapshot) const {
  for (size_t byte = 0; byte < snapshot.mask.size(); ++byte) {
    if (!snapshot.mask[byte] || !snapshot.bytes[byte].writer)
      continue;
    auto writer = writers_.find(*snapshot.bytes[byte].writer);
    if (writer == writers_.end())
      return invalid("load snapshot writer has no registered store identity");
    if (unverified_stores_.count(writer->second))
      return pending("load source awaits independent REF store verification: hart=" +
                     std::to_string(writer->second.hart) + " uid=" + std::to_string(writer->second.uid));
  }
  return {};
}

CheckResult Checker::prepare(Retirement &retirement) {
  for (auto &operation: retirement.instruction.memory) {
    if (operation.store) {
      auto store = stores_.find(operation.id);
      if (store == stores_.end())
        return pending("retired store awaits independently verified store record");
      if (unverified_stores_.count(operation.id))
        return pending("retired store awaits independent REF verification");
      operation.write_time = store->second.write_time;
      if (!operation.write_time.valid && !ordinary_store(operation))
        return pending("retired store awaits global-completion timestamp");
    }
    if (!operation.load)
      continue;
    auto load = loads_.find({operation.id, operation.attempt});
    if (load == loads_.end())
      return pending("retired load awaits final-attempt observation");
    const auto &observed = load->second.operation;
    if (operation.address != observed.address || operation.byte_mask != observed.byte_mask)
      return invalid("retirement address/mask differs from observed final load attempt");
    operation.read_time = observed.read_time;
    operation.source_kind = observed.source_kind;
    operation.read_sources.clear();
    if (operation.source_kind == ReadSourceKind::Unavailable)
      return pending("load has neither observed source identities nor a model witness request");
    auto error = operation.source_kind == ReadSourceKind::ModeledWitness
                     ? memory_.resolve_modeled(load->second.snapshot)
                     : memory_.resolve(load->second.snapshot);
    if (error == "forwarded source store has not locally committed" ||
        error.find("forwarding identity required") != std::string::npos ||
        error.find("modeled read awaits") != std::string::npos)
      return pending(error);
    if (!error.empty())
      return {CheckStatus::Violation, 0, error};
    auto verified = require_verified_sources(load->second.snapshot);
    if (!verified)
      return verified;
    if (!operation.atomic && !operation.lr && !operation.sc) {
      for (const auto &writer : memory_.unpublished_sources(load->second.snapshot)) {
        auto source = writers_.find(writer);
        if (source == writers_.end())
          return invalid("certified local source has no canonical operation identity");
        if (ppo_.has_pending_reference(source->second)) {
          auto ordered = ppo_.observe_store_after(source->second, operation.read_time);
          if (!ordered)
            return ordered;
        }
      }
    }
    if (operation.lr)
      for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte)
        if (operation.byte_mask[byte] && !load->second.snapshot.bytes[byte].writer_time)
          return pending("LR source awaits its global write rank");
    if (operation.source_kind == ReadSourceKind::Observed) {
      operation.read_sources = observed.read_sources;
      if (operation.read_sources.size() != operation.byte_mask.size())
        return pending("load awaits observed byte-writer identities");
    } else {
      // Only the resolved model snapshot may supply a modeled witness. Caller
      // read_sources are deliberately ignored; actual bytes are checked later.
      for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte) {
        const auto &source = load->second.snapshot.bytes[byte].writer;
        if (!operation.byte_mask[byte] || !source) {
          operation.read_sources.push_back(initialization_writer(operation.address + byte));
          continue;
        }
        auto writer = writers_.find(*source);
        if (writer == writers_.end())
          return pending("canonical snapshot writer has no registered operation identity");
        operation.read_sources.push_back(writer->second);
      }
    }
    bool actual_found = false;
    for (const auto &actual: retirement.loads)
      if (actual.id == operation.id) {
        if (actual_found || actual.bytes.size() != operation.byte_mask.size())
          return invalid("duplicate or incorrectly sized retired load value");
        actual_found = true;
      }
    if (!actual_found)
      return pending("retired load awaits its actual value bytes");
  }
  return {};
}

CheckResult Checker::drain(uint32_t hart) {
  auto &queue = retirements_[hart];
  while (!queue.empty()) {
    auto &front = queue.front();
    auto result = prepare(front);
    if (!result)
      return remember_failure(result);
    CheckMemoryStatistics delta;
    if (!front.instruction.memory.empty()) {
      result = verified_memory_delta(front.instruction, delta);
      if (!result)
        return remember_failure(result);
      if (!statistics_fit(memory_statistics_.at(hart), delta))
        return remember_failure(invalid("checker verified-memory counter exhausted"));
    }
    // Bind the most recent LR in architectural order. SC evidence was captured
    // at the write point, so unrelated later writes cannot alter this decision.
    for (auto &operation : front.instruction.memory) {
      if (operation.lr) {
        const auto operand = lrsc_operand(operation);
        std::vector<uint64_t> sources(operand.byte_mask.size());
        const auto &snapshot = loads_.at({operation.id, operation.attempt}).snapshot;
        const size_t offset = operand.address - operation.address;
        for (size_t byte = 0; byte < sources.size(); ++byte)
          if (operand.byte_mask[byte])
            sources[byte] = *snapshot.bytes[offset + byte].writer_time;
        result = lrsc_.retire_lr(operand, sources);
        if (!result)
          return remember_failure(result);
        auto previous = reserved_lr_.find(operation.id.hart);
        if (previous != reserved_lr_.end())
          ppo_.release_writer(previous->second);
        reserved_lr_[operation.id.hart] = operation.id;
      }
      if (operation.sc) {
        auto evidence = sc_evidence_.find(operation.id);
        result = lrsc_.retire_sc(lrsc_operand(operation), evidence == sc_evidence_.end() ? nullptr : &evidence->second,
                                  true, operation.paired_lr);
        if (!result)
          return remember_failure(result);
        operation.has_paired_lr = true;
      }
    }
    if (front.instruction.failed_sc) {
      MemoryOperation failed;
      failed.id = {front.instruction.hart, front.instruction.epoch, front.instruction.uid, 0};
      failed.sc = true;
      OperationId ignored;
      result = lrsc_.retire_sc(failed, nullptr, false, ignored);
      if (!result)
        return remember_failure(result);
    }
    // PPO must succeed before any value comparison. A value failure is terminal;
    // retry never applies already accepted PPO state a second time.
    result = ppo_.retire_deferred(front.instruction);
    if (!result)
      return remember_failure(result);
    for (const auto &operation: front.instruction.memory) {
      if (!operation.load)
        continue;
      auto &sample = loads_.at({operation.id, operation.attempt});
      for (const auto &actual: front.loads)
        if (actual.id == operation.id) {
          if (operation.source_kind == ReadSourceKind::ModeledWitness) {
            for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte)
              if (operation.byte_mask[byte] && sample.snapshot.bytes[byte].value != actual.bytes[byte])
                return remember_failure(
                    {CheckStatus::Violation, 0,
                     "load value differs from modeled fixed-order witness: hart=" +
                         std::to_string(operation.id.hart) + " uid=" + std::to_string(operation.id.uid) +
                         " pc=" + std::to_string(front.instruction.pc) +
                         " address=" + std::to_string(operation.address + byte) +
                         " actual=" + std::to_string(actual.bytes[byte]) +
                         " expected=" + std::to_string(sample.snapshot.bytes[byte].value)});
          } else {
            auto error = memory_.compare(sample.snapshot, actual.bytes);
            if (!error.empty())
              return remember_failure({CheckStatus::Violation, 0, error});
          }
        }
    }
    for (const auto &operation: front.instruction.memory) {
      if (!operation.load)
        continue;
      auto found = loads_.find({operation.id, operation.attempt});
      auto error = memory_.release(found->second.snapshot.id);
      if (!error.empty())
        return remember_failure(invalid(error));
      loads_.erase(found);
    }
    for (const auto &operation: front.instruction.memory)
      if (operation.store) {
        checked_stores_.insert(operation.id);
        if (!operation.write_time.valid)
          retired_pending_publication_.insert(operation.id);
      }
    bool consumed_reservation = front.instruction.failed_sc;
    for (const auto &operation : front.instruction.memory)
      if (operation.sc) {
        sc_evidence_.erase(operation.id);
        consumed_reservation = true;
      }
    if (consumed_reservation) {
      auto prior = reserved_lr_.find(front.instruction.hart);
      if (prior != reserved_lr_.end()) {
        ppo_.release_writer(prior->second);
        reserved_lr_.erase(prior);
      }
    }
    if (!front.instruction.memory.empty()) {
      auto &statistics = memory_statistics_.at(hart);
      statistics.verified_load_operations += delta.verified_load_operations;
      statistics.verified_store_operations += delta.verified_store_operations;
      statistics.cross_hart_reads += delta.cross_hart_reads;
    }
    queue.pop_front();
  }
  return {};
}

CheckResult Checker::retire(const RetiredInstruction &instruction, const std::vector<RetiredLoad> &loads) {
  if (!failure_)
    return failure_;
  if (!instruction.memory.empty()) {
    auto statistics = ensure_statistics_hart(instruction.hart);
    if (!statistics)
      return remember_failure(statistics);
  }
  auto last = last_enqueued_.find(instruction.hart);
  if (last != last_enqueued_.end() &&
      (last->second.first != instruction.epoch || last->second.second >= instruction.uid))
    return remember_failure(invalid("retirement queue requires increasing UID in one hart epoch"));
  last_enqueued_[instruction.hart] = {instruction.epoch, instruction.uid};
  auto &queue = retirements_[instruction.hart];
  DependencyMetadata first, second, composed;
  if (!queue.empty() && queue.back().loads.empty() && loads.empty() &&
      memory_free_dependencies(queue.back().instruction, first) && memory_free_dependencies(instruction, second) &&
      compose_dependencies(first, second, composed)) {
    // Keep the last UID for ordering validation; no memory operation identity is changed.
    queue.back().instruction = instruction;
    queue.back().instruction.dependencies = std::move(composed);
  } else {
    queue.push_back({instruction, loads});
  }
  auto result = drain(instruction.hart);
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    return result;
  auto collected = collect_garbage();
  return collected ? result : collected;
}

CheckResult Checker::poll() {
  if (!failure_)
    return failure_;
  CheckResult result;
  for (auto &entry: retirements_) {
    auto current = drain(entry.first);
    if (current.status != CheckStatus::Pass && current.status != CheckStatus::Pending)
      return current;
    if (current.status == CheckStatus::Pending)
      result = current;
  }
  auto collected = collect_garbage();
  return collected ? result : collected;
}

size_t Checker::pending_retirements() const {
  size_t result = 0;
  for (const auto &entry: retirements_)
    result += entry.second.size();
  return result;
}

CheckResult Checker::finalize() {
  auto result = poll();
  if (!result)
    return result;
  if (!sc_evidence_.empty())
    return pending("successful SC evidence awaits architectural retirement");
  if (!unverified_stores_.empty())
    return pending("provisional stores remain unverified by REF");
  if (checked_stores_.size() != stores_.size())
    return pending("recorded stores have not all completed PPO retirement checks");
  if (pending_retirements() || !loads_.empty() || memory_.pending_snapshots() || memory_.pending_stores())
    return pending("RVWMO finalization has outstanding retirements, samples or stores");
  return ppo_.finalize();
}
} // namespace rvwmo
