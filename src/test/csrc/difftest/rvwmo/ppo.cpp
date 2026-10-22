#include "ppo.h"
#include <algorithm>
#include <limits>
#include <sstream>

namespace rvwmo {
namespace {
DependencySummary stamp(const MemoryOperation &operation, bool latest) {
  DependencySummary result;
  if (operation.load)
    result = {true, operation.read_time.rank, operation.id};
  if (operation.store &&
      (!result.valid || (latest ? operation.write_time.rank > result.rank : operation.write_time.rank < result.rank)))
    result = {true, operation.write_time.rank, operation.id};
  return result;
}
CheckResult require_before(const DependencySummary &before, const MemoryOperation &after, unsigned rule) {
  if (!before.valid || before.rank < stamp(after, false).rank)
    return {};
  std::ostringstream text;
  text << "PPO rule " << rule << ": hart " << after.id.hart << " uid " << before.source.uid << " rank " << before.rank
       << " must precede uid " << after.id.uid << " rank " << stamp(after, false).rank;
  return {CheckStatus::Violation, rule, text.str()};
}
} // namespace

CheckResult PpoChecker::check_operation(HartState &h, const MemoryOperation &op, const DependencyMetadata &metadata) {
  auto check = [&](const DependencySummary &source, unsigned rule) { return require_before(source, op, rule); };
  CheckResult result;
  for (size_t byte = 0; byte < op.byte_mask.size(); ++byte) {
    if (!op.byte_mask[byte])
      continue;
    auto found = h.bytes.find(op.address + byte);
    if (found != h.bytes.end()) {
      const auto &state = found->second;
      if (op.store && !(result = check(state.access, 1)))
        return result;
      if (op.load)
        for (const auto &read: state.reads)
          if (read.time.valid && read.writer != op.read_sources[byte] && !(result = check(read.time, 2)))
            return result;
    }
    if (op.load) {
      const auto &writer = op.read_sources[byte];
      auto source = h.store_dependencies.find(writer);
      if (source != h.store_dependencies.end() && !(result = check(source->second, 12)))
        return result;
      auto atomic = h.reservation_reads.find(writer);
      // Atomic read-source ordering is kept independently of current register dependencies.
      if (atomic != h.reservation_reads.end() && !(result = check(atomic->second, 3)))
        return result;
    }
  }
  if (op.load && !(result = check(h.fence_read, 4)))
    return result;
  if (op.store && !(result = check(h.fence_write, 4)))
    return result;
  if (!(result = check(h.acquire, 5)))
    return result;
  if (op.release && !(result = check(h.all, 6)))
    return result;
  if (op.rcsc && !(result = check(h.rcsc, 7)))
    return result;
  if (op.sc) {
    if (!op.has_paired_lr)
      return {CheckStatus::Invalid, 8, "successful SC lacks paired LR identity"};
    auto lr = h.reservation_reads.find(op.paired_lr);
    if (lr == h.reservation_reads.end())
      return {CheckStatus::Invalid, 8, "paired LR is unavailable"};
    if (!(result = check(lr->second, 8)))
      return result;
  }
  if (!(result = check(h.dependencies.read(metadata.address_sources), 9)))
    return result;
  if (op.store) {
    if (!(result = check(h.dependencies.read(metadata.data_sources), 10)))
      return result;
    if (!(result = check(h.control, 11)))
      return result;
    if (!(result = check(h.address_prefix, 13)))
      return result;
  }
  return {};
}

void PpoChecker::update_operation(HartState &h, const MemoryOperation &op, const DependencyMetadata &metadata) {
  const auto time = stamp(op, true);
  DependencySummary read_time{op.load, op.read_time.rank, op.id};
  for (size_t byte = 0; byte < op.byte_mask.size(); ++byte) {
    if (!op.byte_mask[byte])
      continue;
    auto &state = h.bytes[op.address + byte];
    state.access.include(time);
    if (op.store)
      state.reads = {};
    if (op.load && !op.store) {
      auto &reads = state.reads;
      if (reads[0].time.valid && reads[0].writer == op.read_sources[byte])
        reads[0].time.include(read_time);
      else if (reads[1].time.valid && reads[1].writer == op.read_sources[byte])
        reads[1].time.include(read_time);
      else if (!reads[0].time.valid)
        reads[0] = {op.read_sources[byte], read_time};
      else if (!reads[1].time.valid || read_time.rank > reads[1].time.rank)
        reads[1] = {op.read_sources[byte], read_time};
      if (reads[1].time.valid && (!reads[0].time.valid || reads[1].time.rank > reads[0].time.rank))
        std::swap(reads[0], reads[1]);
    }
  }
  if (op.store) {
    auto sources = h.dependencies.read(metadata.address_sources);
    sources.include(h.dependencies.read(metadata.data_sources));
    h.store_dependencies[op.id] = sources;
  }
  if (op.atomic || op.sc)
    h.reservation_reads[op.id] = time;
  if (op.lr)
    h.reservation_reads[op.id] = read_time;
  h.all.include(time);
  if (op.load)
    h.reads.include(time);
  if (op.store)
    h.writes.include(time);
  if (op.acquire)
    h.acquire.include(time);
  if (op.rcsc)
    h.rcsc.include(time);
  h.address_prefix.include(h.dependencies.read(metadata.address_sources));
}

CheckResult PpoChecker::retire(const RetiredInstruction &instruction) {
  auto &hart = harts_[instruction.hart];
  if (hart.pending && hart.pending_uid != instruction.uid)
    return {CheckStatus::Invalid, 0, "younger retirement overtook an unresolved instruction"};
  if (hart.has_retired && hart.epoch != instruction.epoch)
    return {CheckStatus::Invalid, 0, "epoch changed without reset_hart"};
  if (hart.has_retired && instruction.uid <= hart.last_uid)
    return {CheckStatus::Invalid, 0, "retirement UID must increase within a hart epoch"};
  DependencyMetadata metadata = instruction.dependencies;
  if (!metadata.provided) {
    auto result = decode_dependencies(instruction.instruction, metadata);
    if (!result)
      return result;
  }
  if (!metadata.complete)
    return {CheckStatus::Unsupported, 0, "incomplete external dependency metadata"};
  if (instruction.failed_sc) {
    if (!instruction.memory.empty())
      return {CheckStatus::Invalid, 0, "failed SC must not contain a memory operation"};
    // RVWMO defines SC's syntactic destination only on success. REF still writes
    // architectural rd on failure, but that does not kill its dependency carrier.
    metadata.destinations.clear();
    metadata.destination_sources.clear();
  }
  if (!metadata.destination_sources.empty() && metadata.destination_sources.size() != metadata.destinations.size())
    return {CheckStatus::Invalid, 0, "dependency destination carrier count mismatch"};
  for (const auto &op: instruction.memory) {
    if (op.id.hart != instruction.hart || op.id.uid != instruction.uid || op.id.epoch != instruction.epoch)
      return {CheckStatus::Invalid, 0, "memory operation identity differs from retired instruction"};
    if (!op.load && !op.store)
      return {CheckStatus::Invalid, 0, "memory event has no read or write effect"};
    if ((op.load && !op.read_time.valid) || (op.store && !op.write_time.valid)) {
      hart.pending = true;
      hart.pending_uid = instruction.uid;
      return {CheckStatus::Pending, 0, "retired operation awaits its observation timestamp"};
    }
    if (op.byte_mask.empty() ||
        std::none_of(op.byte_mask.begin(), op.byte_mask.end(), [](uint8_t byte) { return byte != 0; }) ||
        op.address > std::numeric_limits<uint64_t>::max() - (op.byte_mask.size() - 1))
      return {CheckStatus::Invalid, 0, "invalid byte range"};
    if (op.load && op.read_sources.size() != op.byte_mask.size()) {
      hart.pending = true;
      hart.pending_uid = instruction.uid;
      return {CheckStatus::Pending, 2, "load awaits byte writer identities"};
    }
  }
  // Check first, mutate second: a failed instruction cannot contaminate summaries.
  for (const auto &op: instruction.memory) {
    auto result = check_operation(hart, op, metadata);
    if (!result)
      return result;
  }
  if (metadata.fence) {
    DependencySummary predecessors;
    if (metadata.fence_predecessor & 2)
      predecessors.include(hart.reads);
    if (metadata.fence_predecessor & 1)
      predecessors.include(hart.writes);
    if (metadata.fence_predecessor & 12 || metadata.fence_successor & 12)
      return {CheckStatus::Unsupported, 4, "I/O fence domain is not represented by memory events"};
    if (metadata.fence_successor & 2)
      hart.fence_read.include(predecessors);
    if (metadata.fence_successor & 1)
      hart.fence_write.include(predecessors);
  }
  if (metadata.control_transfer)
    hart.control.include(hart.dependencies.read(metadata.sources));
  DependencySummary generated_read;
  for (const auto &op: instruction.memory) {
    update_operation(hart, op, metadata);
    if (op.load)
      generated_read.include({true, op.read_time.rank, op.id});
    // A successful SC is a memory operation whose status destination can carry
    // syntactic dependencies. Failed SCs have no memory event to contribute.
    if (op.sc && op.store)
      generated_read.include({true, op.write_time.rank, op.id});
  }
  auto propagated = hart.dependencies.propagate(metadata, generated_read);
  if (!propagated)
    return propagated;
  hart.epoch = instruction.epoch;
  hart.last_uid = instruction.uid;
  hart.has_retired = true;
  hart.pending = false;
  return {};
}

CheckResult PpoChecker::finalize() const {
  for (const auto &entry: harts_)
    if (entry.second.pending)
      return {CheckStatus::Pending, 0, "PPO checker has unresolved retired observations"};
  return {};
}
void PpoChecker::reset_hart(uint32_t hart, uint64_t epoch) {
  harts_[hart] = {};
  harts_[hart].epoch = epoch;
}
void PpoChecker::release_writer(const OperationId &writer) {
  auto found = harts_.find(writer.hart);
  if (found == harts_.end())
    return;
  found->second.store_dependencies.erase(writer);
  found->second.reservation_reads.erase(writer);
}
size_t PpoChecker::address_count() const {
  size_t count = 0;
  for (const auto &entry: harts_)
    count += entry.second.bytes.size();
  return count;
}
} // namespace rvwmo
