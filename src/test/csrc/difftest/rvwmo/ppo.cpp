#include "ppo.h"
#include <algorithm>
#include <limits>
#include <set>
#include <sstream>

namespace rvwmo {
namespace {
DependencySummary stamp(const MemoryOperation &operation, bool latest) {
  DependencySummary result;
  if (operation.load && operation.read_time.valid)
    result = {true, operation.read_time.rank, operation.id};
  if (operation.store && operation.write_time.valid &&
      (!result.valid || (latest ? operation.write_time.rank > result.rank : operation.write_time.rank < result.rank)))
    result = {true, operation.write_time.rank, operation.id};
  return result;
}
bool ordinary_store(const MemoryOperation &operation) {
  return operation.store && !operation.load && !operation.atomic && !operation.lr && !operation.sc &&
         !operation.acquire && !operation.release && !operation.rcsc && !operation.has_paired_lr;
}
} // namespace

void PpoChecker::OrderSummary::normalize() {
  for (auto store = stores.begin(); store != stores.end();) {
    const auto &clock = *store->second;
    if (!clock.time.valid) {
      ++store;
      continue;
    }
    known.include({true, clock.time.rank, clock.id});
    store = stores.erase(store);
  }
}

void PpoChecker::OrderSummary::include(const DependencySummary &other) {
  normalize();
  known.include(other);
}

void PpoChecker::OrderSummary::include(OrderSummary other) {
  normalize();
  other.normalize();
  known.include(other.known);
  stores.insert(other.stores.begin(), other.stores.end());
}

PpoChecker::OrderPoint PpoChecker::point(const MemoryOperation &operation) {
  const bool ordinary = !operation.atomic && !operation.lr && !operation.sc && !operation.acquire &&
                        !operation.release && !operation.rcsc && !operation.has_paired_lr;
  const auto first = stamp(operation, false);
  ObservationTime time;
  if (first.valid)
    time = operation.load && operation.read_time.valid && operation.read_time.rank == first.rank
             ? operation.read_time : operation.write_time;
  return {operation.id, time, ordinary && operation.load && !operation.store,
          ordinary && operation.store && !operation.load};
}

bool PpoChecker::unordered(const OrderPoint &point) {
  return (point.ordinary_load && (point.time.unordered_read_group || point.time.unordered_effect_group)) ||
         (point.ordinary_store && point.time.unordered_effect_group);
}

CheckResult PpoChecker::compare(const DependencySummary &before, const OrderPoint &after, unsigned rule) {
  if (!before.valid || before.rank < after.time.rank)
    return {};
  std::ostringstream text;
  text << "PPO rule " << rule << ": hart " << after.id.hart << " uid " << before.source.uid << " rank " << before.rank
       << " must precede uid " << after.id.uid << " rank " << after.time.rank;
  if (before.rank == after.time.rank && unordered(after))
    return {CheckStatus::Incomplete, rule, text.str() + "; the certified group lacks intra-group order evidence"};
  return {CheckStatus::Violation, rule, text.str()};
}

CheckResult PpoChecker::check_certified_after(const StoreTime &store, const OrderPoint &after, unsigned rule) {
  if (!store.after || !after.time.valid || store.after->rank < after.time.rank)
    return {};
  std::ostringstream text;
  text << "PPO rule " << rule << ": hart " << after.id.hart << " uid " << store.id.uid
       << " publication is after certified rank " << store.after->rank
       << " but must precede uid " << after.id.uid << " rank " << after.time.rank;
  return {CheckStatus::Violation, rule, text.str()};
}

void PpoChecker::tighten_upper(PendingStore &store, const OrderPoint &after, unsigned rule) {
  auto &bound = store.upper[rule];
  if (!bound || after.time.rank < bound->after.time.rank ||
      (after.time.rank == bound->after.time.rank && !unordered(after)))
    bound = UpperBound{after};
}

CheckResult PpoChecker::require_before(const DependencySummary &before, const OrderPoint &after, unsigned rule,
                                        std::vector<Constraint> &constraints) {
  if (!before.valid)
    return {};
  if (after.time.valid)
    return compare(before, after, rule);
  constraints.push_back({before, {}, after, rule});
  return {};
}

CheckResult PpoChecker::require_before(OrderSummary before, const OrderPoint &after, unsigned rule,
                                        std::vector<Constraint> &constraints) {
  before.normalize();
  auto checked = require_before(before.known, after, rule, constraints);
  if (!checked)
    return checked;
  for (const auto &store : before.stores) {
    if (store.first == after.id)
      return {CheckStatus::Invalid, rule, "PPO order summary contains the current operation"};
    auto certified = check_certified_after(*store.second, after, rule);
    if (!certified)
      return certified;
    constraints.push_back({{}, store.first, after, rule});
  }
  return {};
}

CheckResult PpoChecker::check_operation(HartState &h, const MemoryOperation &op, const DependencyMetadata &metadata,
                                        std::vector<Constraint> &constraints) {
  const auto after = point(op);
  auto check = [&](const auto &source, unsigned rule) { return require_before(source, after, rule, constraints); };
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
        for (const auto &read : state.reads)
          if (read.time.valid && read.writer != op.read_sources[byte] && !(result = check(read.time, 2)))
            return result;
    }
    if (op.load) {
      const auto &writer = op.read_sources[byte];
      auto source = h.store_dependencies.find(writer);
      if (source != h.store_dependencies.end() && !(result = check(source->second, 12)))
        return result;
      auto atomic = h.reservation_reads.find(writer);
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

CheckResult PpoChecker::validate_constraints(const HartState &hart, const std::vector<Constraint> &constraints) const {
  std::set<StorePair> new_edges;
  for (const auto &constraint : constraints) {
    if (constraint.rule == 0 || constraint.rule > 13)
      return {CheckStatus::Invalid, 0, "invalid deferred PPO rule"};
    if (constraint.pending_before && !constraint.after.time.valid) {
      const StorePair edge{*constraint.pending_before, constraint.after.id};
      if (!hart.pending_edges.count(edge))
        new_edges.insert(edge);
    }
  }
  if (new_edges.size() > max_pending_edges - std::min(max_pending_edges, hart.pending_edges.size()))
    return {CheckStatus::Incomplete, 0, "deferred PPO store-edge bound exceeded"};
  return {};
}

void PpoChecker::apply_constraints(HartState &hart, const std::vector<Constraint> &constraints) {
  for (const auto &constraint : constraints) {
    if (!constraint.pending_before) {
      hart.pending_stores.at(constraint.after.id).lower[constraint.rule].include(constraint.known_before);
    } else if (constraint.after.time.valid) {
      tighten_upper(hart.pending_stores.at(*constraint.pending_before), constraint.after, constraint.rule);
    } else {
      hart.pending_edges[{*constraint.pending_before, constraint.after.id}] |= uint16_t(1U << constraint.rule);
    }
  }
}

void PpoChecker::update_operation(HartState &h, const MemoryOperation &op, const DependencyMetadata &metadata) {
  OrderSummary time;
  time.known = stamp(op, true);
  if (op.store && !op.write_time.valid)
    time.stores.emplace(op.id, h.pending_stores.at(op.id).clock);
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
    h.reservation_reads[op.id] = time.known;
  if (op.lr)
    h.reservation_reads[op.id] = read_time;
  h.all.include(time);
  if (op.load)
    h.reads.include(time.known);
  if (op.store)
    h.writes.include(time);
  if (op.acquire)
    h.acquire.include(time.known);
  if (op.rcsc)
    h.rcsc.include(time.known);
  h.address_prefix.include(h.dependencies.read(metadata.address_sources));
}

CheckResult PpoChecker::retire(const RetiredInstruction &instruction) {
  return retire_instruction(instruction, false);
}

CheckResult PpoChecker::retire_deferred(const RetiredInstruction &instruction) {
  return retire_instruction(instruction, true);
}

CheckResult PpoChecker::retire_instruction(const RetiredInstruction &instruction, bool allow_deferred_store) {
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
    metadata.destinations.clear();
    metadata.destination_sources.clear();
  }
  if (!metadata.destination_sources.empty() && metadata.destination_sources.size() != metadata.destinations.size())
    return {CheckStatus::Invalid, 0, "dependency destination carrier count mismatch"};
  size_t deferred = 0;
  for (const auto &op : instruction.memory) {
    if (op.id.hart != instruction.hart || op.id.uid != instruction.uid || op.id.epoch != instruction.epoch)
      return {CheckStatus::Invalid, 0, "memory operation identity differs from retired instruction"};
    if (!op.load && !op.store)
      return {CheckStatus::Invalid, 0, "memory event has no read or write effect"};
    if ((op.load && !op.read_time.valid) ||
        (op.store && !op.write_time.valid && (!allow_deferred_store || !ordinary_store(op)))) {
      hart.pending = true;
      hart.pending_uid = instruction.uid;
      return {CheckStatus::Pending, 0, "retired operation awaits its observation timestamp"};
    }
    if (op.store && !op.write_time.valid)
      ++deferred;
    if (op.byte_mask.empty() ||
        std::none_of(op.byte_mask.begin(), op.byte_mask.end(), [](uint8_t byte) { return byte != 0; }) ||
        op.address > std::numeric_limits<uint64_t>::max() - (op.byte_mask.size() - 1))
      return {CheckStatus::Invalid, 0, "invalid byte range"};
    if (op.sc && (!op.has_paired_lr || !hart.reservation_reads.count(op.paired_lr)))
      return {CheckStatus::Invalid, 8, op.has_paired_lr ? "paired LR is unavailable" :
                                                        "successful SC lacks paired LR identity"};
    if (op.load && op.read_sources.size() != op.byte_mask.size()) {
      hart.pending = true;
      hart.pending_uid = instruction.uid;
      return {CheckStatus::Pending, 2, "load awaits byte writer identities"};
    }
  }
  if (deferred > max_pending_stores - std::min(max_pending_stores, hart.pending_stores.size()))
    return {CheckStatus::Incomplete, 0, "deferred PPO store bound exceeded"};
  if (metadata.fence && (metadata.fence_predecessor & 12 || metadata.fence_successor & 12))
    return {CheckStatus::Unsupported, 4, "I/O fence domain is not represented by memory events"};

  // A known later point cannot reverse any known predecessor. Keep all state
  // updates below even on this path: later instructions still need dependencies.
  auto prior = hart.all;
  prior.normalize();
  std::vector<Constraint> constraints;
  for (const auto &op : instruction.memory) {
    const auto after = point(op);
    const bool follows_all = after.time.valid && prior.stores.empty() &&
                             (!prior.known.valid || prior.known.rank < after.time.rank);
    if (!follows_all) {
      auto result = check_operation(hart, op, metadata, constraints);
      if (!result)
        return result;
    }
  }
  auto checked = validate_constraints(hart, constraints);
  if (!checked)
    return checked;

  // Validate dependency propagation on a copy before committing ordering state.
  DependencySummary generated_read;
  for (const auto &op : instruction.memory) {
    if (op.load)
      generated_read.include({true, op.read_time.rank, op.id});
    if (op.sc && op.store)
      generated_read.include({true, op.write_time.rank, op.id});
  }
  auto dependencies = hart.dependencies;
  auto propagated = dependencies.propagate(metadata, generated_read);
  if (!propagated)
    return propagated;
  for (const auto &op : instruction.memory)
    if (op.store && !op.write_time.valid)
      hart.pending_stores.emplace(op.id, PendingStore{std::make_shared<StoreTime>(StoreTime{op.id, {}, {}}), {}, {}});
  apply_constraints(hart, constraints);
  if (metadata.fence) {
    OrderSummary predecessors;
    if (metadata.fence_predecessor & 2)
      predecessors.include(hart.reads);
    if (metadata.fence_predecessor & 1)
      predecessors.include(hart.writes);
    if (metadata.fence_successor & 2)
      hart.fence_read.include(predecessors);
    if (metadata.fence_successor & 1)
      hart.fence_write.include(predecessors);
  }
  if (metadata.control_transfer)
    hart.control.include(hart.dependencies.read(metadata.sources));
  for (const auto &op : instruction.memory)
    update_operation(hart, op, metadata);
  hart.dependencies = std::move(dependencies);
  hart.epoch = instruction.epoch;
  hart.last_uid = instruction.uid;
  hart.has_retired = true;
  hart.pending = false;
  return {};
}

CheckResult PpoChecker::observe_store(const OperationId &store, ObservationTime time) {
  auto hart = harts_.find(store.hart);
  if (hart == harts_.end())
    return {};
  auto found = hart->second.pending_stores.find(store);
  if (found == hart->second.pending_stores.end())
    return {};
  if (!time.valid)
    return {CheckStatus::Invalid, 0, "deferred PPO store publication lacks a timestamp"};
  if (found->second.clock->after && time.rank <= found->second.clock->after->rank)
    return {CheckStatus::Invalid, 0, "store publication contradicts its certified closed-prefix lower bound"};
  const OrderPoint published{store, time, false, true};
  const DependencySummary before{true, time.rank, store};
  for (unsigned rule = 1; rule <= 13; ++rule) {
    auto checked = compare(found->second.lower[rule], published, rule);
    if (!checked)
      return checked;
    if (found->second.upper[rule]) {
      checked = compare(before, found->second.upper[rule]->after, rule);
      if (!checked)
        return checked;
    }
  }
  auto &state = hart->second;
  for (auto edge = state.pending_edges.begin(); edge != state.pending_edges.end();) {
    const bool source = edge->first.first == store;
    const bool target = edge->first.second == store;
    if (!source && !target) {
      ++edge;
      continue;
    }
    auto &other = state.pending_stores.at(source ? edge->first.second : edge->first.first);
    for (unsigned rule = 1; rule <= 13; ++rule) {
      if (!(edge->second & uint16_t(1U << rule)))
        continue;
      if (source)
        other.lower[rule].include(before);
      else
        tighten_upper(other, published, rule);
    }
    edge = state.pending_edges.erase(edge);
  }
  found->second.clock->time = time;
  state.pending_stores.erase(found);
  return {};
}

CheckResult PpoChecker::observe_store_after(const OperationId &store, ObservationTime earlier) {
  auto hart = harts_.find(store.hart);
  if (hart == harts_.end() || !hart->second.pending_stores.count(store) || !earlier.valid)
    return {CheckStatus::Invalid, 0, "closed-prefix store certificate lacks a pending store or valid timestamp"};
  auto &pending = hart->second.pending_stores.at(store);
  StoreTime certified = *pending.clock;
  if (!certified.after || certified.after->rank < earlier.rank)
    certified.after = earlier;
  for (unsigned rule = 1; rule <= 13; ++rule) {
    if (!pending.upper[rule])
      continue;
    auto result = check_certified_after(certified, pending.upper[rule]->after, rule);
    if (!result)
      return result;
  }
  pending.clock->after = certified.after;
  return {};
}

CheckResult PpoChecker::finalize() const {
  for (const auto &entry : harts_)
    if (entry.second.pending || !entry.second.pending_stores.empty() || !entry.second.pending_edges.empty())
      return {CheckStatus::Pending, 0, "PPO checker has unresolved retired observations"};
  return {};
}

void PpoChecker::reset_hart(uint32_t hart, uint64_t epoch) {
  harts_[hart] = {};
  harts_[hart].epoch = epoch;
}

bool PpoChecker::has_pending_reference(const OperationId &writer) const {
  auto hart = harts_.find(writer.hart);
  return hart != harts_.end() && hart->second.pending_stores.count(writer) != 0;
}

void PpoChecker::release_writer(const OperationId &writer) {
  auto found = harts_.find(writer.hart);
  if (found == harts_.end() || has_pending_reference(writer))
    return;
  found->second.store_dependencies.erase(writer);
  found->second.reservation_reads.erase(writer);
}

size_t PpoChecker::pending_store_count() const {
  size_t count = 0;
  for (const auto &hart : harts_)
    count += hart.second.pending_stores.size();
  return count;
}

size_t PpoChecker::address_count() const {
  size_t count = 0;
  for (const auto &entry : harts_)
    count += entry.second.bytes.size();
  return count;
}
} // namespace rvwmo
