#include "runtime.h"
#include "dependency.h"
#include "globalmem.h"
#include <algorithm>
#include <cstdio>
#include <limits>
#include <sstream>
#include <utility>

namespace rvwmo {
namespace {
CheckResult invalid(const std::string &message) {
  return {CheckStatus::Invalid, 0, message};
}
CheckResult pending(const std::string &message) {
  return {CheckStatus::Pending, 0, message};
}
// A retirement packet can contain up to 256 architectural instructions.
// Reserving this UID interval preserves program order when expanding fusion.
constexpr uint64_t allocation_uid_stride = 256;
enum class ScalarAccess {
  None,
  Read,
  Write
};
ScalarAccess scalar_access(uint32_t instruction) {
  if ((instruction & 3) == 3) {
    if ((instruction & 0x7f) == 0x03)
      return ScalarAccess::Read;
    if ((instruction & 0x7f) == 0x23)
      return ScalarAccess::Write;
  } else if ((instruction & 3) == 0 || (instruction & 3) == 2) {
    const unsigned function = (instruction >> 13) & 7;
    if (function == 2 || function == 3)
      return ScalarAccess::Read;
    if (function == 6 || function == 7)
      return ScalarAccess::Write;
  }
  return ScalarAccess::None;
}
bool scalar_alu(uint32_t instruction) {
  switch (instruction & 0x7f) {
    case 0x13:
    case 0x1b:
    case 0x33:
    case 0x3b:
    case 0x37:
    case 0x17: return true;
    default: return false;
  }
}
// DUT retirement carries expanded instructions, while the reference observer
// reports the original RVC encoding. Only normalize forms with known expansion.
bool fused_arithmetic(uint32_t instruction, uint32_t &expanded) {
  if ((instruction & 3) == 3) {
    if (!scalar_alu(instruction)) return false;
    expanded = instruction;
    return true;
  }
  if (instruction >> 16 || (instruction & 3) != 1) return false;
  const unsigned funct = (instruction >> 13) & 7;
  const unsigned rd = (instruction >> 7) & 31;
  const unsigned imm = ((instruction >> 12) & 1) << 5 | ((instruction >> 2) & 31);
  const int32_t signed_imm = int32_t(imm) - (imm & 32 ? 64 : 0);
  if (funct == 3 && rd != 0 && rd != 2 && imm != 0) { // C.LUI
    expanded = ((uint32_t(signed_imm) & 0xfffff) << 12) | (rd << 7) | 0x37;
    return true;
  }
  if (funct == 1 && rd != 0) { // C.ADDIW (RV64)
    expanded = ((uint32_t(signed_imm) & 0xfff) << 20) | (rd << 15) | (rd << 7) | 0x1b;
    return true;
  }
  return false;
}
bool accepted(const CheckResult &result) {
  return result || result.status == CheckStatus::Pending;
}
std::vector<uint8_t> mask_bytes(uint64_t mask, size_t count) {
  std::vector<uint8_t> bytes(count);
  for (size_t i = 0; i < count; ++i)
    bytes[i] = i < 64 ? (mask >> i) & 1 : 0;
  return bytes;
}
bool overlap(uint64_t a, const std::vector<uint8_t> &am, uint64_t b, const std::vector<uint8_t> &bm) {
  for (size_t i = 0; i < am.size(); ++i)
    if (am[i] && a + i >= b && a + i - b < bm.size() && bm[a + i - b])
      return true;
  return false;
}
} // namespace

Runtime::Runtime(unsigned harts)
    : harts_(harts), memory_(
          [](uint64_t address) {
            uint8_t byte = 0;
            read_globalmem(address, &byte, 1);
            return byte;
          },
          [](uint64_t address, uint8_t byte) { update_globalmem(address, &byte, 1, 1); }),
      checker_(memory_) {}

bool Runtime::read_reference_memory(unsigned hart, uint64_t address, size_t size, uint8_t *bytes) const {
  if (hart >= harts_.size() || !bytes || !global_memory().contains(address, size))
    return false;
  const auto &h = harts_[hart];
  // The active UID excludes younger stores already observed in the DUT stream.
  // These are provisional translation/fetch inputs; all stores still need REF audit.
  const uint64_t before_po = h.active ? h.active->instruction.uid
                                     : h.last_retired_uid + (h.last_retired_uid != UINT64_MAX);
  for (size_t byte = 0; byte < size; ++byte)
    if (!memory_.read_local(hart, before_po, address + byte, bytes[byte]) &&
        !global_memory().read(address + byte, bytes + byte, 1))
      return false;
  return true;
}

CheckResult Runtime::unsupported(const std::string &reason) {
  if (coverage_)
    coverage_ = {CheckStatus::Unsupported, 0, reason};
  return coverage_;
}
void Runtime::timestamp(uint64_t cycle) {
  latest_cycle_ = std::max(latest_cycle_, cycle);
  last_effect_cycle_ = std::max(last_effect_cycle_, cycle);
  touched_cycles_.insert(cycle);
  last_event_tick_ = capture_tick_;
}
CheckResult Runtime::allocate(unsigned hart, uint16_t rob) {
  auto &h = harts_.at(hart);
  auto old = h.allocations.find(rob);
  if (old != h.allocations.end()) {
    // A reused ROB slot ends the previous allocation's speculative lifetime.
    // Committed stores remain live until their normal global/PPO reclamation.
    h.unsupported_allocations.erase(old->second);
    auto members = h.instruction_stores.find(old->second);
    if (members != h.instruction_stores.end()) {
      auto &uids = members->second;
      for (auto uid = uids.begin(); uid != uids.end();) {
        auto store = h.stores.find(*uid);
        if (store != h.stores.end() && !store->second.recorded) {
          store_uids_.erase(store->second.id);
          h.stores.erase(store);
          uid = uids.erase(uid);
        } else {
          ++uid;
        }
      }
      if (uids.empty())
        h.instruction_stores.erase(members);
    }
    auto sample = h.loads.find(old->second);
    if (sample != h.loads.end() && !sample->second->retired) {
      sample->second->cancelled = true;
      if (sample->second->observed) {
        auto result = checker_.cancel_load(sample->second->operation.id, sample->second->operation.attempt);
        if (!accepted(result))
          return result;
      }
      h.attempts.erase(old->second);
      h.loads.erase(sample);
    }
  }
  if (h.next_uid > std::numeric_limits<uint64_t>::max() - allocation_uid_stride)
    return invalid("instruction observation UID exhausted");
  h.allocations[rob] = {hart, 0, h.next_uid, 0};
  h.next_uid += allocation_uid_stride;
  return {};
}

CheckResult Runtime::observe(const std::shared_ptr<Load> &load, ObservationTime time) {
  if (load->cancelled)
    return {};
  load->operation.read_time = time;
  // Physical tags remain diagnostics. The read-value witness is derived from
  // the fixed-order LocalMem/GlobalMem model, including late local stores.
  auto result = checker_.observe_load(load->operation, load->operation.id.uid, {});
  if (accepted(result)) {
    load->observed = true;
    return {};
  }
  return result;
}
CheckResult Runtime::complete_group(Group &group, ObservationTime time) {
  auto &h = harts_.at(group.hart);
  std::vector<MemoryWriter> writers(group.bytes.size());
  std::vector<MemoryWriter> completed;
  std::vector<std::pair<OperationId, MemoryWriter>> ordered_members;
  for (uint64_t member: group.members) {
    auto found = h.stores.find(member);
    if (found == h.stores.end() || !found->second.recorded)
      return pending("global write awaits local store record");
    ordered_members.push_back({found->second.id, found->second.memory.writer});
  }
  if (ordered_members.empty())
    return pending("global write awaits store group membership");
  std::sort(ordered_members.begin(), ordered_members.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });
  if (ordered_members.size() > std::numeric_limits<uint64_t>::max() - time.rank)
    return invalid("merged writer rank space exhausted");
  std::vector<ObservationTime> completion_times;
  for (const auto &member: ordered_members) {
    completed.push_back(member.second);
    completion_times.push_back({time.rank + completion_times.size(), true});
  }
  auto architectural_mask = group.mask;
  for (size_t byte = 0; byte < group.bytes.size(); ++byte) {
    if (!group.mask[byte])
      continue;
    if (!group.writers[byte]) {
      // A miss refill may fill clean Sbuffer bytes and widen its physical mask.
      // Such bytes are not logical stores. Required store bytes must still have
      // a writer and are never removed from the architectural transaction.
      const uint64_t address = group.address + byte;
      bool required = false;
      for (uint64_t member: group.members) {
        const auto &store = h.stores.at(member).memory;
        required |= address >= store.address && address - store.address < store.mask.size() &&
                    store.mask[address - store.address];
      }
      if (!required) {
        architectural_mask[byte] = 0;
        continue;
      }
    }
    if (!group.writers[byte] || !group.members.count(group.writers[byte]))
      return pending("global byte writer lacks matching store group membership: hart=" + std::to_string(group.hart) +
                     " group=" + std::to_string(group.id) + " address=" + std::to_string(group.address) +
                     " byte=" + std::to_string(byte) + " writer=" + std::to_string(group.writers[byte]) + " members=" +
                     std::to_string(group.members.size()) + " first=" + std::to_string(*group.members.begin()));
    auto found = h.stores.find(group.writers[byte]);
    if (found == h.stores.end() || !found->second.recorded)
      return pending("global byte writer awaits local record");
    writers[byte] = found->second.memory.writer;
  }
  auto result =
      checker_.observe_global(group.address, group.bytes, architectural_mask, writers, completed, completion_times);
  if (accepted(result)) {
    ranks_consumed_ = completed.size();
    return {};
  }
  return result;
}
void Runtime::observe_write(uint64_t cycle, unsigned hart, uint64_t address, const std::vector<uint8_t> &mask) {
  auto &writes = writes_by_cycle_[cycle];
  for (const auto &other : writes)
    if (other.hart != hart && overlap(address, mask, other.address, other.mask))
      unsupported("INCOMPLETE_ORDER: simultaneous cross-hart writes lack arbitration order");
  writes.push_back({hart, address, mask});
}

CheckResult Runtime::observe_atomic(unsigned hart, const std::shared_ptr<Atomic> &atomic, ObservationTime time) {
  const bool sc = atomic->kind == AtomicKind::StoreConditional;
  const bool lr = atomic->kind == AtomicKind::LoadReserved;
  if (!sc && !atomic->read_seen)
    return pending("atomic read observation has not arrived");
  if (!lr)
    for (unsigned byte = 0; byte < 8; ++byte) {
      uint8_t local = 0;
      if (((atomic->mask >> byte) & 1) && memory_.read_local(hart, atomic->id.uid, atomic->address + byte, local))
        return {CheckStatus::Violation, 1, "atomic write precedes an older same-address pending store"};
    }
  MemoryOperation operation;
  operation.id = atomic->id;
  operation.attempt = atomic->attempt;
  operation.address = atomic->address;
  operation.byte_mask = mask_bytes(atomic->mask, 8);
  operation.load = !sc;
  operation.store = !lr;
  operation.atomic = !lr && !sc;
  operation.lr = lr;
  operation.sc = sc;
  if (!sc)
    operation.read_time = time;
  if (!lr)
    operation.write_time = time;
  operation.source_kind = ReadSourceKind::ModeledWitness;
  if (!sc) {
    auto load = std::make_shared<Load>();
    load->operation = operation;
    for (unsigned byte = 0; byte < 8; ++byte)
      load->actual.push_back(atomic->old_data >> (8 * byte));
    auto result = checker_.observe_load(operation, atomic->id.uid, {});
    if (!result)
      return result;
    load->observed = true;
    atomic->load = load;
    harts_[hart].loads[atomic->id] = load;
  }
  if (!lr) {
    // Snapshot an RMW before registering its writer. SC has no read effect.
    atomic->store.po = atomic->id.uid;
    atomic->store.address = atomic->address;
    atomic->store.mask = operation.byte_mask;
    for (unsigned byte = 0; byte < 8; ++byte)
      atomic->store.bytes.push_back(atomic->new_data >> (8 * byte));
    auto result = checker_.memory_writer(atomic->id, atomic->store.writer);
    if (!result)
      return result;
    result = checker_.record_store(atomic->store, operation, StoreVerification::Provisional);
    if (!result)
      return result;
    result = checker_.observe_global(atomic->address, atomic->store.bytes, atomic->store.mask,
                                     std::vector<MemoryWriter>(8, atomic->store.writer), {atomic->store.writer}, time);
    if (!result)
      return result;
  }
  atomic->observed = true;
  return {};
}

CheckResult Runtime::capture_atomics(unsigned hart, DiffTestState &state) {
#ifdef CONFIG_DIFFTEST_ATOMICMEMORYEVENT
  auto &h = harts_[hart];
  std::vector<DifftestAtomicMemoryEvent> events;
  for (auto &event : state.atomic_memory)
    if (event.valid) {
      events.push_back(event);
      event.valid = 0;
    }
  std::sort(events.begin(), events.end(), [](const auto &left, const auto &right) {
    const auto priority = [](unsigned phase) { return phase == 3 ? 0 : phase == 4 ? 1 : phase + 2; };
    return std::make_pair(left.timestamp, priority(left.phase)) <
           std::make_pair(right.timestamp, priority(right.phase));
  });
  for (const auto &event : events) {
    timestamp(event.timestamp);
    if (event.phase == 3) {
      if (h.atomic_inflight)
        return invalid("overlapping atomic lifecycles on one hart");
      auto allocation = h.allocations.find(event.robidx);
      if (!event.identityValid || allocation == h.allocations.end())
        return invalid("atomic begin lacks ROB generation");
      auto atomic = std::make_shared<Atomic>();
      atomic->id = allocation->second;
      if (event.fuop == 2 || event.fuop == 3)
        atomic->kind = AtomicKind::LoadReserved;
      if (event.fuop == 6 || event.fuop == 7)
        atomic->kind = AtomicKind::StoreConditional;
      h.atomics[atomic->id] = atomic;
      h.atomic_inflight = atomic;
      continue;
    }
    auto atomic = h.atomic_inflight;
    if (!atomic)
      return invalid("atomic effect lacks an active lifecycle");
    if (event.identityValid) {
      auto allocation = h.allocations.find(event.robidx);
      if (allocation == h.allocations.end() || !(allocation->second == atomic->id))
        return invalid("atomic lifecycle ROB identity changed");
    }
    if (event.error)
      return unsupported("atomic observation reported an access error");
    if (event.phase == 4) {
      if ((!atomic->request_seen && event.attempt != 0) ||
          (atomic->request_seen && (!atomic->awaiting_retry || event.attempt != atomic->attempt + 1)))
        return invalid("atomic request attempt is duplicated or skips its replay lifecycle");
      if ((event.mask != 0x0f && event.mask != 0xf0 && event.mask != 0xff) ||
          !global_memory().contains(event.addr & ~UINT64_C(7), 8))
        return unsupported("atomic operand range or width is not supported");
      atomic->address = event.addr & ~UINT64_C(7);
      atomic->mask = event.mask;
      atomic->attempt = event.attempt;
      atomic->request_seen = true;
      atomic->awaiting_retry = false;
    } else if (event.phase == 5) {
      if (!atomic->request_seen || atomic->awaiting_retry || atomic->read_seen || atomic->write_seen || atomic->response_seen)
        return invalid("atomic replay does not follow an outstanding request without accepted effects");
      atomic->read_seen = false;
      atomic->awaiting_retry = true;
    } else if (event.phase == 1) {
      if (!atomic->request_seen || atomic->awaiting_retry || atomic->read_seen || atomic->write_seen)
        return invalid("atomic read effect is duplicated or lacks an outstanding request");
      if (atomic->kind == AtomicKind::StoreConditional || atomic->address != event.addr || atomic->mask != event.mask)
        return invalid("atomic read operand differs from its request");
      atomic->old_data = event.data;
      atomic->read_seen = true;
      if (atomic->kind == AtomicKind::LoadReserved) {
        if (transport_watermark_ && event.timestamp <= *transport_watermark_)
          return invalid("LR sample arrived behind the completed watermark");
        reserved_reads_by_cycle_[event.timestamp].push_back(atomic);
        const auto key = EventKey{event.timestamp, 1, atomic->id.uid, hart};
        auto inserted = events_.emplace(key, [this, hart, atomic](ObservationTime time) {
          return observe_atomic(hart, atomic, time);
        });
        if (!inserted.second)
          return invalid("duplicate LR read observation key");
      }
    } else if (event.phase == 2) {
      if (!atomic->request_seen || atomic->awaiting_retry || atomic->kind == AtomicKind::LoadReserved || atomic->write_seen ||
          (atomic->kind == AtomicKind::Rmw && !atomic->read_seen) ||
          atomic->address != event.addr || atomic->mask != event.mask)
        return invalid("atomic write does not match its request/read effect");
      if ((event.mask != 0x0f && event.mask != 0xf0 && event.mask != 0xff) || (event.addr & 7) ||
          !global_memory().contains(event.addr, 8))
        return unsupported("atomic write range or width is not supported");
      if (transport_watermark_ && event.timestamp <= *transport_watermark_)
        return invalid("atomic write arrived behind completed transport watermark");
      atomic->new_data = event.data;
      atomic->write_seen = true;
      observe_write(event.timestamp, hart, event.addr, mask_bytes(event.mask, 8));
      auto inserted = events_.emplace(EventKey{event.timestamp, 3, atomic->id.uid, hart},
                                      [this, hart, atomic](ObservationTime time) {
                                        return observe_atomic(hart, atomic, time);
                                      });
      if (!inserted.second)
        return invalid("duplicate atomic write observation key");
    } else if (event.phase == 6) {
      if (!atomic->request_seen || atomic->awaiting_retry || atomic->response_seen)
        return invalid("atomic response is duplicated or lacks an outstanding request");
      atomic->cache_response = event.data;
      atomic->success = event.success;
      if (atomic->kind == AtomicKind::StoreConditional) {
        if (bool(event.success) != (event.data == 0) || bool(atomic->write_seen) != bool(event.success))
          return {CheckStatus::Violation, 0, "SC status does not match its observed write effect"};
      } else if (!event.success || !atomic->read_seen || event.data != atomic->old_data) {
        return {CheckStatus::Violation, 0, "atomic cache response differs from observed old word"};
      }
      atomic->response_seen = true;
    } else if (event.phase == 7) {
      if (!atomic->response_seen || (atomic->kind == AtomicKind::Rmw && !atomic->write_seen))
        return invalid("atomic lifecycle finished without its data effects/response");
      if (atomic->kind == AtomicKind::StoreConditional && event.data != atomic->cache_response)
        return {CheckStatus::Violation, 0, "SC architectural status differs from cache response"};
      atomic->response = event.data;
      atomic->finished = true;
      h.atomic_inflight.reset();
    } else if (event.phase == 8) {
      return unsupported("cancelled atomic lifecycle requires explicit recovery support");
    } else {
      return invalid("unknown atomic observation phase");
    }
  }
#else
  (void)hart;
  (void)state;
#endif
#ifdef CONFIG_DIFFTEST_ATOMICEVENT
  state.atomic.valid = 0; // Legacy response event is not a global-memory writer.
#endif
  return {};
}

void Runtime::collect_released_stores() {
  for (const auto &id: checker_.take_released_stores()) {
    auto wire = store_uids_.find(id);
    if (wire == store_uids_.end()) {
      harts_.at(id.hart).atomics.erase(id);
      continue;
    }
    auto &hart = harts_.at(id.hart);
    const uint64_t uid = wire->second;
    OperationId instruction = id;
    instruction.subaccess = 0;
    auto members = hart.instruction_stores.find(instruction);
    if (members != hart.instruction_stores.end()) {
      auto &uids = members->second;
      uids.erase(std::remove(uids.begin(), uids.end(), uid), uids.end());
      if (uids.empty())
        hart.instruction_stores.erase(members);
    }
    hart.stores.erase(uid);
    store_uids_.erase(wire);
  }
}

CheckResult Runtime::advance(uint64_t watermark) {
  transport_watermark_ = watermark;
  loads_by_cycle_.erase(loads_by_cycle_.begin(), loads_by_cycle_.upper_bound(watermark));
  writes_by_cycle_.erase(writes_by_cycle_.begin(), writes_by_cycle_.upper_bound(watermark));
  reserved_reads_by_cycle_.erase(reserved_reads_by_cycle_.begin(), reserved_reads_by_cycle_.upper_bound(watermark));
  ordering_pending_.clear();
  while (!events_.empty() && std::get<0>(events_.begin()->first) <= watermark) {
    auto &event = *events_.begin();
    ranks_consumed_ = 1;
    auto result = event.second({next_rank_, true});
    if (!result) {
      if (result.status != CheckStatus::Pending)
        failure_ = result;
      else
        ordering_pending_ = "cycle=" + std::to_string(std::get<0>(event.first)) + " " + result.message;
      return result;
    }
    if (ranks_consumed_ > std::numeric_limits<uint64_t>::max() - next_rank_)
      return invalid("observed memory rank space exhausted");
    next_rank_ += ranks_consumed_;
    const auto completed_key = event.first;
    events_.erase(events_.begin());
    if (std::get<1>(completed_key) == 2)
      groups_.erase({std::get<3>(completed_key), std::get<2>(completed_key)});
  }
  auto result = checker_.poll();
  collect_released_stores();
  if (!accepted(result))
    failure_ = result;
  return accepted(result) ? CheckResult{} : result;
}

CheckResult Runtime::capture(const std::vector<DiffTestState *> &states) {
  ++capture_tick_;
  finalized_ = false;
  touched_cycles_.clear();
  for (auto &hart : harts_)
    hart.frame_ref_steps = 0;
  if (!failure_)
    return failure_;
  if (!covered())
    return coverage_;
#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_STOREIDENTITYEVENT) && defined(CONFIG_DIFFTEST_STORELOCALEVENT) &&        \
    defined(CONFIG_DIFFTEST_LOADSNAPSHOTEVENT) && defined(CONFIG_DIFFTEST_SBUFFEREVENT) &&                             \
    defined(CONFIG_DIFFTEST_STOREEVENT) && defined(CONFIG_DIFFTEST_TLBEVENT) &&                                        \
    defined(CONFIG_DIFFTEST_MEMORYTIMEEVENT) && !defined(CONFIG_DIFFTEST_SQUASH) && !defined(CONFIG_DIFFTEST_BATCH) && \
    !defined(CONFIG_DIFFTEST_REPLAY)
  if (states.size() != harts_.size())
    return invalid("runtime hart count differs from event producer");
  for (const auto *state: states)
    latest_cycle_ = std::max(latest_cycle_, state->memory_time.timestamp);
  // Existing ROB-allocation TLB clears cover every instruction, in rename-port
  // order. Preserve them for the independent translation checker.
  for (unsigned hart = 0; hart < states.size(); ++hart) {
    if (harts_[hart].done)
      continue;
    for (unsigned port = 0; port < CONFIG_DIFF_TLB_WIDTH; ++port) {
      auto &event = states[hart]->tlb[port];
      if (event.valid && event.clear && !event.isFetch) {
        auto result = allocate(hart, event.id);
        if (!result)
          return result;
      }
    }
  }
  for (unsigned hart = 0; hart < states.size(); ++hart) {
    auto &h = harts_[hart];
    auto &state = *states[hart];
    for (unsigned port = 0; port < CONFIG_DIFF_COMMIT_WIDTH; ++port)
      if (!h.done && state.commit[port].valid)
        timestamp(state.commit[port].timestamp);
    for (unsigned port = 0; port < CONFIG_DIFF_STORE_IDENTITY_WIDTH; ++port) {
      auto &event = state.store_identity[port];
      if (!event.valid)
        continue;
      event.valid = 0;
      if (h.done)
        continue;
      timestamp(event.timestamp);
      auto allocation = h.allocations.find(event.robidx);
      if (allocation == h.allocations.end())
        return invalid("store allocation lacks ROB generation");
      if (!event.storeUid || event.storeUid <= h.last_store_uid)
        return invalid("reused, nonmonotonic or zero observed store UID");
      h.last_store_uid = event.storeUid;
      auto &members = h.instruction_stores[allocation->second];
      Store store;
      store.id = allocation->second;
      store.id.subaccess = members.size();
      store_uids_[store.id] = event.storeUid;
      h.stores.emplace(event.storeUid, std::move(store));
      members.push_back(event.storeUid);
      if (event.isVector)
        h.unsupported_allocations[allocation->second] =
            "vector store observations are not yet covered by the scalar runtime";
    }
    for (unsigned port = 0; port < CONFIG_DIFF_STORE_LOCAL_WIDTH; ++port) {
      auto &event = state.store_local[port];
      if (!event.valid)
        continue;
      event.valid = 0;
      if (h.done)
        continue;
      timestamp(event.timestamp);
      auto found = h.stores.find(event.storeUid);
      if (found == h.stores.end())
        return invalid("local commit lacks store allocation identity");
      if (event.isVector || event.isUnaligned || event.wline || event.exception || !event.addressValid ||
          !event.dataValid) {
        h.unsupported_allocations[found->second.id] =
            "local store unsupported: hart=" + std::to_string(hart) + " uid=" + std::to_string(event.storeUid) +
            " addr=" + std::to_string(event.addr) + " vector=" + std::to_string(event.isVector) +
            " unaligned=" + std::to_string(event.isUnaligned) + " wline=" + std::to_string(event.wline) +
            " exception=" + std::to_string(event.exception) + " addressValid=" + std::to_string(event.addressValid) +
            " dataValid=" + std::to_string(event.dataValid) + " pmem=" + std::to_string(in_pmem(event.addr));
        continue;
      }
      auto &store = found->second;
      if (!in_pmem(event.addr)) {
        // Uncached device stores have no GlobalMem/SbufferCommit. Accept only
        // a matching skipped retirement, outside coherent RAM coverage.
        store.excluded_io = true;
        continue;
      }
      if (transport_watermark_ && event.timestamp <= *transport_watermark_)
        return invalid("local commit arrived behind completed transport watermark");
      if (store.recorded)
        return invalid("duplicate local store commit");
      store.memory.po = store.id.uid;
      store.memory.address = event.addr;
      store.memory.bytes.assign(event.data, event.data + 16);
      store.memory.mask = mask_bytes(event.mask, 16);
      auto result = checker_.memory_writer(store.id, store.memory.writer);
      if (!result)
        return result;
      store.operation.id = store.id;
      store.operation.store = true;
      store.operation.address = store.memory.address;
      store.operation.byte_mask = store.memory.mask;
      // Local commit has no GMO rank. Register its identity immediately so REF
      // may audit retired stores while source-time reads await queue closure.
      // Snapshot resolution already handles older local stores arriving late.
      result = checker_.record_store(store.memory, store.operation, StoreVerification::Provisional);
      if (!accepted(result))
        return result;
      store.recorded = true;
    }
    for (unsigned port = 0; port < CONFIG_DIFF_STORE_WIDTH; ++port) {
      const auto &event = state.store[port];
      if (event.valid && event.groupId && event.storeUid) {
        auto &group = groups_[{hart, event.groupId}];
        group.hart = hart;
        group.id = event.groupId;
        group.members.insert(event.storeUid);
      }
    }
    for (unsigned port = 0; port < CONFIG_DIFF_LOAD_SNAPSHOT_WIDTH; ++port) {
      auto &event = state.load_snapshot[port];
      if (!event.valid)
        continue;
      event.valid = 0;
      if (h.done)
        continue;
      timestamp(event.timestamp);
      if (event.clear)
        continue; // Allocation identity is supplied for every instruction above.
      auto allocation = h.allocations.find(event.robidx);
      if (allocation == h.allocations.end())
        return invalid("load sample lacks ROB generation");
      if (event.sampleKind != 1 || !in_pmem(event.paddr)) {
        h.unsupported_allocations[allocation->second] =
            "load snapshot kind or address is outside scalar memory coverage";
        continue;
      }
      h.unsupported_allocations.erase(allocation->second);
      if (transport_watermark_ && event.timestamp <= *transport_watermark_)
        return invalid("load sample arrived behind completed transport watermark");
      const EventKey sample_key{event.timestamp, 1, allocation->second.uid, hart};
      if (events_.count(sample_key))
        return invalid("multiple load samples share an instruction/cycle without a subaccess identity");
      auto previous = h.loads.find(allocation->second);
      if (previous != h.loads.end()) {
        previous->second->cancelled = true;
        if (previous->second->observed) {
          auto result = checker_.cancel_load(previous->second->operation.id, previous->second->operation.attempt);
          if (!accepted(result))
            return result;
        }
      }
      auto load = std::make_shared<Load>();
      load->operation.id = allocation->second;
      load->operation.attempt = h.attempts[allocation->second]++;
      load->operation.address = event.paddr;
      load->operation.byte_mask = mask_bytes(event.mask, 16);
      load->operation.load = true;
      load->operation.source_kind = ReadSourceKind::ModeledWitness;
      load->actual.assign(event.data, event.data + 16);
      h.loads[allocation->second] = load;
      loads_by_cycle_[event.timestamp].push_back(load);
      events_.emplace(sample_key, [this, load](ObservationTime time) { return observe(load, time); });
    }
    for (unsigned port = 0; port < CONFIG_DIFF_SBUFFER_WIDTH; ++port) {
      auto &event = state.sbuffer[port];
      if (!event.valid)
        continue;
      event.valid = 0;
      if (!event.groupId) {
        unsupported("store buffer completion has no transaction identity");
        continue;
      }
      auto &group = groups_[{hart, event.groupId}];
      if (group.queued)
        continue;
      if (transport_watermark_ && event.timestamp <= *transport_watermark_)
        return invalid("global completion arrived behind completed transport watermark");
      timestamp(event.timestamp);
      group.hart = hart;
      group.id = event.groupId;
      group.cycle = event.timestamp;
      group.address = event.addr;
      group.bytes.assign(event.data, event.data + 64);
      group.mask = mask_bytes(event.mask, 64);
      group.writers.assign(event.byteWriterUid, event.byteWriterUid + 64);
      group.queued = true;
      observe_write(group.cycle, hart, group.address, group.mask);
      auto key = std::make_pair(hart, event.groupId);
      auto inserted =
          events_.emplace(EventKey{event.timestamp, 2, event.groupId, hart},
                          [this, key](ObservationTime time) { return complete_group(groups_.at(key), time); });
      if (!inserted.second)
        return invalid("duplicate global completion event ordering key");
    }
    auto atomic_result = capture_atomics(hart, state);
    if (!atomic_result)
      return atomic_result;
  }
  // Audit after collecting every hart: the result must not depend on which
  // hart's packet happened to be visited first in this capture.
  for (uint64_t cycle : touched_cycles_) {
    auto writes = writes_by_cycle_.find(cycle);
    if (writes == writes_by_cycle_.end())
      continue;
    auto loads = loads_by_cycle_.find(cycle);
    auto reserved = reserved_reads_by_cycle_.find(cycle);
    for (const auto &write : writes->second) {
      if (loads != loads_by_cycle_.end())
        for (const auto &weak : loads->second) {
          auto load = weak.lock();
          if (load && load->operation.id.hart != write.hart && !load->cancelled &&
              overlap(write.address, write.mask, load->operation.address, load->operation.byte_mask))
            load->coverage_reason = "INCOMPLETE_ORDER: simultaneous cross-hart read/write lacks arbitration order";
        }
      if (reserved != reserved_reads_by_cycle_.end())
        for (const auto &weak : reserved->second) {
          auto atomic = weak.lock();
          if (atomic && atomic->id.hart != write.hart &&
              overlap(write.address, write.mask, atomic->address, mask_bytes(atomic->mask, 8)))
            atomic->coverage_reason = "INCOMPLETE_ORDER: simultaneous LR/remote write lacks arbitration order";
        }
    }
  }
  if (!covered())
    return coverage_;
  if (latest_cycle_ == 0)
    return {};
  // Memory probes are captured at their source edge, including global writes.
  // Load samples carry their SRAM/forwarding source time from s1 but arrive
  // after s3. Keep three source cycles open before replaying any global writes.
  auto result = advance(latest_cycle_ > 3 ? latest_cycle_ - 3 : 0);
  return result.status == CheckStatus::Pending ? CheckResult{} : result;
#else
  (void)states;
  return unsupported(
      "multicore RVWMO event capability is missing or batched/squashed/replayed transport is unsupported");
#endif
}

CheckResult Runtime::before_commit(unsigned hart, unsigned port, DiffTestState &state, RefProxy &reference) {
  if (!failure_)
    return failure_;
  if (!covered())
    return coverage_;
  if (harts_.at(hart).done)
    return {};
#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_LOADEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
  auto &h = harts_.at(hart);
  const auto &commit = state.commit[port];
  if (h.active)
    return invalid("previous reference instruction has not completed");
  const bool is_atomic = (commit.instr & 0x7f) == 0x2f;
  const unsigned atomic_function = commit.instr >> 27;

  auto allocation = h.allocations.find(commit.tlbId);
  if (allocation == h.allocations.end())
    return unsupported("retirement lacks complete allocation identity stream");
  bool excluded_io = false;
  if (commit.skip && commit.isStore) {
    auto members = h.instruction_stores.find(allocation->second);
    if (members != h.instruction_stores.end() && members->second.size() == 1) {
      auto store = h.stores.find(members->second.front());
      excluded_io = store != h.stores.end() && store->second.excluded_io;
    }
  }
  if ((commit.skip && !excluded_io) || commit.special ||
      (commit.nFused && (commit.skip || commit.isLoad || commit.isStore || !scalar_alu(commit.instr))))
    return unsupported("retirement lacks complete semantics: pc=" + std::to_string(commit.pc) +
                       " instr=" + std::to_string(commit.instr) + " skip=" + std::to_string(commit.skip) +
                       " fused=" + std::to_string(commit.nFused) + " special=" + std::to_string(commit.special) +
                       " isStore=" + std::to_string(commit.isStore));
  auto unsupported_instruction = h.unsupported_allocations.find(allocation->second);
  if (unsupported_instruction != h.unsupported_allocations.end())
    return unsupported(unsupported_instruction->second);
  Active active;
  active.instruction.hart = hart;
  active.instruction.uid = allocation->second.uid;
  active.instruction.pc = commit.pc;
  active.instruction.instruction = commit.instr;
  // The simulator's explicit exit marker is not an ISA memory operation.
  const bool exit_marker = (commit.instr & 0x7f) == 0x6b && state.trap.hasTrap && state.trap.pc == commit.pc;
  if (exit_marker) {
    active.instruction.dependencies.provided = true;
  } else {
    auto decoded = decode_dependencies(commit.instr, active.instruction.dependencies);
    if (!decoded)
      return unsupported(decoded.message);
    // In the coherent-RAM checker, a full platform fence retains its complete
    // R/W constraint. Device-domain ordering is outside this verdict.
    auto &dependencies = active.instruction.dependencies;
    if (dependencies.fence && dependencies.fence_predecessor == 15 && dependencies.fence_successor == 15) {
      dependencies.fence_predecessor = 3;
      dependencies.fence_successor = 3;
    }
  }
  if (is_atomic) {
    const bool lr = atomic_function == 2;
    const bool sc = atomic_function == 3;
    if (!lr && !reference.supports_atomic_store())
      return unsupported("reference lacks independent atomic store-log support");
    const unsigned width = (commit.instr >> 12) & 7;
    if (width != 2 && width != 3)
      return unsupported("atomic width is outside W/D coverage");
    switch (atomic_function) {
      case 0: case 1: case 2: case 3: case 4: case 8: case 12: case 16: case 20: case 24: case 28: break;
      default: return unsupported("atomic opcode is not covered");
    }
    auto found = h.atomics.find(allocation->second);
    if (found == h.atomics.end() || !found->second->finished ||
        ((!sc || found->second->success) && !found->second->observed))
      return pending("atomic retirement awaits its ordered effect and completed response");
    auto atomic = found->second;
    if (!atomic->coverage_reason.empty())
      return unsupported(atomic->coverage_reason);
    const auto kind = lr ? AtomicKind::LoadReserved : sc ? AtomicKind::StoreConditional : AtomicKind::Rmw;
    if (atomic->kind != kind)
      return invalid("atomic lifecycle kind differs from encoded instruction");
    const size_t size = width == 2 ? 4 : 8;
    const size_t offset = atomic->mask == 0xf0 ? 4 : 0;
    if ((size == 8 && atomic->mask != 0xff) || (size == 4 && atomic->mask == 0xff))
      return invalid("atomic observation width differs from encoded instruction");
    const bool aq = bool(commit.instr & (1u << 26));
    const bool rl = bool(commit.instr & (1u << 25));
    MemoryOperation operation;
    if (sc) {
      if (!reference.set_sc_result(commit.pc, atomic->response))
        return unsupported("reference cannot consume the selected SC result");
      active.instruction.failed_sc = !atomic->success;
      if (atomic->success) {
        operation.id = atomic->id;
        operation.address = atomic->address;
        operation.byte_mask = mask_bytes(atomic->mask, 8);
        operation.store = operation.sc = true;
      }
    } else {
      const uint64_t old = atomic->old_data >> (offset * 8);
      const uint64_t response = size == 4 ? uint64_t(int64_t(int32_t(old))) : old;
      if (atomic->response != response)
        return {CheckStatus::Violation, 0, "atomic response differs from observed old value"};
      std::vector<uint8_t> candidate;
      auto result = checker_.get_reference_candidate_load(atomic->id, atomic->attempt, candidate);
      if (!result)
        return result;
      result = h.reader.begin({ReferenceAccess{atomic->address + offset,
                                             {candidate.begin() + offset, candidate.begin() + offset + size}}});
      if (!result)
        return result;
      if (!reference.set_load_reader(&ReferenceRead::read, &h.reader)) {
        h.reader.finish();
        return unsupported("reference lacks atomic memory-read callback");
      }
      operation = atomic->load->operation;
      active.reader = true;
      active.load = atomic->load;
    }
    // LR.rl alone and SC.aq alone do not establish release/acquire annotations.
    operation.acquire = sc ? (aq && rl) : aq;
    operation.release = lr ? (aq && rl) : rl;
    operation.rcsc = operation.acquire || operation.release;
    if (!sc || atomic->success)
      active.instruction.memory.push_back(operation);
    active.atomic = atomic;
    active.instruction_count = 1;
    h.active = std::move(active);
    return {};
  }
  const auto access = scalar_access(commit.instr);
  if (bool(commit.isLoad) != (access == ScalarAccess::Read) || bool(commit.isStore) != (access == ScalarAccess::Write))
    return invalid("retirement memory classification differs from encoded instruction: hart=" + std::to_string(hart) +
                   " pc=" + std::to_string(commit.pc) + " instruction=" + std::to_string(commit.instr));
  const auto &load_event = state.load[port];
  if (commit.isStore && load_event.valid && load_event.isLoad)
    return invalid("scalar retirement unexpectedly combines load and store effects");
  if (load_event.valid && (load_event.isAtomic || load_event.isVLoad || commit.fpwen))
    return unsupported("atomic, floating-point or vector memory instruction lacks runtime coverage");
  if (load_event.valid && load_event.isLoad) {
    auto sample = h.loads.find(allocation->second);
    if (sample == h.loads.end() || !sample->second->observed)
      return pending("retired load awaits ordered final-attempt sample: hart=" + std::to_string(hart) +
                     " pc=" + std::to_string(commit.pc) + " rob=" + std::to_string(commit.tlbId) + " uid=" +
                     std::to_string(allocation->second.uid) + " present=" + std::to_string(sample != h.loads.end()) +
                     " sourceClock=" + std::to_string(latest_cycle_) + " pending=" + ordering_pending_);
    auto load = sample->second;
    if (!load->coverage_reason.empty())
      return unsupported(load->coverage_reason);
    if (load_event.opType > 6 || (load_event.opType & 3) > 3 || load_event.paddr2Valid)
      return unsupported("scalar load operation or split access lacks runtime coverage");
    const size_t size = size_t(1) << (load_event.opType & 3);
    const uint64_t address = load_event.paddr;
    if (address < load->operation.address || address - load->operation.address + size > 16 || address % size != 0 ||
        !in_pmem(address) || !in_pmem(address + size - 1))
      return unsupported("scalar load range is unaligned, split or outside modeled memory");
    // A remote source may await another hart's REF step. Candidate bytes let REF
    // advance; Checker retains final validation until every selected source is audited.
    std::vector<uint8_t> candidate;
    auto result = checker_.get_reference_candidate_load(load->operation.id, load->operation.attempt, candidate);
    if (!result)
      return result;
    const size_t offset = address - load->operation.address;
    for (size_t byte = 0; byte < 16; ++byte)
      if (bool(load->operation.byte_mask[byte]) != (byte >= offset && byte < offset + size))
        return invalid("final scalar load sample mask differs from retired access");
    std::vector<uint8_t> bytes(candidate.begin() + offset, candidate.begin() + offset + size);
    result = h.reader.begin({ReferenceAccess{address, std::move(bytes)}});
    if (!result)
      return result;
    if (!reference.set_load_reader(&ReferenceRead::read, &h.reader)) {
      h.reader.finish();
      return unsupported("reference model lacks independent scalar memory-read callback");
    }
    active.reader = true;
    active.load = load;
    active.instruction.memory.push_back(load->operation);
  } else if (commit.isLoad) {
    return unsupported("retired memory read lacks scalar load metadata");
  }
  if (commit.isStore && !excluded_io) {
    auto found = h.instruction_stores.find(allocation->second);
    if (found == h.instruction_stores.end() || found->second.size() != 1)
      return unsupported("retired store lacks a single scalar allocation identity");
    auto &store = h.stores.at(found->second.front());
    if (!store.recorded)
      return pending("retired store awaits its local commit observation");
    active.instruction.memory.push_back(store.operation);
  }
  active.instruction_count = unsigned(commit.nFused) + 1;
  active.is_rvc = commit.isRVC;
  if (commit.nFused && !reference.set_instruction_observer(&Runtime::observe_reference_instruction, &h))
    return unsupported("fused retirement requires reference instruction observation");
  h.active = std::move(active);
  return {};
#else
  (void)hart;
  (void)port;
  (void)state;
  (void)reference;
  return unsupported("reference retirement ABI lacks scalar load capability");
#endif
}
void Runtime::observe_reference_instruction(void *context, uint64_t pc, uint32_t instruction) {
  auto &hart = *static_cast<Hart *>(context);
  if (hart.active && hart.active->reference_instructions.size() <= hart.active->instruction_count)
    hart.active->reference_instructions.emplace_back(pc, instruction);
}

CheckResult Runtime::note_reference_step(unsigned hart) {
  auto &h = harts_.at(hart);
  if (!h.active)
    return failure_ = invalid("REF execution has no active retirement packet");
  if (h.ref_instructions == std::numeric_limits<uint64_t>::max() ||
      h.frame_ref_steps == std::numeric_limits<uint64_t>::max())
    return failure_ = invalid("REF instruction counter exhausted");
  ++h.ref_instructions;
  ++h.frame_ref_steps;
  return {};
}

CheckResult Runtime::note_arch_compare(unsigned hart, uint64_t retired_instructions) {
  auto &h = harts_.at(hart);
  // skip_one synchronizes REF from DUT and cannot earn an independent compare.
  if (!h.frame_ref_steps)
    return {};
  if (h.frame_ref_steps > retired_instructions)
    return failure_ = invalid("REF steps exceed the architecture-compare retirement group");
  if (h.frame_ref_steps > std::numeric_limits<uint64_t>::max() - h.arch_compares)
    return failure_ = invalid("independent architecture-compare counter exhausted");
  h.arch_compares += h.frame_ref_steps;
  h.frame_ref_steps = 0;
  return {};
}

CheckResult Runtime::after_commit(unsigned hart, RefProxy &reference) {
  auto &h = harts_.at(hart);
  if (!h.active)
    return {};
  auto active = std::move(*h.active);
  h.active.reset();
  std::vector<RetiredInstruction> fused_tail;
  if (active.instruction_count > 1) {
    reference.set_instruction_observer(nullptr, nullptr);
    if (active.reference_instructions.size() != active.instruction_count)
      return invalid("fused reference instruction count differs from retirement packet");
    uint64_t expected_pc = active.instruction.pc;
    for (unsigned index = 0; index < active.reference_instructions.size(); ++index) {
      const auto &observed = active.reference_instructions[index];
      uint32_t expanded = 0;
      if (observed.first != expected_pc || !fused_arithmetic(observed.second, expanded))
        return unsupported("fused packet contains nonsequential or unsupported arithmetic instructions");
      if (index == 0) {
        const bool observed_rvc = (observed.second & 3) != 3;
        if (observed_rvc != active.is_rvc || expanded != active.instruction.instruction)
          return {CheckStatus::Violation, 0, "first fused instruction differs from reference execution"};
        if (observed_rvc) {
          active.instruction.instruction = observed.second;
          auto decoded = decode_dependencies(observed.second, active.instruction.dependencies);
          if (!decoded)
            return unsupported(decoded.message);
        }
      } else {
        RetiredInstruction instruction;
        instruction.hart = hart;
        instruction.uid = active.instruction.uid + index;
        instruction.pc = observed.first;
        instruction.instruction = observed.second;
        auto decoded = decode_dependencies(instruction.instruction, instruction.dependencies);
        if (!decoded)
          return unsupported(decoded.message);
        fused_tail.push_back(std::move(instruction));
      }
      expected_pc += (observed.second & 3) == 3 ? 4 : 2;
    }
  }
  if (active.reader) {
    reference.set_load_reader(nullptr, nullptr);
    auto result = h.reader.finish();
    if (!result)
      return result;
  }
  if (active.atomic && active.atomic->write_seen) {
    auto atomic = active.atomic;
    uint64_t address = atomic->address;
    uint64_t data = atomic->new_data;
    uint8_t mask = atomic->mask;
    // Compare only written bytes: MainPipe supplies the merged 64-bit word.
    uint64_t enabled = 0;
    for (unsigned byte = 0; byte < 8; ++byte)
      if ((mask >> byte) & 1)
        enabled |= UINT64_C(255) << (byte * 8);
    data &= enabled;
    if (reference.atomic_commit(&address, &data, &mask)) {
      std::ostringstream message;
      message << "REF AMO write differs from observed atomic write: hart=" << hart << std::hex
              << " pc=0x" << active.instruction.pc << " observed-address=0x" << atomic->address
              << " observed-data=0x" << (atomic->new_data & enabled) << " observed-mask=0x" << unsigned(atomic->mask)
              << " reference-address=0x" << address << " reference-data=0x" << data
              << " reference-mask=0x" << unsigned(mask);
      return {CheckStatus::Violation, 0, message.str()};
    }
    auto reference_store = atomic->store;
    for (unsigned byte = 0; byte < 8; ++byte)
      if (reference_store.mask[byte])
        reference_store.bytes[byte] = data >> (byte * 8);
    auto result = checker_.verify_store(atomic->id, reference_store);
    if (!accepted(result))
      return result;
    atomic->verified = true;
  }
  std::vector<RetiredLoad> loads;
  if (active.load) {
    active.load->retired = true;
    loads.push_back({active.load->operation.id, active.load->actual});
  }
  h.last_retired_uid = active.instruction.uid;
  if (active.instruction.memory.empty()) {
    auto members = h.instruction_stores.find({hart, 0, active.instruction.uid, 0});
    if (members != h.instruction_stores.end()) {
      for (auto uid: members->second) {
        auto store = h.stores.find(uid);
        if (store != h.stores.end() && store->second.excluded_io) {
          store_uids_.erase(store->second.id);
          h.stores.erase(store);
        }
      }
      h.instruction_stores.erase(members);
    }
  }
  auto result = checker_.retire(active.instruction, loads);
  if (!accepted(result)) {
    failure_ = result;
    return result;
  }
  for (const auto &instruction: fused_tail) {
    result = checker_.retire(instruction, {});
    if (!accepted(result)) {
      failure_ = result;
      return result;
    }
    h.last_retired_uid = instruction.uid;
  }
  if (active.load) {
    h.loads.erase(active.load->operation.id);
    h.attempts.erase(active.load->operation.id);
  }
  if (active.atomic && !active.atomic->write_seen)
    h.atomics.erase(active.atomic->id);
  collect_released_stores();
  return {};
}
CheckResult Runtime::verify_store(unsigned hart, uint64_t uid, uint64_t address, uint64_t data, uint8_t mask) {
  if (!covered())
    return coverage_;
  auto &h = harts_.at(hart);
  auto found = h.stores.find(uid);
  if (found == h.stores.end() || !found->second.recorded)
    return pending("REF-checked store metadata lacks local store record");
  auto &store = found->second;
  if (store.verified)
    return invalid("duplicate REF store audit");
  if (store.audited.empty())
    store.audited.resize(store.memory.mask.size());
  auto reference = store.memory;
  for (unsigned byte = 0; byte < 8; ++byte)
    if ((mask >> byte) & 1) {
      const uint64_t at = address + byte;
      if (at < reference.address || at - reference.address >= reference.mask.size() ||
          !reference.mask[at - reference.address])
        return {CheckStatus::Violation, 0, "REF-checked store address/mask differs from provisional local write"};
      const size_t offset = at - reference.address;
      reference.bytes[offset] = (data >> (8 * byte)) & 255;
      if (reference.bytes[offset] != store.memory.bytes[offset])
        return {CheckStatus::Violation, 0, "REF-checked store data differs from provisional local write"};
      store.audited[offset] = 1;
    }
  for (size_t byte = 0; byte < reference.mask.size(); ++byte)
    if (reference.mask[byte] && !store.audited[byte])
      return {};
  auto result = checker_.verify_store(store.id, reference);
  if (!result)
    return result;
  store.verified = true;
  collect_released_stores();
  return {};
}
CheckResult Runtime::note_done(unsigned hart, int code) {
  auto &h = harts_.at(hart);
  if (h.done)
    return h.exit_code == code ? CheckResult{} : invalid("hart termination code changed");
  h.done = true;
  h.exit_code = code;
  h.end_uid = h.last_retired_uid;
  if (all_done())
    all_done_tick_ = capture_tick_;
  return {};
}
bool Runtime::all_done() const {
  return std::all_of(harts_.begin(), harts_.end(), [](const Hart &hart) { return hart.done; });
}
CheckResult Runtime::finish() {
  if (!failure_)
    return failure_;
  if (!all_done())
    return pending("INCOMPLETE_RUN: not every participating hart has terminated");
  if (!covered())
    return coverage_;
  // Allow all fixed-delay probe packets to arrive after the last relevant event.
  if (capture_tick_ <= std::max(all_done_tick_, last_event_tick_) + 4)
    return pending("INCOMPLETE_RUN: observation transport has not drained");
  for (const auto &h : harts_) {
    if (h.atomic_inflight)
      return pending("INCOMPLETE_RUN: atomic lifecycle has not finished");
    for (const auto &entry : h.atomics)
      if (!entry.second->verified || entry.first.uid > h.end_uid)
        return pending("INCOMPLETE_RUN: atomic reference audit is incomplete");
  }
  for (const auto &h: harts_)
    for (const auto &entry: h.stores)
      if (entry.second.recorded && entry.second.id.uid > h.end_uid)
        return {CheckStatus::Unsupported, 0, "local store beyond the selected hart termination prefix"};
  for (auto &h: harts_)
    for (auto &entry: h.loads) {
      auto &load = entry.second;
      if (!load->retired && !load->cancelled) {
        load->cancelled = true;
        if (load->observed) {
          auto result = checker_.cancel_load(load->operation.id, load->operation.attempt);
          if (!accepted(result))
            return result;
        }
      }
    }
  // Hart retirement does not end memory execution: cache misses may still
  // complete later. Never close future source cycles while stores are pending.
  auto result = advance(latest_cycle_ > 3 ? latest_cycle_ - 3 : 0);
  if (!result)
    return result;
  if (!events_.empty())
    return pending("INCOMPLETE_RUN: captured memory events await source-cycle closure");
  auto final_check = checker_.finalize();
  if (final_check)
    finalized_ = true;
  return final_check;
}

bool Runtime::print_final_statistics() {
  if (!finalized_ || !failure_ || !covered() || statistics_emitted_)
    return false;
  statistics_emitted_ = true;
  const auto &memory_statistics = checker_.memory_statistics();
  const auto &ppo_statistics = checker_.ppo_statistics();
  for (unsigned hart = 0; hart < harts_.size(); ++hart) {
    const auto memory = memory_statistics.find(hart);
    const CheckMemoryStatistics memory_stats = memory == memory_statistics.end() ? CheckMemoryStatistics{} : memory->second;
    const auto ppo = ppo_statistics.find(hart);
    const CheckPpoStatistics ppo_stats = ppo == ppo_statistics.end() ? CheckPpoStatistics{} : ppo->second;
    const auto &execution = harts_[hart];
    std::printf("RVWMO_HART_STATS_V1 hart=%u arch_compares=%llu ref_instructions=%llu "
                "ppo_retirements=%llu ppo_operations=%llu load_compares=%llu "
                "verified_stores=%llu store_audits=%llu cross_hart_reads=%llu\n",
                hart, static_cast<unsigned long long>(execution.arch_compares),
                static_cast<unsigned long long>(execution.ref_instructions),
                static_cast<unsigned long long>(ppo_stats.accepted_retirement_batches),
                static_cast<unsigned long long>(ppo_stats.accepted_memory_operations),
                static_cast<unsigned long long>(memory_stats.verified_load_operations),
                static_cast<unsigned long long>(memory_stats.verified_store_operations),
                static_cast<unsigned long long>(memory_stats.store_audits),
                static_cast<unsigned long long>(memory_stats.cross_hart_reads));
  }
  size_t pending_atomics = 0;
  for (const auto &hart : harts_) {
    pending_atomics += hart.atomic_inflight != nullptr;
    for (const auto &entry : hart.atomics)
      pending_atomics += !entry.second->verified;
  }
  // The internal fixed-delay replay watermark is not a producer-certified
  // closure. Report the missing certificate explicitly; never claim strict Pass.
  std::printf("RVWMO_SESSION_STATS_V1 watermarked=%u closed_through=%llu last_effect_cycle=%llu "
              "pending_events=%llu pending_retirements=%llu pending_loads=%llu "
              "pending_stores=%llu pending_atomics=%llu all_harts_done=%u\n",
              0u, 0ull,
              static_cast<unsigned long long>(last_effect_cycle_), static_cast<unsigned long long>(events_.size()),
              static_cast<unsigned long long>(checker_.pending_retirements()),
              static_cast<unsigned long long>(checker_.pending_loads()),
              static_cast<unsigned long long>(memory_.pending_stores()),
              static_cast<unsigned long long>(pending_atomics), static_cast<unsigned>(all_done()));
  std::fflush(stdout);
  return true;
}

} // namespace rvwmo
