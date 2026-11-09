#include "native_collector.h"
#include "csr_profile.h"
#include "../../rvwmo/producer_ids.h"
#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>

namespace rvwmo {
namespace boom {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }
CheckResult pending(const char *message) { return {CheckStatus::Pending, 0, message}; }
bool same_instruction(const ProbeIdentity &lhs, const ProbeIdentity &rhs) {
  return lhs.epoch == rhs.epoch && lhs.uid == rhs.uid && lhs.rob_generation == rhs.rob_generation;
}
bool same_terminal_owner(const ProbeIdentity &lhs, const ProbeIdentity &rhs) {
  return same_instruction(lhs, rhs) && lhs.memory_generation == rhs.memory_generation &&
         lhs.attempt == rhs.attempt;
}
bool faulting_scalar_refill(const ProbeLoad &probe, const InstructionAllocation &owner) {
  if (owner.length != 4 || !owner.ldq ||
      probe.sampling_point != LoadSamplingPoint::RefillData || !probe.source_complete ||
      probe.known_writer_mask || !probe.byte_mask)
    return false;
  unsigned log2_size = 0;
  if (const auto transfer = decode_floating_transfer(owner.instruction)) {
    if (transfer->kind != FloatingTransferKind::Load ||
        (transfer->bytes != 4 && transfer->bytes != 8))
      return false;
    log2_size = transfer->bytes == 4 ? 2 : 3; // FLW/FLD
  } else {
    if ((owner.instruction & 0x7f) != 0x03)
      return false;
    switch ((owner.instruction >> 12) & 7) {
    case 1: case 5: log2_size = 1; break; // LH/LHU
    case 2: case 6: log2_size = 2; break; // LW/LWU
    case 3: log2_size = 3; break;         // LD
    default: return false;
    }
  }
  if (probe.log2_size != log2_size)
    return false;
  const unsigned width = 1U << log2_size;
  return (probe.address & (width - 1)) != 0 && width > 8 - (probe.address & 7);
}
} // namespace

NativeCollector::NativeCollector(NativeCollectorConfiguration configuration)
    : configuration_(configuration), adapter_(configuration.hart, configuration.epoch, configuration.limits) {
  if (!hart_producer_id(configuration.hart) || !configuration.staged_events)
    throw std::invalid_argument("BOOM collector requires a valid hart and nonzero staging limit");
  if ((configuration.checked_ram_size == 0 && configuration.checked_ram_base != 0) ||
      configuration.checked_ram_size > std::numeric_limits<uint64_t>::max() - configuration.checked_ram_base)
    throw std::invalid_argument("BOOM collector requires a representable checked RAM interval");
  for (size_t i = 0; i < configuration.terminal_wfi_pcs.size(); ++i) {
    const auto pc = configuration.terminal_wfi_pcs[i];
    if (!pc || (pc & 1) || std::find(configuration.terminal_wfi_pcs.begin(),
          configuration.terminal_wfi_pcs.begin() + i, pc) != configuration.terminal_wfi_pcs.begin() + i)
      throw std::invalid_argument("BOOM terminal WFI PC must be nonzero, aligned and unique");
  }
}

OperationId NativeCollector::id(const ProbeIdentity &identity) const {
  return {configuration_.hart, identity.epoch, identity.uid, 0};
}

EventSource NativeCollector::capture_source(uint64_t cycle) {
  // Capture sequence is private lifecycle bookkeeping. take_ready assigns the
  // public sequence only after all source samples in the prefix have arrived.
  return {hart_producer_id(configuration_.hart), {cycle, 0, ++capture_sequence_, false}};
}

CheckResult NativeCollector::remember_failure(CheckResult result) {
  if (!result)
    failure_ = result;
  return result;
}

CaptureResult NativeCollector::capture(const NativeFrame &frame) {
  if (!failure_)
    return {failure_, false};
  const uint64_t expected = captured_cycle_ ? *captured_cycle_ + 1 : configuration_.initial_cycle;
  if ((captured_cycle_ && *captured_cycle_ == std::numeric_limits<uint64_t>::max()) ||
      frame.hart != configuration_.hart || frame.epoch != configuration_.epoch || frame.cycle != expected)
    return {remember_failure(invalid("BOOM source frame is missing, repeated or from another hart/epoch")), false};
  // Each retired AMO produces Response and Finish as well as InstructionRetire.
  // Reserve the whole source frame up front; a partial frame cannot be retried.
  const size_t atomic_retirements = std::count_if(frame.retirements.begin(), frame.retirements.end(),
      [](const ProbeInstruction &instruction) {
        return instruction.atomic && supported_amo_rmw(instruction.instruction);
      });
  const size_t facts = frame.allocations.size() + frame.begins.size() + frame.cancellations.size() +
      frame.completions.size() + frame.local_stores.size() + frame.retirements.size() +
      2 * atomic_retirements + frame.store_releases.size() + frame.squashes.size() +
      frame.publications.size() + frame.merged_publications.size() + frame.atomic_applied.size() +
      frame.csr_post.has_value() + frame.csr_write_post.has_value() +
      frame.counter_read.has_value() + frame.fp_posts.size() +
      frame.trap.has_value() + frame.trap_post.has_value();
  if (facts > configuration_.staged_events - std::min(configuration_.staged_events, staged_events_.size()))
    return {pending("BOOM source staging is full; retain the complete frame and drain before retrying"), false};
  if (facts > std::numeric_limits<uint64_t>::max() - capture_sequence_)
    return {remember_failure(invalid("BOOM capture sequence exhausted")), false};
  auto result = capture_frame(frame);
  if (!result) {
    // A frame may already have applied earlier native facts. It cannot be
    // retried after partial application or silently discarded as backpressure.
    if (result.status == CheckStatus::Pending)
      result = incomplete("BOOM lifecycle capacity prevents lossless frame consumption");
    return {remember_failure(result), false};
  }
  captured_cycle_ = frame.cycle;
  queues_empty_ = frame.queues_empty;
  cache_idle_ = frame.cache_idle;
  result = collect_adapter_output();
  return {remember_failure(result), static_cast<bool>(result)};
}

CheckResult NativeCollector::require_checked_ram(uint64_t address, size_t bytes) const {
  if (!configuration_.checked_ram_size)
    return {}; // Existing scalar-only fixtures; the host must opt in to RAM bounds.
  const uint64_t end = configuration_.checked_ram_base + configuration_.checked_ram_size;
  if (address < configuration_.checked_ram_base || address >= end || bytes > end - address)
    return {CheckStatus::Unsupported, 0,
            "BOOM MMIO access lacks independent REF/device and publication evidence"};
  return {};
}

CheckResult NativeCollector::capture_frame(const NativeFrame &frame) {
  auto trap_result = capture_trap_post(frame);
  if (!trap_result) return trap_result;
  if (configuration_.check_csr_post && frame.csr_post) {
    const auto &post = *frame.csr_post;
    const OperationId id{configuration_.hart, post.identity.epoch, post.identity.uid, 0};
    auto expected = pending_csr_.find(id);
    if (expected == pending_csr_.end() ||
        expected->second.after || expected->second.retirement_cycle == UINT64_MAX ||
        frame.cycle != expected->second.retirement_cycle + 1 ||
        post.source_cycle != expected->second.retirement_cycle || post.pc != expected->second.pc ||
        post.address != expected->second.address ||
        post.identity.rob_generation != expected->second.rob_generation)
      return invalid("BOOM post-retirement CSR value lacks its immediately preceding CSR owner");
    expected->second.after = post.value;
  }
  if (configuration_.check_fp_post) {
    for (const auto &post : frame.fp_posts) {
      const auto owner = pending_fp_.find(id(post.identity));
      if (!frame.fp_probe_available || owner == pending_fp_.end() || owner->second.after ||
          owner->second.retirement_cycle == UINT64_MAX ||
          owner->second.retirement_cycle + 1 != frame.cycle ||
          owner->second.retirement_cycle != post.source_cycle || owner->second.pc != post.pc ||
          owner->second.rob_generation != post.identity.rob_generation)
        return invalid("BOOM FP post-state lacks its immediately preceding transfer owner");
      owner->second.after = FloatingPostState{post.fcsr, post.mstatus};
    }
  }
  auto result = capture_allocations(frame);
  if (!result || !(result = capture_counter_write(frame)) ||
      !(result = capture_counter_read(frame)) || !(result = capture_attempts(frame)))
    return result;
  for (const auto &store : frame.local_stores) {
    if (store.atomic) {
      const auto instruction_id = id(store.identity);
      const auto allocation = allocations_.find(instruction_id);
      if (allocation == allocations_.end() ||
          allocation->second.rob.generation != store.identity.rob_generation ||
          !supported_amo_rmw(allocation->second.instruction) || !allocation->second.stq ||
          allocation->second.stq->index != store.queue_index ||
          allocation->second.stq->generation != store.identity.memory_generation ||
          store.log2_size != ((allocation->second.instruction >> 12) & 7))
        return invalid("BOOM local AMO commit lacks matching ROB/STQ generation or width");
      const unsigned width = store.log2_size == 3 ? 8 : 4;
      auto checked = require_checked_ram(store.address, width);
      if (!checked)
        return checked;
      checked = adapter_.commit_atomic_local({instruction_id, *allocation->second.stq,
          store.address, store.byte_mask, store.command});
      if (!checked)
        return checked;
      continue;
    }
    StoreCommit local;
    auto result = convert_store(configuration_.hart, store, capture_source(frame.cycle), local);
    if (!result)
      return result;
    result = require_checked_ram(local.address, local.bytes.size());
    if (!result) {
      const uint64_t ram_end = configuration_.checked_ram_base + configuration_.checked_ram_size;
      const bool outside_ram = local.address >= ram_end ||
          (local.address < configuration_.checked_ram_base &&
           local.bytes.size() <= configuration_.checked_ram_base - local.address);
      if (!configuration_.skip_device_stores || result.status != CheckStatus::Unsupported || !outside_ram)
        return result;
      result = adapter_.skip_device_store(local);
      if (result && !skipped_device_stores_.insert(local.id).second)
        return invalid("BOOM device store has duplicate local commit");
    } else {
      result = adapter_.commit_store(local);
    }
    if (!result)
      return result;
  }
  for (const auto &effect : frame.atomic_applied) {
    const auto instruction_id = id(effect.identity);
    const auto allocation = allocations_.find(instruction_id);
    if (allocation == allocations_.end() ||
        allocation->second.rob.generation != effect.identity.rob_generation ||
        !supported_amo_rmw(allocation->second.instruction) || !allocation->second.stq ||
        allocation->second.stq->index != effect.queue_index ||
        allocation->second.stq->generation != effect.identity.memory_generation ||
        effect.mem_size != ((allocation->second.instruction >> 12) & 7))
      return invalid("BOOM physical AMO effect lacks its exact live ROB/STQ owner");
    if (effect.source_cycle != frame.cycle || effect.source.position.cycle != effect.source_cycle)
      return invalid("BOOM physical AMO effect source cycle differs from actual cache-write edge");
    const unsigned width = effect.mem_size == 3 ? 8 : 4;
    result = require_checked_ram(effect.address, width);
    if (!result)
      return result;
    result = adapter_.apply_atomic({instruction_id, *allocation->second.stq, effect.identity.attempt,
        effect.address, effect.old_word, effect.new_word, effect.byte_mask, effect.command,
        effect.exclusive_valid, effect.source});
    if (!result)
      return result;
  }
  result = capture_retirements(frame);
  if (!result || !(result = capture_trap_begin(frame)) || !(result = capture_terminations(frame)))
    return result;
  for (const auto &publication : frame.publications) {
    if (publication.source.position.cycle > frame.cycle)
      return invalid("BOOM store publication claims a future source cycle");
    StorePublication converted;
    auto result = convert_single_store_publication(configuration_.hart, publication.probe, publication.source,
        publication.transaction_id, publication.evidence, publication.single_writer_complete, converted);
    if (!result)
      return result;
    result = require_checked_ram(converted.address, converted.bytes.size());
    if (!result || !(result = adapter_.publish_store(converted)))
      return result;
  }
  for (const auto &publication : frame.merged_publications) {
    if (publication.source.position.cycle > frame.cycle)
      return invalid("BOOM merged publication claims a future source cycle");
    if (!publication.bytes.empty()) {
      auto range = require_checked_ram(publication.address, publication.bytes.size());
      if (!range)
        return range;
    }
    auto result = adapter_.publish_merged_stores(publication);
    if (!result)
      return result;
  }
  return {};
}

CheckResult NativeCollector::capture_allocations(const NativeFrame &frame) {
  std::set<size_t> used_queues;
  for (const auto &core : frame.allocations) {
    std::optional<ProbeQueueAllocation> queue;
    for (size_t index = 0; index < frame.queue_allocations.size(); ++index) {
      const auto &candidate = frame.queue_allocations[index];
      if (!same_instruction(core.identity, candidate.identity))
        continue;
      if (queue || !used_queues.insert(index).second)
        return invalid("BOOM dispatch has duplicate queue identity");
      queue = candidate;
    }
    InstructionAllocation allocation;
    auto result = merge_allocation(configuration_.hart, core, queue, configuration_.limits.ldq_slots,
                                   configuration_.limits.stq_slots, capture_source(frame.cycle), allocation);
    if (!result)
      return result;
    const bool delimiter = std::find(configuration_.terminal_wfi_pcs.begin(),
        configuration_.terminal_wfi_pcs.end(), allocation.pc) != configuration_.terminal_wfi_pcs.end();
    if (!configuration_.terminal_wfi_pcs.empty() && allocation.id.uid <= last_allocated_uid_)
      return invalid("BOOM terminal profile dispatch UID is not strictly increasing");
    if (certified_terminal_wfi_)
      return incomplete("BOOM instruction allocated after its terminal WFI was certified");
    if (allocations_.count(allocation.id) || std::any_of(allocations_.begin(), allocations_.end(),
          [&](const auto &existing) { return existing.second.rob.index == allocation.rob.index; }))
      return invalid("BOOM terminal profile reuses a live instruction identity or ROB slot");
    if (delimiter) {
      if (allocation.instruction != 0x10500073 || allocation.length != 4 || allocation.ldq || allocation.stq)
        return invalid("BOOM ELF terminal WFI PC dispatched a different instruction or memory operation");
      if (!terminal_wfis_.emplace(allocation.id, HeldTerminalWfi{allocation, core.identity}).second)
        return invalid("BOOM terminal WFI repeats a live owner");
    } else if (!(result = adapter_.allocate(allocation))) {
      return result;
    }
    allocations_.emplace(allocation.id, allocation);
    if (!configuration_.terminal_wfi_pcs.empty())
      last_allocated_uid_ = allocation.id.uid;
  }
  if (used_queues.size() != frame.queue_allocations.size())
    return invalid("BOOM queue allocation has no matching core dispatch");

  return {};
}

CheckResult NativeCollector::capture_counter_write(const NativeFrame &frame) {
  if (!frame.csr_write_post || !configuration_.check_csr_post)
    return {};
  const auto &post = *frame.csr_write_post;
  const auto instruction_id = id(post.identity);
  const auto allocation = allocations_.find(instruction_id);
  if (!frame.csr_write_probe_available || allocation == allocations_.end() ||
      allocation->second.rob.generation != post.identity.rob_generation ||
      allocation->second.pc != post.pc ||
      !certified_counter_write(allocation->second.instruction) ||
      (allocation->second.instruction >> 20) != post.address ||
      post.source_cycle == UINT64_MAX || post.source_cycle + 1 != frame.cycle)
    return invalid("BOOM physical counter write sample has no live CSR owner");
  if (!pending_counter_writes_.emplace(instruction_id, post).second)
    return invalid("BOOM physical counter write has multiple post-state samples");
  return {};
}

CheckResult NativeCollector::capture_counter_read(const NativeFrame &frame) {
  if (!frame.counter_read)
    return {};
  if (!configuration_.check_counter_reads || !frame.counter_read_probe_available)
    return {CheckStatus::Unsupported, 0, "BOOM counter environment has no enabled physical read probe"};
  const auto &sample = *frame.counter_read;
  const auto owner = allocations_.find(id(sample.identity));
  if (owner == allocations_.end() || owner->second.rob.generation != sample.identity.rob_generation ||
      owner->second.pc != sample.pc || !supported_mcycle_read(owner->second.instruction) ||
      sample.address != 0xb00 || sample.source_cycle == 0 || sample.source_cycle == UINT64_MAX ||
      sample.source_cycle + 1 != frame.cycle || sample.identity.memory_generation || sample.identity.attempt)
    return invalid("BOOM counter read has stale identity, source time or CSR address");
  if (!pending_counter_reads_.emplace(id(sample.identity), sample).second)
    return invalid("BOOM counter read repeats a physical execution sample");
  return {};
}

CheckResult NativeCollector::capture_attempts(const NativeFrame &frame) {
  std::set<OperationId> beginning_instructions;
  std::set<AttemptKey> begins;
  for (const auto &begin : frame.begins) {
    auto result = validate_attempt(begin);
    if (!result)
      return result;
    if (pending_trap_ && same_instruction(begin.identity, pending_trap_->identity))
      return invalid("BOOM faulted load started a new attempt after its physical trap");
    const AttemptKey key{id(begin.identity), begin.identity.attempt};
    if (!beginning_instructions.insert(key.first).second || !begins.insert(key).second ||
        unresolved_samples_.count(key))
      return invalid("BOOM source frame repeats a load execution begin");
  }
  std::map<AttemptKey, NativeAttempt> cancellations;
  for (const auto &cancel : frame.cancellations) {
    auto result = validate_attempt(cancel);
    if (!result)
      return result;
    cancellations.emplace(AttemptKey{id(cancel.identity), cancel.identity.attempt}, cancel);
  }
  // A TLB retry may begin on the edge that reports the previous attempt's
  // delayed cancellation. Normalize those private lifecycle facts before the
  // new begin; a cancellation of that new attempt still follows its own begin.
  for (const auto &cancel : cancellations) {
    if (begins.count(cancel.first))
      continue;
    auto result = capture_cancellation(cancel.second, frame.cycle);
    if (!result)
      return result;
  }
  for (const auto &begin : frame.begins) {
    auto result = adapter_.begin_load_attempt(convert_attempt(configuration_.hart, begin.identity, begin.queue_index),
                                               capture_source(frame.cycle));
    if (!result)
      return result;
    unresolved_samples_.emplace(AttemptKey{id(begin.identity), begin.identity.attempt}, frame.cycle);
  }
  for (const auto &cancel : cancellations) {
    if (!begins.count(cancel.first))
      continue;
    auto result = capture_cancellation(cancel.second, frame.cycle);
    if (!result)
      return result;
  }
  for (const auto &complete : frame.completions) {
    const auto &probe = complete.probe;
    auto checked = validate_attempt({probe.identity, probe.queue_index});
    if (!checked)
      return checked;
    if (fault_rollback_cancellations_.count({id(probe.identity), probe.identity.attempt}))
      return invalid("BOOM faulted load completed after its physical cancellation");
    if (complete.sampled_at.cycle > frame.cycle)
      return invalid("BOOM completed load claims a future source cycle");
    const AttemptKey key{id(probe.identity), probe.identity.attempt};
    const auto owner = allocations_.find(key.first);
    if (owner != allocations_.end() && faulting_scalar_refill(probe, owner->second)) {
      // The one-word refill has no second-word bytes or writer identities.
      // It is not a valid LoadSample. Only a later precise misaligned-load
      // trap (or a cancelled/squashed attempt) can discharge this candidate.
      const auto begin = unresolved_samples_.find(key);
      if (begin == unresolved_samples_.end() || complete.sampled_at.cycle < begin->second ||
          !faulting_refills_.emplace(key.first, key.second).second)
        return invalid("BOOM faulting refill repeats or lacks its live load attempt");
      auto checked_ram = require_checked_ram(probe.address, size_t{1} << probe.log2_size);
      if (!checked_ram)
        return checked_ram;
      unresolved_samples_.erase(key);
      continue;
    }
    LoadObservation sample;
    auto source = capture_source(complete.sampled_at.cycle);
    source.position.qualified_phase = complete.sampled_at.qualified_phase;
    source.position.order_qualified = complete.sampled_at.order_qualified;
    auto result = convert_load(configuration_.hart, probe, source, sample);
    if (!result || !(result = adapter_.sample_load(sample)))
      return result;
    unresolved_samples_.erase({id(probe.identity), probe.identity.attempt});
  }
  return {};
}

CheckResult NativeCollector::capture_cancellation(const NativeAttempt &cancel, uint64_t cycle) {
  if (pending_trap_ && same_instruction(cancel.identity, pending_trap_->identity)) {
    const AttemptKey key{id(cancel.identity), cancel.identity.attempt};
    const auto live = unresolved_samples_.find(key);
    const auto refill = faulting_refills_.find(key.first);
    const bool faulting_refill = refill != faulting_refills_.end() && refill->second == key.second;
    // Only an already begun, unsampled attempt of the exact fault owner can
    // cancel at T+1. The physical fact remains private until the matched
    // Trap(T), post-state(T+2), and rollback(T+3) all close.
    if (pending_trap_->source_cycle == UINT64_MAX || cycle != pending_trap_->source_cycle + 1 ||
        (live == unresolved_samples_.end() && !faulting_refill) ||
        !fault_rollback_cancellations_.emplace(key, cycle).second)
      return invalid("BOOM post-trap cancel lacks one live unsampled fault attempt");
    return {};
  }
  auto result = adapter_.cancel_load_attempt(convert_attempt(configuration_.hart, cancel.identity, cancel.queue_index),
                                             capture_source(cycle));
  if (result) {
    const auto fault = faulting_refills_.find(id(cancel.identity));
    if (fault != faulting_refills_.end() && fault->second == cancel.identity.attempt)
      faulting_refills_.erase(fault);
    unresolved_samples_.erase({id(cancel.identity), cancel.identity.attempt});
  }
  return result;
}

CheckResult NativeCollector::capture_retirements(const NativeFrame &frame) {
  std::set<size_t> used_retired_loads;
  for (const auto &core : frame.retirements) {
    const auto instruction_id = id(core.identity);
    auto allocation = allocations_.find(instruction_id);
    if (allocation == allocations_.end())
      return invalid("BOOM retirement has no retained core/queue allocation");
    if (core.identity.rob_generation != allocation->second.rob.generation ||
        core.rob_index != allocation->second.rob.index || core.pc != allocation->second.pc ||
        core.instruction != allocation->second.instruction ||
        core.uses_ldq != allocation->second.ldq.has_value() || core.uses_stq != allocation->second.stq.has_value())
      return invalid("BOOM physical retirement differs from its retained core/ROB allocation");
    if (core.architectural && faulting_refills_.count(instruction_id))
      return {CheckStatus::Unsupported, 0, "BOOM cross-word refill retired without a precise misalignment trap"};
    // ECALL/EBREAK may retire physically before the precise exception edge.
    // Do not step REF or free the ROB owner until its matching trap post-state.
    const bool system_trap = core.architectural &&
        (core.instruction == 0x00000073 || core.instruction == 0x00100073);
    if (system_trap) {
      if (pending_system_ || pending_trap_ || core.uses_ldq || core.uses_stq || core.atomic)
        return invalid("BOOM ECALL/EBREAK retired without an isolated physical ROB owner");
      pending_system_ = PendingSystem{core, frame.cycle};
      continue;
    }
    if (pending_system_)
      return invalid("BOOM newer instruction retired before held ECALL/EBREAK trap boundary");
    const bool terminal_wfi = terminal_wfis_.count(instruction_id) != 0;
    if (terminal_wfi && core.architectural)
      return incomplete("BOOM terminal WFI retired instead of remaining physically parked");
    if (!core.architectural) {
      if (!terminal_wfi) {
        auto result = adapter_.squash(instruction_id, allocation->second.rob, capture_source(frame.cycle));
        if (!result)
          return result;
      }
    } else {
      std::optional<ProbeLoadRetirement> load;
      for (size_t index = 0; index < frame.retired_loads.size(); ++index) {
        const auto &candidate = frame.retired_loads[index];
        if (!same_instruction(core.identity, candidate.identity))
          continue;
        if (load || !used_retired_loads.insert(index).second)
          return invalid("BOOM retirement has duplicate final LDQ identities");
        load = candidate;
      }
      Retirement retirement;
      const bool amo_rmw = core.atomic && supported_amo_rmw(core.instruction);
      std::optional<EventSource> response_source, finish_source;
      if (amo_rmw) {
        response_source = capture_source(frame.cycle);
        finish_source = capture_source(frame.cycle);
      }
      auto result = merge_retirement(configuration_.hart, core, allocation->second, load,
                                     configuration_.limits.ldq_slots, configuration_.limits.stq_slots,
                                     capture_source(frame.cycle), retirement);
      if (!result)
        return result;
      retirement.atomic_response_source = response_source;
      retirement.atomic_finish_source = finish_source;
      if (retirement.load_address && retirement.load_log2_size && *retirement.load_log2_size <= 3) {
        result = require_checked_ram(*retirement.load_address, size_t{1} << *retirement.load_log2_size);
        if (!result)
          return result;
      }
      retirement.skipped_device_store = skipped_device_stores_.count(instruction_id) != 0;
      result = adapter_.retire(retirement);
      if (result)
        skipped_device_stores_.erase(instruction_id);
      if (!result)
        return result;
      if (configuration_.check_fp_post && decode_floating_transfer(core.instruction)) {
        if (!frame.fp_probe_available)
          return {CheckStatus::Unsupported, 0, "BOOM FP retirement lacks a physical status probe"};
        if (!pending_fp_.emplace(instruction_id,
              PendingFp{core.pc, frame.cycle, core.identity.rob_generation, std::nullopt}).second)
          return invalid("BOOM FP retirement repeats an existing transfer owner");
      }
      if (supported_mcycle_read(core.instruction)) {
        if (!configuration_.check_counter_reads || !frame.counter_read_probe_available)
          return {CheckStatus::Unsupported, 0, "BOOM mcycle read lacks a physical counter environment"};
        const auto sample = pending_counter_reads_.find(instruction_id);
        if (sample == pending_counter_reads_.end())
          return incomplete("BOOM retiring mcycle read lacks its execution-time sample");
        if (sample->second.source_cycle > frame.cycle)
          return invalid("BOOM counter read sample follows its owner retirement");
      }
      if (configuration_.check_csr_post && certified_csr_instruction(core.instruction)) {
        const bool counter_write = certified_counter_write(core.instruction);
        if (!(counter_write ? frame.csr_write_probe_available : frame.csr_probe_available))
          return {CheckStatus::Unsupported, 0, "BOOM CSR retirement lacks an enabled physical post-state probe"};
        std::optional<uint64_t> observed;
        if (counter_write) {
          auto sample = pending_counter_writes_.find(instruction_id);
          if (sample == pending_counter_writes_.end())
            return incomplete("BOOM retiring counter write lacks an accepted physical CSR sample");
          observed = sample->second.value;
          pending_counter_writes_.erase(sample);
        }
        if (!pending_csr_.emplace(instruction_id, PendingCsr{core.pc, frame.cycle,
              static_cast<uint16_t>(core.instruction >> 20), observed,
              core.identity.rob_generation}).second)
          return invalid("BOOM CSR retirement repeats a pending CSR owner");
      }
    }
    if (!core.architectural) {
      pending_counter_writes_.erase(instruction_id);
      pending_counter_reads_.erase(instruction_id);
      pending_fp_.erase(instruction_id);
    }
    terminal_wfis_.erase(instruction_id);
    allocations_.erase(allocation);
    faulting_refills_.erase(instruction_id);
    for (auto attempt = unresolved_samples_.begin(); attempt != unresolved_samples_.end();)
      if (attempt->first.first == instruction_id)
        attempt = unresolved_samples_.erase(attempt);
      else
        ++attempt;
  }
  if (used_retired_loads.size() != frame.retired_loads.size())
    return invalid("BOOM final LDQ result has no matching architectural retirement");
  return {};
}

CheckResult NativeCollector::capture_trap_begin(const NativeFrame &frame) {
  if (!frame.trap) {
    if (pending_system_ && frame.cycle > pending_system_->retirement_cycle &&
        frame.cycle - pending_system_->retirement_cycle > 3)
      return incomplete("BOOM retired ECALL/EBREAK never produced its precise physical trap");
    return {};
  }
  if (!frame.trap_post_probe_available)
    return {CheckStatus::Unsupported, 0, "BOOM physical trap lacks a UID-linked CSR post-state probe"};
  const auto &trap = *frame.trap;
  const auto instruction_id = id(trap.identity);
  const auto owner = allocations_.find(instruction_id);
  if (pending_trap_ || pending_fault_rollback_ || owner == allocations_.end() || trap.source_cycle != frame.cycle ||
      trap.pc != owner->second.pc || trap.identity.rob_generation != owner->second.rob.generation)
    return invalid("BOOM physical trap has no unique live instruction/ROB owner");
  if (pending_system_ && (!same_instruction(pending_system_->core.identity, trap.identity) ||
                          pending_system_->core.pc != trap.pc))
    return invalid("BOOM system trap UID or PC differs from its retired owner");
  pending_trap_ = trap;
  return {};
}

CheckResult NativeCollector::capture_trap_post(const NativeFrame &frame) {
  if (!pending_trap_)
    return frame.trap_post ? invalid("BOOM trap post-state has no preceding physical trap") : CheckResult{};
  const auto &trap = *pending_trap_;
  if (trap.source_cycle == UINT64_MAX || frame.cycle <= trap.source_cycle)
    return invalid("BOOM trap post-state arrived before its physical exception edge");
  if (frame.cycle == trap.source_cycle + 1)
    return frame.trap_post ? invalid("BOOM trap post-state arrived one cycle too early") : CheckResult{};
  if (frame.cycle != trap.source_cycle + 2 || !frame.trap_post)
    return incomplete("BOOM precise trap lacks the immediate two-cycle CSR/redirect post-state");
  const auto &post = *frame.trap_post;
  const auto instruction_id = id(trap.identity);
  const auto allocation = allocations_.find(instruction_id);
  if (allocation == allocations_.end() || !same_instruction(post.identity, trap.identity) ||
      post.source_cycle != trap.source_cycle || post.pc != trap.pc || post.cause != trap.cause ||
      post.target_pc % 2 || (post.privilege != 1 && post.privilege != 3))
    return invalid("BOOM trap post-state UID, timing, PC, cause, target or privilege is inconsistent");
  if (post.privilege == 3 ? (post.mepc != trap.pc || post.mcause != trap.cause)
                          : (post.sepc != trap.pc || post.scause != trap.cause))
    return {CheckStatus::Violation, 0, "BOOM trap CSR EPC/cause differs from its physical fault"};
  const bool physically_retired = pending_system_.has_value();
  if (faulting_refills_.count(instruction_id) && trap.cause != 4)
    return {CheckStatus::Unsupported, 0, "BOOM cross-word refill lacks a misaligned-load fault"};
  if (!physically_retired && trap.source_cycle > UINT64_MAX - 3)
    return incomplete("BOOM synchronous fault lacks a bounded precise rollback owner");
  auto recorded = adapter_.trap(instruction_id, allocation->second.rob, trap.pc, trap.cause,
                                capture_source(trap.source_cycle));
  if (!recorded) return recorded;
  ArchitecturalTrap snapshot{instruction_id, allocation->second.instruction, post.pc, post.cause, post.target_pc, post.privilege,
      post.mstatus, post.mepc, post.mcause, post.mtval, post.sepc, post.scause, post.stval,
      physically_retired};
  if (!staged_traps_.emplace(instruction_id, snapshot).second)
    return invalid("BOOM physical trap post-state repeats its architectural UID");
  faulting_refills_.erase(instruction_id);
  if (!physically_retired)
    pending_fault_rollback_ = PendingFaultRollback{trap.identity, allocation->second.rob.index,
                                                    trap.source_cycle + 3};
  allocations_.erase(allocation);
  pending_trap_.reset();
  pending_system_.reset();
  return {};
}

CheckResult NativeCollector::capture_terminations(const NativeFrame &frame) {
  for (const auto &release : frame.store_releases) {
    auto result = adapter_.release_store_slot(id(release.identity), {release.queue_index, release.identity.memory_generation});
    if (!result)
      return result;
  }
  for (const auto &squash : frame.squashes) {
    if (pending_fault_rollback_ &&
        same_instruction(squash.identity, pending_fault_rollback_->identity)) {
      if (!squash.rollback || squash.rob_index != pending_fault_rollback_->rob_index ||
          frame.cycle != pending_fault_rollback_->cycle ||
          allocations_.count(id(squash.identity)))
        return invalid("BOOM fault owner rollback has wrong ROB, cycle or identity");
      // A faulted load can have a private begin with no data sample. Keep that
      // source prefix open until the exact physical ROB rollback proves the
      // attempt cannot produce a late public sample.
      const auto instruction_id = id(squash.identity);
      for (auto cancel = fault_rollback_cancellations_.begin();
           cancel != fault_rollback_cancellations_.end();) {
        if (cancel->first.first == instruction_id)
          cancel = fault_rollback_cancellations_.erase(cancel);
        else
          ++cancel;
      }
      for (auto attempt = unresolved_samples_.begin(); attempt != unresolved_samples_.end();) {
        if (attempt->first.first == instruction_id)
          attempt = unresolved_samples_.erase(attempt);
        else
          ++attempt;
      }
      pending_fault_rollback_.reset();
      continue;
    }
    const auto instruction_id = id(squash.identity);
    auto allocation = allocations_.find(instruction_id);
    if (pending_trap_ && same_instruction(squash.identity, pending_trap_->identity)) {
      if (!squash.rollback || allocation == allocations_.end() ||
          allocation->second.rob.index != squash.rob_index ||
          allocation->second.rob.generation != squash.identity.rob_generation)
        return invalid("BOOM fault owner squash differs from its physical ROB trap");
      continue;
    }
    if (pending_system_ && same_instruction(squash.identity, pending_system_->core.identity))
      return invalid("BOOM held ECALL/EBREAK was squashed before its matching trap");
    if (allocation == allocations_.end() || allocation->second.rob.index != squash.rob_index ||
        allocation->second.rob.generation != squash.identity.rob_generation)
      return invalid("BOOM squash has no matching live ROB generation");
    if (!terminal_wfis_.count(instruction_id)) {
      auto result = adapter_.squash(instruction_id, allocation->second.rob, capture_source(frame.cycle));
      if (!result)
        return result;
    }
    terminal_wfis_.erase(instruction_id);
    pending_counter_writes_.erase(instruction_id);
    pending_counter_reads_.erase(instruction_id);
    pending_fp_.erase(instruction_id);
    allocations_.erase(allocation);
    faulting_refills_.erase(instruction_id);
    for (auto attempt = unresolved_samples_.begin(); attempt != unresolved_samples_.end();)
      if (attempt->first.first == instruction_id)
        attempt = unresolved_samples_.erase(attempt);
      else
        ++attempt;
  }
  if (pending_fault_rollback_ && frame.cycle >= pending_fault_rollback_->cycle)
    return incomplete("BOOM precise synchronous trap lacks its immediate physical ROB rollback");
  return {};
}

CheckResult NativeCollector::validate_attempt(const NativeAttempt &attempt) const {
  auto allocation = allocations_.find(id(attempt.identity));
  if (allocation == allocations_.end() || !allocation->second.ldq ||
      allocation->second.rob.generation != attempt.identity.rob_generation ||
      allocation->second.ldq->generation != attempt.identity.memory_generation ||
      allocation->second.ldq->index != attempt.queue_index)
    return invalid("BOOM native load attempt has a stale ROB or LDQ identity");
  return {};
}

CheckResult NativeCollector::collect_adapter_output() {
  auto batch = adapter_.take_batch();
  staged_events_.insert(staged_events_.end(), batch.events.begin(), batch.events.end());
  auto retirements = adapter_.take_retirements();
  staged_retirements_.insert(staged_retirements_.end(), retirements.begin(), retirements.end());
  if (staged_events_.size() > configuration_.staged_events)
    return incomplete("BOOM source staging limit exceeded");
  return {};
}

CheckResult NativeCollector::take_ready(CollectedObservations &output) {
  if (!failure_)
    return failure_;
  if (!captured_cycle_)
    return pending("BOOM collector has not captured a complete source edge");
  uint64_t through = *captured_cycle_;
  if (pending_system_) {
    if (!pending_system_->retirement_cycle)
      return incomplete("BOOM system trap retirement at cycle zero cannot close a prefix");
    through = std::min(through, pending_system_->retirement_cycle - 1);
  }
  if (pending_fault_rollback_) {
    if (pending_fault_rollback_->cycle < 4)
      return incomplete("BOOM fault owner rollback cannot close a cycle-zero prefix");
    through = std::min(through, pending_fault_rollback_->cycle - 4);
  }
  if (pending_trap_) {
    if (!pending_trap_->source_cycle)
      return incomplete("BOOM trap at cycle zero cannot close a prefix");
    through = std::min(through, pending_trap_->source_cycle - 1);
  }
  for (const auto &csr : pending_csr_) {
    if (!csr.second.after) {
      if (!csr.second.retirement_cycle)
        return incomplete("BOOM CSR retirement at cycle zero needs a delayed CSR sample");
      through = std::min(through, csr.second.retirement_cycle - 1);
    }
  }
  for (const auto &fp : pending_fp_) {
    if (!fp.second.after) {
      if (!fp.second.retirement_cycle)
        return incomplete("BOOM FP retirement at cycle zero needs a delayed status sample");
      through = std::min(through, fp.second.retirement_cycle - 1);
    }
  }
  for (const auto &attempt : unresolved_samples_) {
    if (!attempt.second)
      return pending("BOOM unresolved load can still sample cycle zero");
    through = std::min(through, attempt.second - 1);
  }
  if (closed_cycle_ && through <= *closed_cycle_)
    return pending("BOOM delayed load sample keeps the source prefix open");
  auto result = adapter_.close_prefix({hart_producer_id(configuration_.hart), SourcePosition::end_of_cycle(through)});
  if (!result)
    return result;
  adapter_.take_batch(); // The only generated record here is the checked hart watermark.
  std::stable_sort(staged_events_.begin(), staged_events_.end(), [](const RuntimeEvent &lhs, const RuntimeEvent &rhs) {
    return lhs.source.cycle < rhs.source.cycle;
  });
  CollectedObservations ready;
  std::map<OperationId, SourcePosition> retirement_positions;
  uint64_t next_sequence = emitted_sequence_;
  // The shared session certifies concurrent read prefixes and checks PPO ties.
  // This producer sequence preserves delivery identity, not subcycle GMO order.
  for (const auto &event : staged_events_) {
    if (event.source.cycle > through)
      continue;
    auto converted = event;
    if (event.producer_id == hart_producer_id(configuration_.hart)) {
      if (next_sequence == std::numeric_limits<uint64_t>::max())
        return remember_failure(invalid("BOOM public source sequence exhausted"));
      converted.source.producer_sequence = ++next_sequence;
    }
    if (event.kind == RuntimeEventKind::Trap) {
      const auto &trapped = std::get<TrapEvent>(event.payload);
      const auto snapshot = staged_traps_.find(trapped.instruction);
      if (snapshot == staged_traps_.end())
        return remember_failure(incomplete("BOOM trap lacks its matched physical post-state snapshot"));
      ready.traps.push_back(snapshot->second);
    }
    if (event.kind == RuntimeEventKind::InstructionRetire) {
      const auto &retired = std::get<InstructionRetireEvent>(event.payload).instruction;
      retirement_positions[{retired.hart, retired.epoch, retired.uid, 0}] = converted.source;
    }
    ready.batch.events.push_back(std::move(converted));
  }
  std::vector<OperationId> converted_csr, converted_fp, converted_counters;
  for (const auto &retirement : staged_retirements_) {
    auto position = retirement_positions.find(retirement.id);
    if (position == retirement_positions.end())
      continue;
    auto captured = retirement;
    auto pending = pending_csr_.find(retirement.id);
    if (pending != pending_csr_.end()) {
      if (!pending->second.after)
        return remember_failure(incomplete("BOOM CSR retirement escaped before its post-update sample"));
      captured.csr_post = std::make_pair(pending->second.address, *pending->second.after);
      converted_csr.push_back(retirement.id);
    }
    auto counter = pending_counter_reads_.find(retirement.id);
    if (counter != pending_counter_reads_.end()) {
      const auto &sample = counter->second;
      captured.counter_read = CounterReadEnvironment{sample.address, sample.source_cycle, sample.value};
      converted_counters.push_back(retirement.id);
    }
    auto fp = pending_fp_.find(retirement.id);
    if (fp != pending_fp_.end()) {
      if (!fp->second.after)
        return remember_failure(incomplete("BOOM FP retirement escaped without its physical status sample"));
      captured.fp_post = *fp->second.after;
      converted_fp.push_back(retirement.id);
    }
    ArchitecturalRetirement converted;
    result = convert_retirement_snapshot(captured, converted);
    if (!result)
      return remember_failure(result);
    ready.retirements.push_back(converted);
  }
  ready.batch.watermarks.push_back({hart_producer_id(configuration_.hart), SourcePosition::end_of_cycle(through)});
  staged_events_.erase(std::remove_if(staged_events_.begin(), staged_events_.end(), [through](const RuntimeEvent &event) {
    return event.source.cycle <= through;
  }), staged_events_.end());
  staged_retirements_.erase(std::remove_if(staged_retirements_.begin(), staged_retirements_.end(),
      [&](const CapturedRetirement &event) { return retirement_positions.count(event.id); }), staged_retirements_.end());
  for (const auto &id : converted_csr)
    pending_csr_.erase(id);
  for (const auto &id : converted_fp)
    pending_fp_.erase(id);
  for (const auto &id : converted_counters)
    pending_counter_reads_.erase(id);
  for (const auto &trap : ready.traps)
    staged_traps_.erase(trap.id);
  emitted_sequence_ = next_sequence;
  closed_cycle_ = through;
  output = std::move(ready);
  return {};
}

CheckResult NativeCollector::audit_reference_store(const ReferenceStoreAudit &reference) {
  if (!failure_)
    return failure_;
  auto result = adapter_.audit_reference_store(reference);
  if (result.status == CheckStatus::Pending)
    return result;
  return remember_failure(result);
}

CheckResult NativeCollector::certify_parked_wfi_terminal(const ProbeIdentity &owner, uint64_t pc,
                                                         uint64_t source_cycle) {
  if (!failure_)
    return failure_;
  if (!captured_cycle_ || !closed_cycle_ || *captured_cycle_ != *closed_cycle_ ||
      source_cycle != *captured_cycle_ || !queues_empty_ || !cache_idle_ ||
      !staged_events_.empty() || !staged_retirements_.empty() || !unresolved_samples_.empty() ||
      !faulting_refills_.empty() || !fault_rollback_cancellations_.empty() ||
      !pending_csr_.empty() || !pending_counter_writes_.empty() || !pending_counter_reads_.empty() || !pending_fp_.empty() || pending_system_ || pending_trap_ ||
      pending_fault_rollback_ || !staged_traps_.empty() ||
      !skipped_device_stores_.empty() || adapter_.live_instructions())
    return incomplete("BOOM terminal WFI cannot close while source, cache or older instructions remain live");
  if (!owner.uid || owner.epoch != configuration_.epoch ||
      std::find(configuration_.terminal_wfi_pcs.begin(), configuration_.terminal_wfi_pcs.end(), pc) ==
          configuration_.terminal_wfi_pcs.end())
    return invalid("BOOM terminal WFI certificate is not an expected ELF owner and PC");
  if (certified_terminal_wfi_) {
    if (!same_terminal_owner(certified_terminal_wfi_->owner, owner) || certified_terminal_wfi_->pc != pc ||
        !terminal_wfis_.empty() || !allocations_.empty())
      return invalid("BOOM certified terminal WFI changed identity or regained a live instruction");
    return {};
  }
  const auto it = terminal_wfis_.find(id(owner));
  if (terminal_wfis_.size() != 1 || allocations_.size() != 1 || it == terminal_wfis_.end())
    return incomplete("BOOM physically parked WFI is not the only live instruction");
  const auto &held = it->second;
  const auto &allocation = held.allocation;
  if (!same_terminal_owner(held.identity, owner) || allocation.rob.generation != owner.rob_generation ||
      allocation.pc != pc ||
      allocation.instruction != 0x10500073 || allocation.ldq || allocation.stq)
    return invalid("BOOM parked WFI does not match its held ELF/ROB identity");
  allocations_.erase(it->first);
  terminal_wfis_.erase(it);
  certified_terminal_wfi_ = CertifiedTerminalWfi{owner, pc};
  return {};
}

CheckResult NativeCollector::completion() const {
  if (!failure_)
    return failure_;
  if (!captured_cycle_ || !closed_cycle_ || *closed_cycle_ != *captured_cycle_ ||
      !staged_events_.empty() || !staged_retirements_.empty() || !unresolved_samples_.empty() ||
      !faulting_refills_.empty() || !fault_rollback_cancellations_.empty() ||
      !allocations_.empty() || !pending_csr_.empty() || !pending_counter_writes_.empty() || !pending_counter_reads_.empty() ||
      !pending_fp_.empty() || pending_system_ || pending_trap_ ||
      pending_fault_rollback_ || !staged_traps_.empty() || !queues_empty_ || !cache_idle_)
    return incomplete("BOOM source, instruction or cache observations have not drained");
  return adapter_.completion();
}

} // namespace boom
} // namespace rvwmo
