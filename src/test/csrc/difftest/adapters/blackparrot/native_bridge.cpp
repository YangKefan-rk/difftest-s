#include "native_bridge.h"
#include "cache_geometry.h"
#include "load_order.h"
#include "../../rvwmo/producer_ids.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace blackparrot {
namespace {
constexpr size_t kMaximumInstructions = 65536;
constexpr size_t kMaximumObservations = 1048576;
constexpr size_t kMaximumOnlinePrefixEvents = 32768;
constexpr uint32_t kKnownMemoryFlags = 0x3f;
constexpr uint32_t kInternalMemoryFlag = 1u << 2;
using DrainKey = std::tuple<rvwmo::OperationId, uint32_t, uint64_t, uint64_t>;

DrainKey drain_key(const rvwmo::OperationId &id, uint32_t attempt, uint64_t time, uint64_t address) {
  return {id, attempt, time, address};
}

struct Attempt {
  uint64_t allocated_at = 0;
  bool cancelled = false;
  bool squashed = false;
  uint64_t cancelled_at = 0;
  uint64_t drained_at = 0;
  uint32_t memory_flags = 0;
  bool observed_store_drain = false;
  bool drained = false;
  std::optional<NativeMemoryFact> accepted_store;
  std::optional<NativeMemoryFact> store;
  std::optional<NativeMemoryFact> sample;
  std::array<std::optional<rvwmo::OperationId>, 8> forwarding_candidates;
  std::array<bool, 8> forwarding_seen{};
};

struct Instruction {
  rvwmo::InstructionAllocateEvent allocation;
  uint32_t expanded_instruction = 0;
  uint64_t allocated_at = 0;
  uint32_t latest_attempt = 0;
  std::map<uint32_t, Attempt> attempts;
  std::optional<NativeRetirementFact> retirement;
  bool trapped = false;
  bool staged = false;
  bool allocation_staged = false;
  uint64_t last_fact_time = 0;
  std::optional<LoadOrderCertificate> load_order;
};

struct Hart {
  bool initialized = false;
  bool reset_pending = false;
  std::optional<uint64_t> epoch;
  uint64_t last_uid = 0;
  uint64_t heartbeat_time = 0;
  uint64_t latest_core_time = 0;
  uint32_t pending_retirements = 0;
  bool memory_idle = false;
  uint64_t memory_idle_time = 0;
  uint64_t terminal_uid = 0;
  bool terminal_stopped = false;
  uint64_t terminal_time = 0;
  uint64_t latest_memory_time = 0;
  uint32_t pending_writebacks = 0;
  std::optional<uint64_t> closed_at;
  std::optional<rvwmo::OperationId> retired_wfi;
  uint64_t retirements = 0;
  uint64_t load_samples = 0;
  uint64_t coherent_stores = 0;
};

struct PlannedObservation {
  uint32_t hart = 0;
  uint64_t time = 0;
  uint32_t producer = 0;
  bool stops_hart = false;
  std::function<ConversionResult(Adapter &, const Origin &)> convert;
};

std::vector<uint8_t> bytes(uint64_t value) {
  std::vector<uint8_t> lanes(8);
  for (size_t lane = 0; lane < lanes.size(); ++lane)
    lanes[lane] = static_cast<uint8_t>(value >> (8 * lane));
  return lanes;
}

struct ScalarSpan {
  unsigned first = 0;
  unsigned size = 0;
};

ScalarSpan scalar_span(uint32_t mask) {
  ScalarSpan span;
  while (span.first < 8 && !(mask & (1u << span.first)))
    ++span.first;
  while (span.first + span.size < 8 && (mask & (1u << (span.first + span.size))))
    ++span.size;
  if (!span.size || mask != (((1u << span.size) - 1) << span.first))
    throw std::runtime_error("ordinary scalar byte mask is not contiguous");
  return span;
}

std::vector<uint8_t> span_bytes(uint64_t aligned_data, ScalarSpan span) {
  std::vector<uint8_t> result(span.size);
  for (unsigned byte = 0; byte < span.size; ++byte)
    result[byte] = static_cast<uint8_t>(aligned_data >> (8 * (span.first + byte)));
  return result;
}

std::vector<uint8_t> architectural_load_bytes(uint64_t writeback, uint32_t mask) {
  const auto span = scalar_span(mask);
  // Architectural integer loads place the addressed bytes in the low bits,
  // regardless of their SRAM word lanes. Sign extension is checked by REF.
  return span_bytes(writeback, {0, span.size});
}

bool is_load(uint32_t instruction) { return (instruction & 0x7f) == 0x03; }
bool is_store(uint32_t instruction) { return (instruction & 0x7f) == 0x23; }
bool is_atomic(uint32_t instruction) { return (instruction & 0x7f) == 0x2f; }
bool is_cbo(uint32_t instruction) { return (instruction & 0x707f) == 0x200f; }

class Bridge {
public:
  Configuration configuration;
  NativeSink sink;
  NativeVerifier verifier;
  NativePrefixConsumer prefix_consumer;
  std::unique_ptr<Adapter> online_adapter;
  rvwmo::CheckResult online_result;
  std::optional<uint64_t> delivery_barrier;
  std::optional<uint64_t> online_closed;
  std::map<uint32_t, uint64_t> online_sequences;
  std::map<uint64_t, std::vector<PlannedObservation>> online_observations;
  ConvertedOutput online_batch;
  LoadOrderValidator load_orders;
  NativeFailureObserver failure_observer;
  bool notifying_failure = false;
  NativeCapture capture;
  bool finished = false;
  bool failed = false;
  bool online_failure_reported = false;
  uint32_t hart_count = 0;
  std::optional<uint64_t> completed_cycle;
  size_t observations = 0;
  std::map<uint32_t, Hart> harts;
  std::map<rvwmo::OperationId, Instruction> instructions;
  std::map<DrainKey, size_t> physical_drain_counts;
  std::map<DrainKey, size_t> coherent_drain_indices;
  std::map<DrainKey, size_t> coherent_admission_indices;
  std::map<std::tuple<rvwmo::OperationId, uint32_t, uint32_t>, size_t> forwarding_fact_indices;

  void reject_transport(const char *message) {
    const bool first_failure = !failed;
    failed = true;
    capture.summary.malformed_transport = true;
    capture.summary.incomplete = true;
    const rvwmo::CheckResult failure{rvwmo::CheckStatus::Invalid, 0, message};
    if (online_adapter) {
      remember_online_failure(failure);
      capture.summary.verification = NativeVerification{online_result, false};
      return;
    }
    if (capture.summary.verification && capture.summary.verification->check.status == rvwmo::CheckStatus::Pass)
      capture.summary.verification = NativeVerification{failure, false};
    if (!first_failure || !failure_observer)
      return;
    notifying_failure = true;
    try {
      failure_observer(failure);
    } catch (...) {
      std::cerr << "[Difftest-S] native failure observer threw; transport remains rejected\n";
    }
    notifying_failure = false;
  }

  void require(bool condition, const char *message) const {
    if (!condition)
      throw std::runtime_error(message);
  }

  void gap(const std::string &message) {
    auto &gaps = capture.summary.gaps;
    if (std::find(gaps.begin(), gaps.end(), message) == gaps.end() && gaps.size() < 64)
      gaps.push_back(message);
  }

  template <typename... Fields> void record(const char *kind, const Fields &...fields) {
    require(online_adapter || observations < kMaximumObservations, "native observation buffer limit reached");
    require(observations != std::numeric_limits<size_t>::max(), "native observation counter exhausted");
    ++observations;
    auto *output = trace_stream();
    if (!output)
      return;
    *output << kind;
    ((*output << '\t' << fields), ...);
    *output << '\n';
    flush_trace();
  }

  void trace(const std::string &record) {
    auto *output = trace_stream();
    if (!output)
      return;
    *output << record << '\n';
    flush_trace();
  }

  Hart &hart(uint32_t id) {
    auto found = harts.find(id);
    require(found != harts.end() && found->second.initialized, "observation names an uninitialized hart");
    return found->second;
  }

  Instruction &instruction(const rvwmo::OperationId &id) {
    hart(id.hart);
    require(id.uid != 0 && id.epoch != 0, "instruction epoch/UID must be nonzero");
    auto found = instructions.find(id);
    require(found != instructions.end(), "observation has no matching native allocation");
    return found->second;
  }

  Attempt &attempt(const rvwmo::OperationId &id, uint32_t number, uint64_t time) {
    auto &live = instruction(id);
    auto found = live.attempts.find(number);
    require(found != live.attempts.end(), "observation names an unallocated execution attempt");
    require(time >= found->second.allocated_at, "observation source time predates its execution attempt");
    return found->second;
  }

  void initialize(uint32_t id, uint32_t count) {
    require(count != 0 && count <= 1024 && id < count, "invalid native hart roster");
    require(!hart_count || hart_count == count, "native hart count changed within a session");
    hart_count = count;
    if (configuration.harts.empty()) {
      for (uint32_t index = 0; index < count; ++index) {
        const auto producer = rvwmo::hart_producer_id(index);
        configuration.harts.push_back({index, producer, producer, producer});
      }
      for (uint32_t index = 0; index < count; ++index)
        configuration.publication_producers.push_back(rvwmo::memory_fabric_producer_id(index));
    }
    require(configuration.harts.size() == count, "installed sink roster differs from native hart count");
    require(std::any_of(configuration.harts.begin(), configuration.harts.end(),
                        [id](const HartChannels &channels) { return channels.hart == id; }),
            "native hart is absent from installed sink configuration");
    auto &state = harts[id];
    if (state.initialized) {
      state.reset_pending = state.last_uid != 0;
      if (state.reset_pending) {
        gap("native reset requires a fresh coordinator semantic session");
      } else {
        state.epoch.reset();
      }
    }
    state.initialized = true;
    record("INIT", id, count);
  }

  void allocate(const rvwmo::OperationId &id, uint32_t number, uint64_t time, uint64_t pc,
                uint32_t raw, uint32_t length, uint32_t expanded) {
    auto &state = hart(id.hart);
    require(!state.closed_at && !completed_cycle, "allocation delivered after the native hart was sealed");
    state.latest_core_time = std::max(state.latest_core_time, time);
    record("ALLOCATE", id.hart, id.epoch, id.uid, number, time, pc, raw, length, expanded);
    require(id.uid && id.epoch && number, "allocation epoch/UID/attempt must be nonzero");
    require((pc & 1) == 0, "native allocation PC is not halfword aligned");
    require(length == 0 || length == 2 || length == 4, "invalid native instruction length");
    if (length) {
      require(((raw & 3) != 3) == (length == 2), "raw instruction length differs from encoding");
      require(length != 2 || (raw >> 16) == 0, "compressed instruction contains upper bits");
    }
    auto existing = instructions.find(id);
    if (existing != instructions.end()) {
      auto &live = existing->second;
      require(!live.retirement && !live.trapped, "retry allocated after retirement or trap");
      require(number == live.latest_attempt + 1 && live.latest_attempt != std::numeric_limits<uint32_t>::max(),
              "duplicate or nonconsecutive execution attempt");
      require(live.attempts.at(live.latest_attempt).cancelled, "retry has no cancellation of its previous attempt");
      require(!live.attempts.at(live.latest_attempt).squashed, "whole-instruction squash cannot reuse its old UID");
      require(live.allocation.pc == pc && live.allocation.instruction == raw && live.allocation.length == length &&
                  live.expanded_instruction == expanded,
              "retry changed its stable raw instruction identity");
      require(time >= live.attempts.at(live.latest_attempt).cancelled_at, "retry source time predates cancellation");
      require(!online_closed || time > *online_closed, "retry allocation arrived inside a closed online prefix");
      live.latest_attempt = number;
      live.attempts.emplace(number, Attempt{}).first->second.allocated_at = time;
      ++capture.summary.retries;
    } else {
      require(instructions.size() < kMaximumInstructions, "native instruction buffer limit reached");
      require(!online_closed || time > *online_closed, "allocation arrived inside a closed online prefix");
      require(number == 1, "first allocation must use attempt one");
      if (state.epoch && *state.epoch != id.epoch) {
        require(state.reset_pending && id.epoch > *state.epoch, "epoch changed without a native reset boundary");
        state.last_uid = 0;
      }
      require(!state.epoch || id.epoch >= *state.epoch, "allocation uses a stale epoch");
      require(id.uid > state.last_uid, "new allocation UID is not strictly increasing within its epoch");
      state.epoch = id.epoch;
      state.reset_pending = false;
      state.last_uid = id.uid;
      Instruction live;
      live.allocation = {id, pc, raw, static_cast<uint8_t>(length)};
      live.expanded_instruction = expanded;
      live.allocated_at = time;
      live.last_fact_time = time;
      live.latest_attempt = number;
      live.attempts.emplace(number, Attempt{}).first->second.allocated_at = time;
      if (online_adapter) {
        const auto allocation = live.allocation;
        const auto producer = channels(id.hart).instruction;
        online_observations[time].push_back({id.hart, time, producer, false,
            [allocation](Adapter &target, const Origin &origin) { return target.allocate(origin, allocation); }});
        live.allocation_staged = true;
      }
      instructions.emplace(id, std::move(live));
      capture.summary.live_instructions = instructions.size();
      capture.summary.peak_live_instructions = std::max(capture.summary.peak_live_instructions, instructions.size());
      ++capture.summary.allocations;
    }
    if (!length)
      gap("faulting dispatch has no complete raw instruction encoding");
  }

  void retire(const NativeRetirementFact &fact) {
    auto &source = hart(fact.id.hart);
    require(!source.closed_at && !completed_cycle, "retirement delivered after the native hart was sealed");
    source.latest_core_time = std::max(source.latest_core_time, fact.source_time);
    auto &live = instruction(fact.id);
    auto &execution = attempt(fact.id, fact.attempt, fact.source_time);
    require(!execution.cancelled && !live.retirement && !live.trapped, "duplicate, cancelled or trapped retirement");
    require(fact.attempt == live.latest_attempt, "retirement selected a stale execution attempt");
    require(fact.pc == live.allocation.pc && fact.instruction == live.allocation.instruction &&
                fact.instruction_bytes == live.allocation.length,
            "retirement differs from its stable dispatch identity");
    require(fact.rd < 32 && (!fact.write_enable || fact.rd != 0), "invalid architectural writeback destination");
    live.retirement = fact;
    live.last_fact_time = std::max(live.last_fact_time, fact.source_time);
    source.retired_wfi = live.expanded_instruction == 0x10500073
        ? std::optional<rvwmo::OperationId>{fact.id} : std::nullopt;
    ++source.retirements;
    capture.retirement_facts.push_back(fact);
    ++capture.summary.retirements;
    if (fact.fp)
      gap("FP retirement is outside the scalar consumer profile");
    record("RETIRE", fact.id.hart, fact.id.epoch, fact.id.uid, fact.attempt, fact.source_time, fact.pc,
           fact.instruction, fact.instruction_bytes, fact.rd, fact.write_enable, fact.fp, fact.write_data);
  }

  void cancel(const rvwmo::OperationId &id, uint32_t number, uint64_t time, uint32_t reason) {
    auto &source = hart(id.hart);
    require(!source.closed_at && !completed_cycle, "cancellation delivered after the native hart was sealed");
    source.latest_core_time = std::max(source.latest_core_time, time);
    auto &live = instruction(id);
    auto &execution = attempt(id, number, time);
    live.last_fact_time = std::max(live.last_fact_time, time);
    require(reason == 1 || reason == 2, "unknown native cancellation reason");
    require(!online_closed || time > *online_closed, "cancellation arrived inside a closed online prefix");
    require(!live.retirement, "cancellation names an architecturally retired instruction");
    require(!execution.accepted_store && !execution.store, "accepted ordinary store cannot be cancelled");
    if (reason == 1)
      require(!execution.cancelled, "duplicate execution-attempt cancellation");
    else
      require(!execution.squashed, "duplicate whole-instruction squash");
    if (!execution.cancelled)
      execution.cancelled_at = time;
    execution.cancelled = true;
    execution.squashed = reason == 2;
    ++capture.summary.cancellations;
    capture.cancellation_facts.push_back({id, number, time, reason});
    record("CANCEL", id.hart, id.epoch, id.uid, number, time, reason);
  }

  static bool forwards_byte(const Attempt &execution, const NativeMemoryFact &sample, size_t lane) {
    if (!execution.store || execution.store->address != sample.address ||
        !(execution.store->mask & (1u << lane)))
      return false;
    // Bypass registers observe the pre-edge queue. The same edge may drain
    // this entry, so equality remains a valid physical forwarding source.
    return execution.store->source_time <= sample.forwarding_time &&
           (!execution.cancelled || execution.cancelled_at > sample.forwarding_time) &&
           (!execution.drained || execution.drained_at >= sample.forwarding_time);
  }

  void validate_forwarded_byte(const NativeMemoryFact &sample, size_t lane,
                              const rvwmo::OperationId &writer, const Attempt &execution) const {
    const unsigned shift = 8 * lane;
    require(static_cast<uint8_t>(execution.store->aligned_data >> shift) ==
                static_cast<uint8_t>(sample.aligned_data >> shift),
            "forwarded byte differs from its observed store-buffer writer data");
    // This fixed WBUF retains individual stores in FIFO order. Its bypass
    // selects current input, then el0, then el1: the youngest active older
    // same-hart store covering each byte. This audits a physical source tag;
    // it neither supplies REF bytes nor establishes a cross-hart memory rank.
    for (auto newer = instructions.upper_bound(writer);
         newer != instructions.end() && newer->first < sample.id; ++newer)
      for (const auto &attempt_entry : newer->second.attempts)
        require(!forwards_byte(attempt_entry.second, sample, lane),
                "forwarded byte skips a younger active store-buffer writer");
  }

  void validate_forwarded_sample(const NativeMemoryFact &sample) {
    // Only a closed raw source interval can prove that no later callback adds
    // an older physical store input. Recheck the final sample before conversion.
    for (size_t lane = 0; lane < sample.forwarded_writers.size(); ++lane) {
      const auto &writer_id = sample.forwarded_writers[lane];
      if (!writer_id)
        continue;
      const auto &writer = instruction(*writer_id);
      size_t eligible = 0;
      for (const auto &writer_attempt : writer.attempts)
        if (forwards_byte(writer_attempt.second, sample, lane)) {
          ++eligible;
          validate_forwarded_byte(sample, lane, *writer_id, writer_attempt.second);
        }
      if (eligible != 1)
        gap("forwarded byte lacks a unique writer attempt in the closed source interval");
    }
  }

  void memory(NativeMemoryFact fact) {
    hart(fact.id.hart);
    require(!completed_cycle, "memory observation delivered after the terminal source prefix");
    auto &source = hart(fact.id.hart);
    source.latest_memory_time = std::max(source.latest_memory_time, fact.source_time);
    require(fact.kind >= 1 && fact.kind <= 4, "unknown native memory observation kind");
    require(fact.mask && !(fact.mask & ~0xffu) && !(fact.address & 7), "invalid aligned memory byte mask/address");
    require(!(fact.flags & ~kKnownMemoryFlags), "unknown native memory flags");
    require(!(fact.forwarded_mask & ~fact.mask), "forwarded byte mask exceeds enabled memory bytes");
    require(fact.kind == 3 || !fact.forwarded_mask, "non-load memory record contains forwarding bytes");
    require(fact.array_time <= fact.source_time && fact.forwarding_time <= fact.source_time,
            "memory sampling time is later than its source observation");
    const bool internal = (fact.flags & kInternalMemoryFlag) != 0;
    if (!internal) {
      auto &live = instruction(fact.id);
      live.last_fact_time = std::max(live.last_fact_time, fact.source_time);
      auto &execution = attempt(fact.id, fact.attempt, fact.source_time);
      require(!execution.cancelled, "memory observation belongs to a cancelled execution attempt");
      execution.memory_flags |= fact.flags;
      execution.observed_store_drain |= fact.kind == 2;
      if (fact.kind == 4) {
        require(is_store(live.expanded_instruction) && !(fact.flags & ~uint32_t{8}),
                "accepted miss payload is not an ordinary cached store");
        require(!execution.accepted_store && !execution.store,
                "duplicate or late accepted store-miss payload");
        execution.accepted_store = fact;
      } else if (fact.kind == 1) {
        require(!execution.store, "duplicate store-buffer input for one execution attempt");
        if (execution.accepted_store) {
          const auto &accepted = *execution.accepted_store;
          require(accepted.source_time < fact.source_time && accepted.address == fact.address &&
                      accepted.mask == fact.mask, "replayed store differs from its accepted miss payload");
          for (size_t lane = 0; lane < 8; ++lane)
            require(!(fact.mask & (1u << lane)) ||
                        uint8_t(accepted.aligned_data >> (8 * lane)) == uint8_t(fact.aligned_data >> (8 * lane)),
                    "replayed store bytes differ from its accepted miss payload");
        }
        execution.store = fact;
      } else if (fact.kind == 2) {
        require(execution.store.has_value(), "physical store drain has no prior store-buffer input");
        const auto &store = *execution.store;
        require(!execution.drained, "duplicate physical store drain for one store-buffer input");
        require(fact.source_time >= store.source_time && fact.address == store.address && fact.mask == store.mask,
                "physical store drain differs from its prior store-buffer input identity/address/mask");
        const auto input_bytes = bytes(store.aligned_data);
        const auto drain_bytes = bytes(fact.aligned_data);
        for (size_t lane = 0; lane < 8; ++lane)
          require(!(fact.mask & (1u << lane)) || input_bytes[lane] == drain_bytes[lane],
                  "physical store drain data differs from its store-buffer input");
        execution.drained = true;
        execution.drained_at = fact.source_time;
        ++physical_drain_counts[drain_key(fact.id, fact.attempt, fact.source_time, fact.address)];
      } else if (fact.kind == 3) {
        require(!execution.sample, "duplicate successful load sample");
        for (size_t lane = 0; lane < 8; ++lane) {
          const bool forwarded = (fact.forwarded_mask >> lane) & 1;
          require(forwarded || !execution.forwarding_seen[lane], "writer identity supplied for a nonforwarded byte");
          if (forwarded) {
            require(execution.forwarding_seen[lane], "forwarded byte lacks its source writer callback");
            const auto forward_index = forwarding_fact_indices.find({fact.id, fact.attempt, lane});
            require(forward_index != forwarding_fact_indices.end(), "forwarded writer callback was not retained");
            auto &forward = capture.forwarding_facts[forward_index->second];
            forward.source_time = fact.forwarding_time;
            if (!execution.forwarding_candidates[lane]) {
              fact.forwarded_writers[lane].reset();
              gap("forwarded byte has no observed logical writer identity");
              continue;
            }
            const auto candidate = *execution.forwarding_candidates[lane];
            fact.forwarded_writers[lane] = candidate;
            auto &writer = instruction(candidate);
            std::vector<uint32_t> eligible_attempts;
            bool observed_writer_byte = false;
            for (const auto &writer_attempt : writer.attempts) {
              const auto &attempt_state = writer_attempt.second;
              if (!attempt_state.store || attempt_state.store->address != fact.address ||
                  !((attempt_state.store->mask >> lane) & 1))
                continue;
              observed_writer_byte = true;
              if (forwards_byte(attempt_state, fact, lane))
                eligible_attempts.push_back(writer_attempt.first);
            }
            require(observed_writer_byte, "forwarded writer does not own the captured address/byte lane");
            if (eligible_attempts.size() == 1) {
              forward.resolved_writer_attempt = eligible_attempts.front();
            } else {
              fact.forwarded_writers[lane].reset();
              gap(eligible_attempts.empty()
                      ? "forwarded writer has no active store-buffer input at the observed source time"
                      : "forwarded writer attempt is ambiguous at the observed source time");
            }
          }
        }
        const auto sample_time = fact.forwarded_mask ? fact.forwarding_time : fact.array_time;
        require(!sample_time || sample_time >= execution.allocated_at, "load byte sample predates dispatch attempt");
        execution.sample = fact;
        ++source.load_samples;
      }
    } else {
      gap("PTW/internal memory facts are diagnostic and have no fake instruction allocation");
    }

    if (fact.flags & 1)
      gap("atomic/LRSC memory requires a complete supported atomic lifecycle");
    if (fact.flags & 2)
      gap("uncached/MMIO memory is outside the scalar coherent-memory consumer profile");
    if (fact.flags & (1u << 4))
      gap("FP memory is outside the scalar consumer profile");
    if (fact.flags & (1u << 5))
      gap("cache/block operations are outside the scalar consumer profile");
    if (fact.kind == 3 && fact.forwarded_mask && fact.forwarded_mask != fact.mask &&
        fact.array_time != fact.forwarding_time)
      gap("load bytes mix distinct SRAM and forwarding sample times");
    capture.memory_facts.push_back(fact);
    ++capture.summary.memory_records;
    record("MEMORY", fact.id.hart, fact.id.epoch, fact.id.uid, fact.attempt, fact.source_time, fact.kind,
           fact.address, fact.aligned_data, fact.mask, fact.array_time, fact.forwarding_time,
           fact.forwarded_mask, fact.flags);
  }

  void forward(const rvwmo::OperationId &id, uint32_t number, uint32_t lane,
               const rvwmo::OperationId &writer) {
    auto &live = instruction(id);
    auto found = live.attempts.find(number);
    require(found != live.attempts.end() && !found->second.cancelled, "forwarding uses an unavailable load attempt");
    auto &execution = found->second;
    require(lane < 8 && !execution.sample && !execution.forwarding_seen[lane], "duplicate/late/invalid forwarding byte");
    execution.forwarding_seen[lane] = true;
    capture.forwarding_facts.push_back({id, number, lane, writer});
    forwarding_fact_indices.emplace(std::make_tuple(id, number, lane), capture.forwarding_facts.size() - 1);
    if (!writer.uid) {
      gap("forwarded byte has no observed logical writer identity");
      record("FORWARD_UNKNOWN", id.hart, id.epoch, id.uid, number, lane, writer.epoch);
      return;
    }
    require(writer.epoch == id.epoch && writer.uid < id.uid,
            "forwarded writer is not a valid older same-hart instruction");
    instruction(writer);
    execution.forwarding_candidates[lane] = writer;
    record("FORWARD", id.hart, id.epoch, id.uid, number, lane, writer.epoch, writer.uid);
  }

  void trap(const NativeTrapFact &fact) {
    auto &source = hart(fact.id.hart);
    require(!source.closed_at && !completed_cycle, "trap delivered after the native hart was sealed");
    source.latest_core_time = std::max(source.latest_core_time, fact.source_time);
    require(fact.id.epoch && fact.privilege <= 3 && fact.target_privilege <= 3,
            "invalid native trap epoch/privilege");
    if (fact.id.uid) {
      auto &live = instruction(fact.id);
      auto &execution = attempt(fact.id, fact.attempt, fact.source_time);
      require(!execution.cancelled && fact.attempt == live.latest_attempt,
              "trap references a stale or cancelled instruction attempt");
      require(!live.trapped && !live.retirement, "duplicate trap or trap of a retired instruction");
      live.trapped = true;
    } else {
      require(fact.interrupt, "synchronous trap lacks a dynamic instruction identity");
      gap("UID-zero interrupt is a control boundary, not an allocated instruction");
    }
    capture.trap_facts.push_back(fact);
    ++capture.summary.traps;
    gap("trap/interrupt semantic consumption requires coordinator support");
    record("TRAP", fact.id.hart, fact.id.epoch, fact.id.uid, fact.attempt, fact.source_time, fact.pc,
           fact.cause, fact.interrupt, fact.tval, fact.target_pc, fact.privilege, fact.target_privilege);
  }

  void coherent_store(const NativeCoherenceFact &fact) {
    hart(fact.id.hart);
    require(!completed_cycle, "coherence observation delivered after the terminal source prefix");
    auto &source = hart(fact.id.hart);
    source.latest_memory_time = std::max(source.latest_memory_time, fact.source_time);
    require(!(fact.address & 7) && !(fact.proof_flags & ~0x1fu) && (fact.source_time & 1) &&
                fact.cache_set < cache_geometry::kSetCount && fact.cache_way < cache_geometry::kWayCount,
            "coherent store record has an invalid source position, address or proof shape");
    if (fact.proof_flags == 0x1f) {
      require(fact.id.epoch && fact.id.uid && fact.attempt &&
                  (fact.coherence_state == 2 || fact.coherence_state == 6) && fact.grant_time &&
                  fact.grant_time < fact.source_time,
              "coherent store proof lacks the fixed four-hart ownership evidence");
      require(cache_geometry::is_one_hot_bank(fact.bank_select) &&
                  fact.physical_sram_index < cache_geometry::kPhysicalEntryCount,
              "coherent store proof lacks a one-hot SRAM location");
      const uint32_t physical_set = cache_geometry::set_for_physical_index(fact.physical_sram_index);
      const uint32_t expected_set = cache_geometry::set_for_address(fact.address);
      const uint32_t expected_way = cache_geometry::way_for_location(fact.bank_select,
                                                                     fact.physical_sram_index);
      require(physical_set == expected_set && fact.cache_set == expected_set &&
                  fact.cache_way == expected_way,
              "coherence proof set/way differs from the observed PA and physical SRAM write location");
    } else {
      require(!(fact.proof_flags & 1u), "ordinary coherent drain has incomplete ownership/write evidence");
      gap("coherence monitor retained a drain outside the ordinary scalar proof");
    }
    require(hart_count == 4, "coherent publication proof requires the audited four-hart profile");
    if (online_adapter)
      instruction(fact.id).last_fact_time = std::max(instruction(fact.id).last_fact_time, fact.source_time);
    if (fact.proof_flags == 0x1f && !fact.admission)
      ++source.coherent_stores;
    const auto key = drain_key(fact.id, fact.attempt, fact.source_time, fact.address);
    auto &indices = fact.admission ? coherent_admission_indices : coherent_drain_indices;
    require(!indices.count(key), "duplicate coherent store proof");
    // The two source monitors run in separate SV processes. Match their facts
    // after delivery, without assuming which DPI callback arrives first.
    capture.coherence_facts.push_back(fact);
    indices.emplace(key, capture.coherence_facts.size() - 1);
    record(fact.admission ? "COHERENT_ACCEPT" : "COHERENT_DRAIN", fact.id.hart, fact.id.epoch, fact.id.uid, fact.attempt,
           fact.source_time, fact.address, fact.cache_set, fact.cache_way,
           fact.coherence_state, fact.grant_time, fact.proof_flags, fact.bank_select,
           fact.physical_sram_index);
  }

  bool can_end() const {
    if (!hart_count || harts.size() != hart_count || failed || completed_cycle)
      return false;
    for (const auto &entry : harts) {
      const auto &source = entry.second;
      if (!source.initialized || !source.terminal_stopped || !source.terminal_uid ||
          source.pending_retirements || source.pending_writebacks || !source.memory_idle)
        return false;
    }
    return true;
  }

  void terminal_state(uint32_t id, uint64_t time, uint64_t uid, bool stopped, uint32_t pending) {
    auto &source = hart(id);
    require(!source.closed_at && !completed_cycle, "terminal state delivered after the native hart was sealed");
    require(!(time & 1) && time >= source.terminal_time && time >= source.heartbeat_time &&
                time >= source.latest_core_time,
            "terminal source time predates its last core observation or is not a core edge");
    source.latest_core_time = time;
    source.terminal_time = time;
    source.terminal_uid = uid;
    source.terminal_stopped = stopped;
    source.pending_writebacks = pending;
    if (stopped) {
      require(source.epoch.has_value() && uid, "terminal stop has no native epoch or UID");
      require(source.retired_wfi && *source.retired_wfi == rvwmo::OperationId{id, *source.epoch, uid, 0},
              "terminal stop has no matching retired WFI");
    }
    record("TERMINAL_STATE", id, time, uid, stopped, pending);
  }

  void close_hart(uint32_t id, uint64_t time, uint64_t uid) {
    auto &source = hart(id);
    require(source.terminal_stopped && source.terminal_uid == uid && !source.closed_at &&
                !source.pending_retirements && !source.pending_writebacks && source.memory_idle,
            "native hart closure lacks a stopped, drained terminal WFI");
    require(!(time & 1) && time >= source.terminal_time && time >= source.heartbeat_time &&
                time >= source.latest_core_time && time > source.latest_memory_time && time > source.memory_idle_time,
            "native hart closure predates its stopped core or memory source evidence");
    for (const auto &entry : instructions) {
      if (entry.first.hart != id)
        continue;
      const auto &live = entry.second;
      require(live.retirement || live.trapped || live.attempts.at(live.latest_attempt).squashed,
              "native hart closure retains an unsquashed instruction allocation");
    }
    source.closed_at = time;
    capture.completion.harts.push_back({id, time, uid});
    record("CLOSE_HART", id, time, uid);
  }

  void close_prefix(uint64_t time) {
    require(!completed_cycle && !(time & 1) && hart_count && harts.size() == hart_count,
            "native prefix closure is duplicate or has an incomplete hart roster");
    for (const auto &entry : harts) {
      const auto &source = entry.second;
      require(source.closed_at && *source.closed_at < time && source.memory_idle &&
                  source.memory_idle_time > *source.closed_at && source.memory_idle_time < time &&
                  source.terminal_time <= *source.closed_at && source.heartbeat_time <= *source.closed_at &&
                  source.latest_memory_time <= source.memory_idle_time,
              "native prefix closure lacks the final stopped memory-source edge");
    }
    completed_cycle = time;
    record("CLOSE_PREFIX", time);
  }

  void advance(uint64_t delivered_through) {
    require(online_adapter != nullptr, "online source progress has no installed online session");
    require(!delivery_barrier || delivered_through >= *delivery_barrier,
            "online delivery barrier regressed");
    delivery_barrier = delivered_through;
    if (!online_result || harts.size() != configuration.harts.size())
      return;
    pump_online(delivered_through);
  }

  void finish() {
    if (finished)
      return;
    finished = true;
    if (!failed && hart_count) {
      if (online_adapter)
        finish_online();
      else
        convert();
    }
    if (!hart_count)
      gap("no native producer initialized");
    for (const auto &entry : harts) {
      if (entry.second.pending_retirements)
        gap("native finish retains pending retirement/writeback records");
      if (!entry.second.memory_idle)
        gap("native finish has no observed physical memory-idle diagnostic for every hart");
    }
    capture.completion.completed_cycle = completed_cycle;
    capture.completion.all_harts_completed = completed_cycle.has_value();
    capture.completion.observations_drained = completed_cycle.has_value();
    capture.completion.memory_drained = completed_cycle.has_value();
    if (!completed_cycle)
      gap("no terminal source-prefix closure or complete memory drain was observed");
    capture.summary.sink_installed = static_cast<bool>(sink) || static_cast<bool>(verifier);
    capture.summary.malformed_transport = failed;
    if (!online_adapter)
      capture.summary.converted_events = capture.converted.batch.events.size();
    if (!sink && !verifier)
      gap("no coordinator semantic sink installed");
    if (sink && !failed) {
      const auto result = sink(capture);
      require(static_cast<bool>(result), ("native sink rejected capture: " + result.message).c_str());
    }
    capture.summary.incomplete = failed || !completed_cycle || !capture.summary.gaps.empty();
    const char *verdict = "Incomplete";
    if (online_adapter && !online_result) {
      verdict = online_result.status == rvwmo::CheckStatus::Violation ? "Violation"
                : online_result.status == rvwmo::CheckStatus::Invalid ? "Invalid"
                : online_result.status == rvwmo::CheckStatus::Unsupported ? "Unsupported" : "Incomplete";
      capture.summary.verification = NativeVerification{online_result, false};
    }
    if (verifier && !failed) {
      auto result = online_adapter && !online_result
          ? NativeVerification{online_result, false} : verifier(capture);
      if (result.check.status == rvwmo::CheckStatus::Pass &&
          (!result.finalized || capture.summary.incomplete))
        result.check = {rvwmo::CheckStatus::Incomplete, 0,
                        "native verifier lacks complete capture evidence or a finalized public session"};
      if (result.check.status == rvwmo::CheckStatus::Pending)
        result.check.status = rvwmo::CheckStatus::Incomplete;
      capture.summary.verification = result;
      switch (result.check.status) {
      case rvwmo::CheckStatus::Pass: verdict = "Pass"; break;
      case rvwmo::CheckStatus::Violation: verdict = "Violation"; break;
      case rvwmo::CheckStatus::Unsupported: verdict = "Unsupported"; break;
      case rvwmo::CheckStatus::Invalid: verdict = "Invalid"; break;
      default: verdict = "Incomplete"; break;
      }
      capture.summary.incomplete = result.check.status != rvwmo::CheckStatus::Pass;
      if (!result.check.message.empty())
        std::cout << "[Difftest-S] detail: " << result.check.message << '\n';
    }
    if (!online_failure_reported)
      std::cout << "[Difftest-S] " << verdict << ": captured allocations=" << capture.summary.allocations
              << " retries=" << capture.summary.retries << " retirements=" << capture.summary.retirements
              << " memory=" << capture.summary.memory_records << " traps=" << capture.summary.traps
              << " converted=" << capture.summary.converted_events << " sink="
              << (capture.summary.sink_installed ? "installed" : "absent")
              << " unresolved=" << capture.summary.gaps.size() << '\n';
    for (const auto &message : capture.summary.gaps)
      std::cout << "[Difftest-S] gap: " << message << '\n';
    for (const auto &entry : harts) {
      const uint32_t hart_id = entry.first;
      const auto retired = entry.second.retirements;
      const auto samples = entry.second.load_samples;
      const auto publications = entry.second.coherent_stores;
      std::cout << "[BP-CHECK] hart=" << hart_id << " retirements=" << retired << " load_samples=" << samples
                << " coherent_stores=" << publications << " sealed=" << entry.second.closed_at.has_value() << '\n';
    }
    trace(std::string("FINISH\t") + verdict);
  }

private:
  bool trace_checked_ = false;
  std::ofstream trace_;
  uint64_t publication_transaction_ = 0;

  std::ostream *trace_stream() {
    if (!trace_checked_) {
      trace_checked_ = true;
      const char *path = std::getenv("BP_DIFFTEST_S_TRACE");
      if (path && *path) {
        trace_.open(path);
        require(trace_.is_open(), "cannot open BP_DIFFTEST_S_TRACE");
      }
    }
    return trace_.is_open() ? &trace_ : nullptr;
  }

  void flush_trace() {
    trace_.flush();
    require(static_cast<bool>(trace_), "cannot write BP_DIFFTEST_S_TRACE");
  }

  const HartChannels &channels(uint32_t id) const {
    return *std::find_if(configuration.harts.begin(), configuration.harts.end(),
                         [id](const HartChannels &entry) { return entry.hart == id; });
  }

  bool scalar_sample(const NativeMemoryFact &fact) const {
    if (fact.flags & ~uint32_t{1u << 3})
      return false;
    if (fact.forwarded_mask && fact.forwarded_mask != fact.mask && fact.array_time != fact.forwarding_time)
      return false;
    return fact.forwarded_mask ? fact.forwarding_time != 0 : fact.array_time != 0;
  }

  rvwmo::LoadSampleEvent sample(const NativeMemoryFact &fact) const {
    rvwmo::LoadSampleEvent result;
    result.operation.id = fact.id;
    result.operation.attempt = fact.attempt;
    const auto span = scalar_span(fact.mask);
    result.operation.address = fact.address + span.first;
    result.operation.byte_mask.assign(span.size, 1);
    result.operation.load = true;
    result.operation.source_kind = rvwmo::ReadSourceKind::Unavailable;
    result.actual_bytes = span_bytes(fact.aligned_data, span);
    result.forwarded_writers.assign(fact.forwarded_writers.begin() + span.first,
                                   fact.forwarded_writers.begin() + span.first + span.size);
    return result;
  }

  void remember_online_failure(rvwmo::CheckResult result) {
    if (online_result.status == rvwmo::CheckStatus::Pass || online_result.status == rvwmo::CheckStatus::Pending) {
      online_result = std::move(result);
      const char *verdict = online_result.status == rvwmo::CheckStatus::Violation ? "Violation"
                            : online_result.status == rvwmo::CheckStatus::Invalid ? "Invalid"
                            : online_result.status == rvwmo::CheckStatus::Unsupported ? "Unsupported" : "Incomplete";
      online_failure_reported = true;
      std::cout << "[Difftest-S] " << verdict << ": online prefix rejected: " << online_result.message << '\n';
      std::cout.flush();
      if (failure_observer) {
        notifying_failure = true;
        try {
          failure_observer(online_result);
        } catch (...) {
          std::cerr << "[Difftest-S] online failure observer threw; source remains rejected\n";
        }
        notifying_failure = false;
      }
    }
  }

  bool raw_instruction_complete(const rvwmo::OperationId &id, const Instruction &live) const {
    if (!live.retirement && !live.trapped && !live.attempts.at(live.latest_attempt).squashed)
      return false;
    if (live.retirement && is_load(live.expanded_instruction) &&
        !live.attempts.at(live.retirement->attempt).sample)
      return false;
    if (live.retirement && is_store(live.expanded_instruction) &&
        !live.attempts.at(live.retirement->attempt).store)
      return false;
    for (const auto &entry : live.attempts) {
      const auto &execution = entry.second;
      if (execution.store && (!execution.drained || !coherent_admission_indices.count(
          drain_key(id, entry.first, execution.store->source_time, execution.store->address))))
        return false;
      if (!execution.drained)
        continue;
      const auto key = drain_key(id, entry.first, execution.drained_at, execution.store->address);
      if (!coherent_drain_indices.count(key))
        return false;
    }
    for (const auto &proof : capture.coherence_facts) {
      if (proof.id != id)
        continue;
      if (proof.admission) {
        const auto execution = live.attempts.find(proof.attempt);
        if (execution == live.attempts.end() || !execution->second.store ||
            execution->second.store->source_time != proof.source_time ||
            execution->second.store->address != proof.address)
          return false;
      } else {
        const auto drain = physical_drain_counts.find(drain_key(id, proof.attempt, proof.source_time, proof.address));
        if (drain == physical_drain_counts.end() || drain->second != 1)
          return false;
      }
    }
    return true;
  }

  uint64_t raw_safe_frontier(uint64_t delivered_through) const {
    uint64_t safe = delivered_through;
    // Any delayed result, WB or proof can refer back to this allocation, so
    // closing before the oldest unresolved allocation is conservative across
    // every monitor. A callback barrier alone never closes such an interval.
    for (const auto &entry : instructions) {
      if (raw_instruction_complete(entry.first, entry.second))
        continue;
      const auto &active = entry.second.attempts.at(entry.second.latest_attempt);
      // A cancelled attempt cannot later deliver a sample or retire. Preserve
      // its UID for a possible future retry, without pinning other harts to the
      // abandoned attempt's old allocation forever (e.g. a sleeping WFI hart).
      if (active.cancelled && !active.store)
        continue;
      safe = std::min(safe, active.allocated_at ? active.allocated_at - 1 : 0);
    }
    return safe;
  }

  bool stage_online_instructions(uint64_t raw_safe) {
    std::set<uint32_t> blocked_harts;
    for (auto &entry : instructions) {
      auto &live = entry.second;
      if (live.staged || blocked_harts.count(entry.first.hart))
        continue;
      if (!raw_instruction_complete(entry.first, live) || live.last_fact_time > raw_safe) {
        blocked_harts.insert(entry.first.hart);
        continue;
      }
      if (live.trapped) {
        remember_online_failure({rvwmo::CheckStatus::Unsupported, 0,
                                 "online native trap requires architectural session support"});
        return false;
      }
      if (live.retirement) {
        const auto &execution = live.attempts.at(live.retirement->attempt);
        const NativeMemoryFact *memory = execution.sample ? &*execution.sample
                                              : execution.store ? &*execution.store : nullptr;
        const NativeCoherenceFact *proof = nullptr;
        if (execution.store) {
          const auto found = coherent_admission_indices.find(
              drain_key(entry.first, live.retirement->attempt, execution.store->source_time, execution.store->address));
          if (found != coherent_admission_indices.end())
            proof = &capture.coherence_facts[found->second];
        }
        LoadOrderCertificate certificate;
        const auto order = load_orders.retire(*live.retirement, live.expanded_instruction,
            memory, proof, raw_safe, capture.memory_facts, certificate);
        if (!order) {
          remember_online_failure(order.status == rvwmo::CheckStatus::Pending
              ? rvwmo::CheckResult{rvwmo::CheckStatus::Incomplete, order.rule, order.message} : order);
          return false;
        }
        if (certificate.valid) {
          live.load_order = certificate;
          if (certificate.modeled_witness)
            record("LOAD_ORDER_WINDOW", entry.first.hart, entry.first.epoch, entry.first.uid,
                   certificate.attempt, certificate.begin, certificate.end,
                   certificate.selected, certificate.mask);
        }
      }
      std::vector<PlannedObservation> planned;
      std::map<uint32_t, uint64_t> stop_at;
      plan_instruction(entry.first, live, planned, stop_at);
      for (const auto &fact : capture.cancellation_facts) {
        if (fact.id != entry.first || fact.reason == 1)
          continue;
        const rvwmo::InstructionCancelAttemptEvent cancelled{fact.id, fact.attempt};
        planned.push_back({fact.id.hart, fact.source_time, channels(fact.id.hart).memory, false,
            [cancelled, squashed = fact.reason == 2](Adapter &target, const Origin &origin) {
              return squashed ? target.squash(origin, cancelled.id) : target.cancel_load(origin, cancelled);
            }});
      }
      if (!capture.summary.gaps.empty() || !stop_at.empty()) {
        remember_online_failure({rvwmo::CheckStatus::Incomplete, 0,
            capture.summary.gaps.empty() ? "online conversion stopped an unsupported instruction"
                                         : capture.summary.gaps.front()});
        return false;
      }
      for (auto &observation : planned)
        online_observations[observation.time].push_back(std::move(observation));
      live.staged = true;
    }
    return true;
  }

  bool submit_online_batch(uint64_t through) {
    const auto submitted = prefix_consumer(online_batch);
    if (!submitted.accepted) {
      if (submitted.check.status != rvwmo::CheckStatus::Pending)
        remember_online_failure(submitted.check);
      return false;
    }
    ++capture.summary.online_prefixes;
    capture.summary.converted_events += online_batch.batch.events.size();
    online_batch = {};
    online_closed = through;
    if (submitted.check.status != rvwmo::CheckStatus::Pass &&
        submitted.check.status != rvwmo::CheckStatus::Pending) {
      remember_online_failure(submitted.check);
      return false;
    }
    return true;
  }

  bool close_online_batch(uint64_t through) {
    std::set<uint32_t> producers;
    for (const auto &channel : configuration.harts) {
      producers.insert(channel.instruction);
      producers.insert(channel.memory);
      producers.insert(channel.control);
    }
    producers.insert(configuration.publication_producers.begin(), configuration.publication_producers.end());
    for (const auto producer : producers) {
      const auto closed = online_adapter->close_prefix({producer, rvwmo::SourcePosition::end_of_cycle(through)});
      if (!closed) {
        remember_online_failure({rvwmo::CheckStatus::Incomplete, 0, closed.message});
        return false;
      }
    }
    online_batch = online_adapter->take_output();
    if (!online_batch.diagnostics.empty()) {
      remember_online_failure({rvwmo::CheckStatus::Incomplete, 0, online_batch.diagnostics.front().message});
      return false;
    }
    return submit_online_batch(through);
  }

  void release_online_prefix(uint64_t through) {
    std::set<rvwmo::OperationId> released;
    for (auto instruction = instructions.begin(); instruction != instructions.end();) {
      if (instruction->second.staged && instruction->second.last_fact_time <= through) {
        released.insert(instruction->first);
        instruction = instructions.erase(instruction);
      } else {
        ++instruction;
      }
    }
    const auto cancelled_before = [this, through](const rvwmo::OperationId &id, uint32_t number) {
      const auto instruction = instructions.find(id);
      if (instruction == instructions.end())
        return false;
      const auto execution = instruction->second.attempts.find(number);
      return execution != instruction->second.attempts.end() && execution->second.cancelled &&
             !execution->second.store && execution->second.cancelled_at <= through;
    };
    capture.memory_facts.erase(std::remove_if(capture.memory_facts.begin(), capture.memory_facts.end(),
        [&](const auto &fact) { return fact.kind == 3 && cancelled_before(fact.id, fact.attempt); }),
        capture.memory_facts.end());
    capture.forwarding_facts.erase(std::remove_if(capture.forwarding_facts.begin(), capture.forwarding_facts.end(),
        [&](const auto &fact) { return cancelled_before(fact.reader, fact.attempt); }), capture.forwarding_facts.end());
    capture.cancellation_facts.erase(std::remove_if(capture.cancellation_facts.begin(), capture.cancellation_facts.end(),
        [&](const auto &fact) { return fact.reason == 1 && cancelled_before(fact.id, fact.attempt); }),
        capture.cancellation_facts.end());
    const auto remove_released = [&released](auto &facts, const auto &identity) {
      facts.erase(std::remove_if(facts.begin(), facts.end(), [&](const auto &fact) {
        return released.count(identity(fact)) != 0;
      }), facts.end());
    };
    remove_released(capture.retirement_facts, [](const auto &fact) { return fact.id; });
    remove_released(capture.memory_facts, [](const auto &fact) { return fact.id; });
    remove_released(capture.coherence_facts, [](const auto &fact) { return fact.id; });
    remove_released(capture.cancellation_facts, [](const auto &fact) { return fact.id; });
    remove_released(capture.forwarding_facts, [](const auto &fact) { return fact.reader; });
    for (auto drain = physical_drain_counts.begin(); drain != physical_drain_counts.end();)
      if (released.count(std::get<0>(drain->first)))
        drain = physical_drain_counts.erase(drain);
      else
        ++drain;
    coherent_drain_indices.clear();
    coherent_admission_indices.clear();
    for (size_t index = 0; index < capture.coherence_facts.size(); ++index) {
      const auto &fact = capture.coherence_facts[index];
      auto &indices = fact.admission ? coherent_admission_indices : coherent_drain_indices;
      indices.emplace(drain_key(fact.id, fact.attempt, fact.source_time, fact.address), index);
    }
    forwarding_fact_indices.clear();
    for (size_t index = 0; index < capture.forwarding_facts.size(); ++index) {
      const auto &fact = capture.forwarding_facts[index];
      forwarding_fact_indices.emplace(std::make_tuple(fact.reader, fact.attempt, fact.byte_index), index);
    }
    for (auto &entry : instructions) {
      auto &attempts = entry.second.attempts;
      for (auto execution = attempts.begin(); execution != attempts.end();) {
        if (execution->first != entry.second.latest_attempt && execution->second.cancelled &&
            execution->second.cancelled_at <= through)
          execution = attempts.erase(execution);
        else
          ++execution;
      }
    }
    capture.summary.live_instructions = instructions.size();
  }

  void pump_online(uint64_t delivered_through) {
    if (!online_batch.batch.watermarks.empty()) {
      const uint64_t through = online_batch.batch.watermarks.front().closed_through.cycle;
      if (!submit_online_batch(through))
        return;
      release_online_prefix(through);
    }
    const uint64_t raw_safe = raw_safe_frontier(delivered_through);
    if (!stage_online_instructions(raw_safe))
      return;
    uint64_t through = raw_safe;
    for (const auto &entry : instructions) {
      if (entry.second.staged)
        continue;
      const auto &active = entry.second.attempts.at(entry.second.latest_attempt);
      if (!active.cancelled || active.store)
        through = std::min(through, active.allocated_at ? active.allocated_at - 1 : 0);
    }
    // Do not seal a retirement before its selected sample has reached Adapter.
    // A complete instruction may span this prefix because another hart has an
    // older unresolved allocation. Keep the retirement and late sample queued.
    bool changed = true;
    while (changed) {
      changed = false;
      for (const auto &entry : instructions) {
        const auto &live = entry.second;
        if (live.staged && live.retirement && live.load_order &&
            live.retirement->source_time <= through && live.load_order->selected > through) {
          through = live.retirement->source_time ? live.retirement->source_time - 1 : 0;
          changed = true;
        }
      }
    }
    if (online_closed && through <= *online_closed)
      return;
    size_t batch_events = 0;
    for (const auto &cycle : online_observations) {
      if (cycle.first > through)
        break;
      batch_events += cycle.second.size();
    }
    if (batch_events > kMaximumOnlinePrefixEvents) {
      remember_online_failure({rvwmo::CheckStatus::Incomplete, 0,
                               "one unresolved online prefix exceeds the bounded live event window"});
      return;
    }
    for (auto cycle = online_observations.begin(); cycle != online_observations.end() && cycle->first <= through;) {
      for (const auto &observation : cycle->second) {
        const Origin origin{observation.producer,
            {observation.time, 0, ++online_sequences[observation.producer], false}};
        const auto converted = observation.convert(*online_adapter, origin);
        if (!converted) {
          const auto status = converted.status == ConversionStatus::Invalid ? rvwmo::CheckStatus::Invalid
                              : converted.status == ConversionStatus::Unsupported ? rvwmo::CheckStatus::Unsupported
                                                                                  : rvwmo::CheckStatus::Incomplete;
          remember_online_failure({status, 0, converted.message});
          return;
        }
      }
      cycle = online_observations.erase(cycle);
    }
    if (close_online_batch(through))
      release_online_prefix(through);
  }

  void finish_online() {
    if (online_result) {
      const uint64_t through = completed_cycle.value_or(delivery_barrier.value_or(0));
      pump_online(through);
    }
    capture.completion.pending = online_adapter->pending();
    // Native facts not yet converted must also participate in final drain.
    capture.completion.pending.instructions += instructions.size();
    if (!instructions.empty() || !online_observations.empty() || !online_batch.batch.watermarks.empty())
      gap("online native capture retains unresolved instructions, source observations or backpressure");
  }

  void plan_instruction(const rvwmo::OperationId &id, const Instruction &live,
                        std::vector<PlannedObservation> &planned, std::map<uint32_t, uint64_t> &stop_at) {
    const auto stop = [&](uint32_t hart_id, uint64_t time, const std::string &message) {
      gap(message);
      const auto previous = stop_at.find(hart_id);
      if (previous == stop_at.end() || time < previous->second)
        stop_at[hart_id] = time;
    };
    if (live.retirement) {
      const auto &selected = live.attempts.at(live.retirement->attempt);
      if (selected.sample)
        validate_forwarded_sample(*selected.sample);
    }
    const auto &channel = channels(id.hart);
    const auto allocation = live.allocation;
    if (!allocation.length) {
      stop(id.hart, live.allocated_at, "raw encoding unavailable; subsequent instruction facts remain unconverted");
      return;
    }
    if (!live.allocation_staged)
      planned.push_back({id.hart, live.allocated_at, channel.instruction, false,
                         [allocation](Adapter &target, const Origin &origin) { return target.allocate(origin, allocation); }});
    for (const auto &attempt_entry : live.attempts) {
      const auto &execution = attempt_entry.second;
      if (execution.store && !execution.drained)
        gap("store-buffer input has no matching physical drain candidate");
      if (execution.drained) {
        const auto key = drain_key(id, attempt_entry.first, execution.store->source_time, execution.store->address);
        const auto proof_index = coherent_admission_indices.find(key);
        if (proof_index == coherent_admission_indices.end()) {
          gap("store-buffer acceptance lacks qualified ownership/publication evidence");
        } else if (capture.coherence_facts[proof_index->second].proof_flags != 0x1f ||
                   (execution.memory_flags & ~uint32_t{1u << 3})) {
          gap("coherent admission belongs to an unsupported memory lifecycle");
        } else if (!live.retirement || live.retirement->attempt != attempt_entry.first || execution.cancelled) {
          gap("coherent physical store drain has no final committed instruction");
        } else {
          require(configuration.publication_producers.size() == hart_count,
                  "coherent publication requires one factual cache source per hart");
          const auto &store = *execution.store;
          const auto span = scalar_span(store.mask);
          const auto producer = configuration.publication_producers.at(id.hart);
          rvwmo::StorePublishEvent publish;
          publish.address = store.address + span.first;
          publish.bytes = span_bytes(store.aligned_data, span);
          publish.byte_mask.assign(span.size, 1);
          publish.byte_writers.assign(span.size, id);
          // Transaction IDs identify per-instruction acceptance and do not
          // establish an order among simultaneous cache producers.

          planned.push_back({id.hart, capture.coherence_facts[proof_index->second].source_time,
              producer, false,
              [this, publish, id](Adapter &target, const Origin &origin) mutable {
                publish.transaction_id = ++publication_transaction_;
                publish.members = {{id, origin.source}};
                return target.publish_store(origin, publish);
              }});
        }
      }
      if (execution.sample && (!online_adapter || !execution.cancelled) && scalar_sample(*execution.sample)) {
        const auto load = sample(*execution.sample);
        const auto actual_time = execution.sample->forwarded_mask
            ? execution.sample->forwarding_time : execution.sample->array_time;
        const auto time = live.load_order && live.retirement && live.retirement->attempt == attempt_entry.first
            ? live.load_order->selected : actual_time;
        planned.push_back({id.hart, time, channel.memory, false,
                           [load](Adapter &target, const Origin &origin) { return target.load_sample(origin, load); }});
      }

    }
    if (!live.retirement) {
      if (!live.trapped && !live.attempts.at(live.latest_attempt).squashed)
        gap("native finish retains allocated instructions without architectural completion");
      return;
    }
    const auto &fact = *live.retirement;
    const auto &execution = live.attempts.at(fact.attempt);
    const bool ordinary_load = is_load(live.expanded_instruction);
    const bool ordinary_store = is_store(live.expanded_instruction);
    const bool mismatched_effect = (execution.sample && !ordinary_load) ||
                                   ((execution.store || execution.observed_store_drain) && !ordinary_store);
    if (fact.fp || is_atomic(live.expanded_instruction) || is_cbo(live.expanded_instruction) ||
        (execution.memory_flags & ~uint32_t{1u << 3}) || mismatched_effect) {
      stop(id.hart, fact.source_time, "unsupported or non-scalar memory effect retained as raw fact, not ordinary retirement");
      return;
    }
    RetireRecord retired;
    retired.id = id;
    retired.pc = fact.pc;
    retired.instruction = fact.instruction;
    retired.length = static_cast<uint8_t>(fact.instruction_bytes);
    retired.rd = static_cast<uint8_t>(fact.rd);
    retired.integer_writeback = fact.write_enable;
    if (fact.write_enable)
      retired.register_value = fact.write_data;
    if (is_load(live.expanded_instruction)) {
      if (!execution.sample || !scalar_sample(*execution.sample)) {
        stop(id.hart, fact.source_time, "retired load lacks a representable final byte sample");
        return;
      }
      const auto load = sample(*execution.sample);
      retired.memory.push_back(load.operation);
      if (fact.write_enable) {
        // The load's architectural actual value comes from the separately
        // paired register writeback, not the SRAM/forwarding sample itself.
        retired.loads.push_back({id, fact.attempt,
                                 architectural_load_bytes(fact.write_data, execution.sample->mask)});
      } else {
        retired.loads.push_back({id, fact.attempt, load.actual_bytes});

      }
    } else if (is_store(live.expanded_instruction)) {
      if (!execution.store || (execution.store->flags & ~uint32_t{1u << 3})) {
        stop(id.hart, fact.source_time, "retired store lacks ordinary captured store bytes");
        return;
      }
      const auto &store = *execution.store;
      const bool accepted_before_retirement = store.source_time < fact.source_time;
      if (!accepted_before_retirement && !execution.accepted_store) {
        stop(id.hart, fact.source_time, "retired unpublished store lacks its accepted miss payload");
        return;
      }
      const auto &local_data = accepted_before_retirement ? store : *execution.accepted_store;
      if (local_data.source_time > fact.source_time) {
        stop(id.hart, fact.source_time, "retired store predates its accepted payload");
        return;
      }
      const auto span = scalar_span(local_data.mask);
      const rvwmo::LocalStoreEvent local{id, local_data.address + span.first, span_bytes(local_data.aligned_data, span),
                                        std::vector<uint8_t>(span.size, 1)};
      // Hit stores have zero local-overlay residency but retain their REF audit record.
      planned.push_back({id.hart, std::min(fact.source_time, store.source_time), channel.memory, false,
                         [local](Adapter &target, const Origin &origin) { return target.local_store(origin, local); }});
      rvwmo::MemoryOperation operation;
      operation.id = id;
      operation.attempt = fact.attempt;
      operation.address = local.address;
      operation.byte_mask = local.byte_mask;
      operation.store = true;
      retired.memory.push_back(operation);
    }
    planned.push_back({id.hart, fact.source_time, channel.instruction, false,
                       [retired](Adapter &target, const Origin &origin) { return target.retire(origin, retired); }});
  }

  void convert() {
    Adapter adapter(configuration);
    require(static_cast<bool>(adapter.configuration()), adapter.configuration().message.c_str());
    std::vector<PlannedObservation> planned;
    std::map<uint32_t, uint64_t> stop_at;
    for (const auto &proof : capture.coherence_facts) {
      const auto key = drain_key(proof.id, proof.attempt, proof.source_time, proof.address);
      if (proof.admission) {
        const auto live = instructions.find(proof.id);
        if (live == instructions.end() || !live->second.attempts.count(proof.attempt) ||
            !live->second.attempts.at(proof.attempt).store ||
            live->second.attempts.at(proof.attempt).store->source_time != proof.source_time ||
            live->second.attempts.at(proof.attempt).store->address != proof.address)
          gap("coherence admission proof has no unique matching store input");
      } else if (physical_drain_counts[key] != 1) {
        gap("coherence location proof has no unique exact physical store drain fact");
      }
    }
    for (const auto &drain : physical_drain_counts)
      if (drain.second != 1 || !coherent_drain_indices.count(drain.first))
        gap("physical store drain has no unique coherence/location proof");
    for (const auto &entry : instructions)
      plan_instruction(entry.first, entry.second, planned, stop_at);
    for (const auto &fact : capture.cancellation_facts) {
      if (fact.reason == 1) {
        const auto instruction = instructions.find(fact.id);
        if (instruction == instructions.end() || !is_load(instruction->second.expanded_instruction))
          continue;
      }
      const rvwmo::InstructionCancelAttemptEvent cancelled{fact.id, fact.attempt};
      planned.push_back({fact.id.hart, fact.source_time, channels(fact.id.hart).memory, false,
                         [cancelled, squashed = fact.reason == 2](Adapter &target, const Origin &origin) {
                           if (squashed)
                             return target.squash(origin, cancelled.id);
                           return target.cancel_load(origin, cancelled);
                         }});
    }
    for (const auto &fact : capture.trap_facts) {
      if (!fact.id.uid)
        continue;
      const rvwmo::TrapEvent trap_event{fact.id.hart, fact.id, fact.pc, fact.cause, fact.interrupt};
      planned.push_back({fact.id.hart, fact.source_time, channels(fact.id.hart).control, true,
                         [trap_event](Adapter &target, const Origin &origin) { return target.trap(origin, trap_event); }});
    }
    // Native half-cycle source ticks are factual. Equal ticks remain unqualified;
    // this stable serialization is not a cross-producer arbitration/GMO witness.
    std::stable_sort(planned.begin(), planned.end(), [](const auto &left, const auto &right) { return left.time < right.time; });
    std::map<uint32_t, uint64_t> sequences;
    std::set<uint32_t> blocked;
    for (const auto &observation : planned) {
      if (blocked.count(observation.hart) ||
          (stop_at.count(observation.hart) && observation.time >= stop_at.at(observation.hart)))
        continue;
      const Origin origin{observation.producer, {observation.time, 0, ++sequences[observation.producer], false}};
      const auto result = observation.convert(adapter, origin);
      if (!result) {
        gap("public conversion retained an unresolved observation: " + result.message);
        blocked.insert(observation.hart);
      }
      if (observation.stops_hart)
        blocked.insert(observation.hart);
    }
    if (completed_cycle) {
      std::set<uint32_t> producers;
      for (const auto &channel : configuration.harts) {
        producers.insert(channel.instruction);
        producers.insert(channel.memory);
        producers.insert(channel.control);
      }
      producers.insert(configuration.publication_producers.begin(), configuration.publication_producers.end());
      for (uint32_t producer : producers) {
        const auto closed = adapter.close_prefix({producer, rvwmo::SourcePosition::end_of_cycle(*completed_cycle)});
        if (!closed)
          gap("native source prefix cannot close converted events: " + closed.message);
        // Deliver each watermark before trying the next producer; this is
        // adapter delivery, never a hardware relative-order witness.
        auto output = adapter.take_output();
        capture.converted.batch.events.insert(capture.converted.batch.events.end(),
            output.batch.events.begin(), output.batch.events.end());
        capture.converted.batch.watermarks.insert(capture.converted.batch.watermarks.end(),
            output.batch.watermarks.begin(), output.batch.watermarks.end());
        capture.converted.retirements.insert(capture.converted.retirements.end(),
            output.retirements.begin(), output.retirements.end());
        capture.converted.diagnostics.insert(capture.converted.diagnostics.end(),
            output.diagnostics.begin(), output.diagnostics.end());
      }
    } else {
      capture.converted = adapter.take_output();
    }
    for (const auto &diagnostic : capture.converted.diagnostics)
      gap(diagnostic.message);
    const auto pending = adapter.pending();
    capture.completion.pending = pending;
    if (pending.instructions || pending.writebacks || pending.load_samples)
      gap("converted capture retains pending instruction, writeback or load-sample state");
    if (pending.unpublished_stores)
      gap("LocalStore remains unpublished without qualified coherence evidence");
  }
};

std::unique_ptr<Bridge> session;
Bridge &bridge() {
  if (!session)
    session = std::make_unique<Bridge>();
  return *session;
}

template <typename Function> int invoke(const char *name, Function action, bool final = false) noexcept {
  try {
    auto &state = bridge();
    state.require(!state.notifying_failure, "native failure observer cannot reenter capture");
    if (!final)
      state.require(!state.finished && !state.failed, "native session is finished or has a prior transport failure");
    action(state);
    return state.failed ? 1 : 0;
  } catch (const std::exception &error) {
    auto &state = bridge();
    state.reject_transport(error.what());
    std::cerr << "[Difftest-S] rejected " << name << ": " << error.what() << '\n';
    return 1;
  } catch (...) {
    bridge().reject_transport("unknown native host exception");
    std::cerr << "[Difftest-S] rejected " << name << ": unknown host exception\n";
    return 1;
  }
}
} // namespace

ConversionResult install_native_sink(Configuration configuration, NativeSink sink,
                                     NativeFailureObserver failure_observer) {
  auto &state = bridge();
  if (state.hart_count || state.finished || state.failed || !sink || state.sink || state.verifier)
    return {ConversionStatus::Invalid, "install a nonempty native sink before producer initialization"};
  Adapter check(configuration);
  if (!check.configuration())
    return check.configuration();
  state.configuration = std::move(configuration);
  state.sink = std::move(sink);
  state.failure_observer = std::move(failure_observer);
  return {};
}

ConversionResult install_native_verifier(Configuration configuration, NativeVerifier verifier,
                                         NativeFailureObserver failure_observer) {
  auto &state = bridge();
  if (state.hart_count || state.finished || state.failed || !verifier || state.sink || state.verifier)
    return {ConversionStatus::Invalid, "install one native verifier before producer initialization"};
  Adapter check(configuration);
  if (!check.configuration())
    return check.configuration();
  state.configuration = std::move(configuration);
  state.verifier = std::move(verifier);
  state.failure_observer = std::move(failure_observer);
  return {};
}

ConversionResult install_native_online_verifier(Configuration configuration, NativePrefixConsumer consume,
    NativeVerifier finalize, NativeFailureObserver failure_observer) {
  if (!consume || !finalize)
    return {ConversionStatus::Invalid, "online native session requires prefix and finalization callbacks"};
  configuration.monotonic_publication_transactions = true;
  auto installed = install_native_verifier(std::move(configuration), std::move(finalize), std::move(failure_observer));
  if (!installed)
    return installed;
  auto &state = bridge();
  state.prefix_consumer = std::move(consume);
  state.online_adapter = std::make_unique<Adapter>(state.configuration);
  return {};
}

ConversionResult reset_native_session() {
  if (session && session->notifying_failure)
    return {ConversionStatus::Invalid, "native failure notification must return before resetting its session"};
  if (session && session->hart_count && !session->finished)
    return {ConversionStatus::Invalid, "active native capture must finish before starting a fresh session"};
  session = std::make_unique<Bridge>();
  return {};
}

const NativeCapture &last_native_capture() { return bridge().capture; }
} // namespace blackparrot

extern "C" int bp_difftest_s_probe_init(uint32_t hart, uint32_t count) {
  return blackparrot::invoke("probe_init", [&](auto &state) { state.initialize(hart, count); });
}
extern "C" int bp_difftest_s_allocate(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                     uint64_t time, uint64_t pc, uint32_t raw, uint32_t length, uint32_t expanded) {
  return blackparrot::invoke("allocate", [&](auto &state) { state.allocate({hart, epoch, uid, 0}, attempt, time, pc, raw, length, expanded); });
}
extern "C" int bp_difftest_s_retire(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                   uint64_t time, uint64_t pc, uint32_t raw, uint32_t length,
                                   uint32_t rd, uint32_t enable, uint32_t fp, uint64_t value) {
  return blackparrot::invoke("retire", [&](auto &state) {
    state.require(enable <= 1 && fp <= 1, "invalid retirement boolean flags");
    state.retire({{hart, epoch, uid, 0}, attempt, time, pc, raw, length, rd, enable != 0, fp != 0, value});
  });
}
extern "C" int bp_difftest_s_cancel(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                   uint64_t time, uint32_t reason) {
  return blackparrot::invoke("cancel", [&](auto &state) { state.cancel({hart, epoch, uid, 0}, attempt, time, reason); });
}
extern "C" int bp_difftest_s_trap(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                 uint64_t time, uint64_t pc, uint64_t cause, uint32_t interrupt, uint64_t tval,
                                 uint64_t target, uint32_t privilege, uint32_t target_privilege) {
  return blackparrot::invoke("trap", [&](auto &state) {
    state.require(interrupt <= 1, "invalid interrupt flag");
    state.trap({{hart, epoch, uid, 0}, attempt, time, pc, cause, interrupt != 0, tval, target, privilege, target_privilege});
  });
}
extern "C" int bp_difftest_s_memory(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                   uint64_t time, uint32_t kind, uint64_t address, uint64_t value, uint32_t mask,
                                   uint64_t array_time, uint64_t forwarding_time, uint32_t forwarded_mask, uint32_t flags) {
  return blackparrot::invoke("memory", [&](auto &state) {
    blackparrot::NativeMemoryFact fact;
    fact.id = {hart, epoch, uid, 0}; fact.attempt = attempt; fact.source_time = time; fact.kind = kind;
    fact.address = address; fact.aligned_data = value; fact.mask = mask; fact.array_time = array_time;
    fact.forwarding_time = forwarding_time; fact.forwarded_mask = forwarded_mask; fact.flags = flags;
    state.memory(std::move(fact));
  });
}
extern "C" int bp_difftest_s_forward_byte(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                         uint32_t lane, uint64_t writer_epoch, uint64_t writer_uid) {
  return blackparrot::invoke("forward_byte", [&](auto &state) { state.forward({hart, epoch, uid, 0}, attempt, lane, {hart, writer_epoch, writer_uid, 0}); });
}
extern "C" int bp_difftest_s_heartbeat(uint32_t hart, uint64_t time, uint32_t pending) {
  return blackparrot::invoke("heartbeat", [&](auto &state) {
    auto &source = state.hart(hart);
    state.require(!source.closed_at && !state.completed_cycle, "heartbeat delivered after native source seal");
    state.require(time >= source.heartbeat_time, "hart heartbeat source time regressed");
    source.heartbeat_time = time;
    source.latest_core_time = std::max(source.latest_core_time, time);
    source.pending_retirements = pending;
    state.record("HEARTBEAT", hart, time, pending);
  });
}
extern "C" int bp_difftest_s_memory_idle(uint32_t hart, uint64_t time, uint32_t idle) {
  return blackparrot::invoke("memory_idle", [&](auto &state) {
    state.require(idle <= 1, "invalid physical memory-idle flag");
    auto &source = state.hart(hart);
    state.require(!state.completed_cycle, "memory observation delivered after the terminal source prefix");
    state.require(time >= source.memory_idle_time && time >= source.latest_memory_time,
                  "memory-idle source time predates its last memory observation");
    source.memory_idle = idle != 0;
    source.memory_idle_time = time;
    state.record("MEMORY_IDLE", hart, time, idle);
  });
}
extern "C" int bp_difftest_s_coherent_drain(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                              uint64_t time, uint64_t address, uint32_t cache_set,
                                              uint32_t cache_way, uint32_t state, uint64_t grant_time,
                                              uint32_t proof_flags, uint32_t bank_select,
                                              uint32_t physical_sram_index) {
  return blackparrot::invoke("coherent_drain", [&](auto &bridge) {
    bridge.coherent_store({{hart, epoch, uid, 0}, attempt, time, address, cache_set, cache_way,
                           state, grant_time, proof_flags, bank_select, physical_sram_index});
  });
}
extern "C" int bp_difftest_s_coherent_accept(uint32_t hart, uint64_t epoch, uint64_t uid, uint32_t attempt,
                                               uint64_t time, uint64_t address, uint32_t cache_set,
                                               uint32_t cache_way, uint32_t state, uint64_t grant_time,
                                               uint32_t proof_flags, uint32_t bank_select,
                                               uint32_t target_sram_index) {
  return blackparrot::invoke("coherent_accept", [&](auto &bridge) {
    bridge.coherent_store({{hart, epoch, uid, 0}, attempt, time, address, cache_set, cache_way,
                           state, grant_time, proof_flags, bank_select, target_sram_index, true});
  });
}
extern "C" int bp_difftest_s_terminal_state(uint32_t hart, uint64_t time, uint64_t uid,
                                              uint32_t stopped, uint32_t pending) {
  return blackparrot::invoke("terminal_state", [&](auto &state) {
    state.require(stopped <= 1, "invalid terminal stopped flag");
    state.terminal_state(hart, time, uid, stopped != 0, pending);
  });
}
extern "C" int bp_difftest_s_can_end() {
  return blackparrot::bridge().can_end() ? 1 : 0;
}
extern "C" int bp_difftest_s_close_hart(uint32_t hart, uint64_t time, uint64_t uid) {
  return blackparrot::invoke("close_hart", [&](auto &state) { state.close_hart(hart, time, uid); });
}
extern "C" int bp_difftest_s_close_prefix(uint64_t time) {
  return blackparrot::invoke("close_prefix", [&](auto &state) { state.close_prefix(time); });
}

extern "C" int bp_difftest_s_advance(uint64_t time) {
  const auto status = blackparrot::invoke("advance", [&](auto &state) { state.advance(time); });
  return status || !blackparrot::bridge().online_result ? 1 : 0;
}
extern "C" int bp_difftest_s_finish() {
  const int transport = blackparrot::invoke("finish", [](auto &state) { state.finish(); }, true);
  if (transport)
    return transport;
  const auto &verification = blackparrot::last_native_capture().summary.verification;
  return !verification || verification->check.status != rvwmo::CheckStatus::Pass || !verification->finalized ? 2 : 0;
}
