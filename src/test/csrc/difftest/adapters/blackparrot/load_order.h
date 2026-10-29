#ifndef DIFFTEST_BLACKPARROT_LOAD_ORDER_H
#define DIFFTEST_BLACKPARROT_LOAD_ORDER_H

#include "native_bridge.h"
#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <vector>

namespace blackparrot {

// A private model-order witness, never a replacement physical sample timestamp.
// The caller retains the unmodified NativeMemoryFact and uses the certificate
// only after independent memory-value/store audits and all PPO checks succeed.
struct LoadOrderCertificate {
  rvwmo::OperationId id;
  uint32_t attempt = 0;
  uint64_t begin = 0;
  uint64_t end = 0;
  uint64_t selected = 0;
  uint32_t mask = 0;
  bool valid = false;
  bool modeled_witness = false;
};

// Called exactly once for each final architectural retirement, in each hart's
// UID order. Cancelled/replayed attempts never advance this state. The caller
// proves source_closed_through closes the *raw* prefix and retains every hart's
// store input in each sample interval, including already retired stores.
// This class retains constant-size order summaries per hart, not trace history.
class LoadOrderValidator {
public:
  rvwmo::CheckResult retire(const NativeRetirementFact &retired, uint32_t expanded,
      const NativeMemoryFact *memory, const NativeCoherenceFact *publication,
      uint64_t source_closed_through, const std::vector<NativeMemoryFact> &retained_memory,
      LoadOrderCertificate &certificate) {
    certificate = {};
    if (!retired.id.uid || !retired.id.epoch || retired.id.subaccess || !retired.attempt ||
        (retired.instruction_bytes != 2 && retired.instruction_bytes != 4))
      return failure(rvwmo::CheckStatus::Invalid, "load-order retirement identity or instruction length is invalid");
    if (retired.fp)
      return failure(rvwmo::CheckStatus::Unsupported, "load-order certificate supports scalar integer retirement only");

    HartState next;
    const auto current = harts_.find(retired.id.hart);
    if (current != harts_.end()) {
      if (retired.id.epoch < current->second.epoch)
        return failure(rvwmo::CheckStatus::Invalid, "load-order retirement uses a stale epoch");
      if (retired.id.epoch == current->second.epoch)
        next = current->second;
    }
    if (retired.id.uid <= next.last_uid)
      return failure(rvwmo::CheckStatus::Invalid, "load-order retirement UID is not increasing within its hart epoch");
    next.epoch = retired.id.epoch;

    const uint32_t opcode = expanded & 0x7f;
    rvwmo::CheckResult result;
    LoadOrderCertificate candidate;
    if (opcode == 0x23)
      result = record_store(retired, memory, publication, source_closed_through, next);
    else if (opcode == 0x03) {
      if (publication)
        return failure(rvwmo::CheckStatus::Invalid, "load retirement carries an unrelated publication proof");
      result = validate_load(retired, memory, source_closed_through, retained_memory, next, candidate);
    } else if (memory || publication)
      result = failure(rvwmo::CheckStatus::Invalid, "non-scalar-memory retirement carries load-order memory evidence");
    else if (opcode == 0x2f)
      result = failure(rvwmo::CheckStatus::Unsupported, "atomic retirement requires its own memory-order certificate");
    if (!result)
      return result;

    const bool base_fence = retired.instruction_bytes == 4 && (expanded & 0xf000707f) == 0x000f;
    if (base_fence && (expanded & (1u << 24)) && (expanded & (1u << 21)))
      next.fenced_store_publish = std::max(next.fenced_store_publish, next.latest_store_publish);
    next.last_uid = retired.id.uid;
    harts_[retired.id.hart] = next;
    certificate = candidate;
    return {};
  }

private:
  struct HartState {
    uint64_t epoch = 0;
    uint64_t last_uid = 0;
    uint64_t latest_store_publish = 0;
    uint64_t fenced_store_publish = 0;
  };
  std::map<uint32_t, HartState> harts_;

  static rvwmo::CheckResult failure(rvwmo::CheckStatus status, const char *message) {
    return {status, 0, message};
  }

  static bool ordinary_span(const NativeMemoryFact &memory) {
    return memory.mask && !(memory.mask & ~0xffu) && !(memory.address & 7) &&
           !(memory.flags & ~uint32_t{8});
  }

  static bool matches(const NativeRetirementFact &retired, const NativeMemoryFact &memory) {
    return retired.id == memory.id && retired.attempt == memory.attempt;
  }

  static rvwmo::CheckResult record_store(const NativeRetirementFact &retired,
      const NativeMemoryFact *memory, const NativeCoherenceFact *publication,
      uint64_t closed_through, HartState &next) {
    if (!memory || !publication)
      return failure(rvwmo::CheckStatus::Pending, "store order awaits its input and qualified publication");
    if (!matches(retired, *memory) || memory->kind != 1 || publication->id != retired.id ||
        publication->attempt != retired.attempt || publication->address != memory->address)
      return failure(rvwmo::CheckStatus::Invalid, "store order evidence differs from the final retired identity or address");
    if (!ordinary_span(*memory))
      return failure(rvwmo::CheckStatus::Unsupported, "store order requires an ordinary aligned scalar byte span");
    if (!publication->admission || publication->proof_flags != 0x1f)
      return failure(rvwmo::CheckStatus::Incomplete, "store order lacks a qualified coherence publication proof");
    if (!memory->source_time || publication->source_time != memory->source_time ||
        !publication->grant_time || publication->grant_time >= publication->source_time)
      return failure(rvwmo::CheckStatus::Invalid, "store order input, grant and publication times are inconsistent");
    if (closed_through < publication->source_time)
      return failure(rvwmo::CheckStatus::Pending, "store order awaits raw source-prefix closure");
    next.latest_store_publish = std::max(next.latest_store_publish, publication->source_time);
    return {};
  }

  static bool overlaps(const NativeMemoryFact &left, const NativeMemoryFact &right) {
    // Native ordinary facts have aligned eight-byte addresses and one byte mask.
    return left.address == right.address && (left.mask & right.mask) != 0;
  }

  static rvwmo::CheckResult validate_load(const NativeRetirementFact &retired,
      const NativeMemoryFact *sample, uint64_t closed_through,
      const std::vector<NativeMemoryFact> &retained_memory, const HartState &state,
      LoadOrderCertificate &certificate) {
    if (!sample)
      return failure(rvwmo::CheckStatus::Pending, "load order awaits its final selected sample");
    if (!matches(retired, *sample) || sample->kind != 3 || (sample->forwarded_mask & ~sample->mask))
      return failure(rvwmo::CheckStatus::Invalid, "load-order sample identity, attempt, kind or forwarding mask is invalid");
    if (!sample->mask || (sample->mask & ~0xffu) || (sample->address & 7))
      return failure(rvwmo::CheckStatus::Invalid, "load-order sample address or byte mask is invalid");
    if (sample->flags & ~uint32_t{8})
      return failure(rvwmo::CheckStatus::Unsupported, "load order supports ordinary scalar RAM samples only");
    if (sample->forwarded_mask && sample->forwarded_mask != sample->mask)
      return failure(rvwmo::CheckStatus::Incomplete, "mixed SRAM and forwarded bytes lack one load-order certificate");
    const uint64_t actual_time = sample->forwarded_mask ? sample->forwarding_time : sample->array_time;
    if (!actual_time || !sample->source_time || actual_time > sample->source_time)
      return failure(rvwmo::CheckStatus::Invalid, "load-order sample source interval is invalid");
    if (closed_through < sample->source_time)
      return failure(rvwmo::CheckStatus::Pending, "load order awaits complete raw sample-interval closure");

    LoadOrderCertificate candidate{retired.id, retired.attempt, actual_time, sample->source_time,
                                   actual_time, sample->mask, true, false};
    // A WBUF acceptance can share the load's physical read/forward edge.
    // Derive an interval witness instead of inventing a cross-hart clock phase.
    const NativeMemoryFact *current_input_writer = nullptr;
    for (const auto &store : retained_memory) {
      if (store.kind != 1 || store.id.hart != retired.id.hart || store.source_time != actual_time)
        continue;
      if (current_input_writer)
        return failure(rvwmo::CheckStatus::Incomplete,
                       "load sample tick has multiple same-hart store-input candidates");
      current_input_writer = &store;
    }
    const bool input_tie = current_input_writer != nullptr;
    const bool older_input = input_tie && current_input_writer->id.epoch == retired.id.epoch &&
                             current_input_writer->id.uid < retired.id.uid;
    const bool overlapping_input = older_input && overlaps(*sample, *current_input_writer);
    bool exact_forwarded_input = overlapping_input && sample->forwarded_mask == sample->mask &&
                                 (current_input_writer->mask & sample->mask) == sample->mask;
    for (size_t lane = 0; lane < 8 && exact_forwarded_input; ++lane)
      if (sample->mask & (1u << lane))
        exact_forwarded_input = sample->forwarded_writers[lane] &&
                                *sample->forwarded_writers[lane] == current_input_writer->id;
    // A disjoint SRAM load can commute with a same-tick older store. A
    // model-order point after that store is valid only if the complete closed
    // interval below contains no write to any byte the load reads. This is an
    // existential order witness, never a new physical sample timestamp.
    const bool disjoint_stable_input = older_input && !overlapping_input && !sample->forwarded_mask;
    if (input_tie && !exact_forwarded_input && !disjoint_stable_input)
      return failure(rvwmo::CheckStatus::Incomplete,
                     "same-hart load/store source tie lacks stable disjoint bytes or exact forwarded writer");
    if ((!state.fenced_store_publish || actual_time > state.fenced_store_publish) && !input_tie) {
      certificate = candidate;
      return {};
    }
    if (sample->forwarded_mask && actual_time < state.fenced_store_publish)
      return failure(rvwmo::CheckStatus::Incomplete,
                     "fenced forwarded load has no certified model-order point after prior stores");
    if (std::max(actual_time, state.fenced_store_publish) == std::numeric_limits<uint64_t>::max())
      return failure(rvwmo::CheckStatus::Incomplete, "fenced store leaves no representable load-order witness");
    uint64_t selected = std::max(actual_time, state.fenced_store_publish) + 1;
    // The derived point must precede architectural retirement. Equality has
    // no proven intra-tick rank; moving it later would invent a post-retire load.
    if (selected >= retired.source_time)
      return failure(rvwmo::CheckStatus::Incomplete, "load-order witness is not strictly before retirement");
    if (selected > sample->source_time)
      return failure(rvwmo::CheckStatus::Incomplete, "load has no closed stable-writer interval after tied store");
    for (const auto &store : retained_memory) {
      if (store.kind != 1 || store.source_time < actual_time ||
          store.source_time > sample->source_time)
        continue;
      if (!ordinary_span(store))
        return failure(rvwmo::CheckStatus::Incomplete, "load-order interval contains unqualified store-byte evidence");
      if (!overlaps(*sample, store))
        continue;
      // Current-input bypass observes these exact store bytes on this edge.
      // No other writer, even one writing the same value, may enter the window.
      const bool input_source = exact_forwarded_input && store.id == current_input_writer->id;
      if (!input_source)
        return failure(rvwmo::CheckStatus::Incomplete, "load-order interval contains a byte writer transition");
    }
    candidate.selected = selected;
    candidate.modeled_witness = true;
    certificate = candidate;
    return {};
  }
};

} // namespace blackparrot
#endif
