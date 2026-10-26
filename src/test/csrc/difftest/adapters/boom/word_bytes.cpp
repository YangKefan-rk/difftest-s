#include "word_bytes.h"
#include <limits>

namespace rvwmo {
namespace boom {
namespace {
OperationId operation_id(uint32_t hart, const ProbeIdentity &identity) {
  return {hart, identity.epoch, identity.uid, 0};
}

bool same_instruction(const ProbeIdentity &lhs, const ProbeIdentity &rhs) {
  return lhs.epoch == rhs.epoch && lhs.uid == rhs.uid && lhs.rob_generation == rhs.rob_generation;
}

bool power_of_two(size_t value) { return value && (value & (value - 1)) == 0; }

CheckResult physical_queue_index(uint32_t raw_index, size_t entries, uint32_t &index) {
  if (!power_of_two(entries) || entries > uint64_t{1} << 31)
    return {CheckStatus::Invalid, 0, "BOOM queue capacity must be a power of two representable by its raw index"};
  if (uint64_t{raw_index} >= 2 * entries)
    return {CheckStatus::Invalid, 0, "BOOM raw circular queue index exceeds its slot plus wrap bit"};
  index = raw_index & (entries - 1);
  return {};
}

CheckResult unsupported_atomic(bool atomic) {
  if (atomic)
    return {CheckStatus::Unsupported, 0, "BOOM atomic probe requires the public atomic lifecycle consumer"};
  return {};
}
} // namespace

CheckResult extract_word_bytes(uint64_t physical_address, uint8_t log2_size, uint64_t word, uint8_t byte_mask,
                               WordLayout layout, uint8_t known_writer_mask,
                               const std::array<OperationId, 8> &writers, WordBytes &result) {
  if (log2_size > 3)
    return {CheckStatus::Unsupported, 0, "BOOM scalar word converter supports at most eight bytes"};
  const unsigned size = 1U << log2_size;
  const unsigned physical_offset = physical_address & 7;
  const unsigned offset = layout == WordLayout::AlignedMemoryWord ? physical_offset : 0;
  if (size > 8 - physical_offset || physical_address > std::numeric_limits<uint64_t>::max() - (size - 1))
    return {CheckStatus::Unsupported, 0, "BOOM access crosses a word boundary and requires split-access support"};
  const unsigned range_mask = ((1U << size) - 1) << offset;
  if (byte_mask != range_mask || (known_writer_mask & ~byte_mask))
    return {CheckStatus::Invalid, 0, "BOOM scalar byte mask does not cover its complete physical access"};
  WordBytes converted;
  converted.address = physical_address;
  for (unsigned byte = 0; byte < size; ++byte) {
    const unsigned lane = offset + byte;
    converted.bytes.push_back(static_cast<uint8_t>(word >> (lane * 8)));
    converted.byte_mask.push_back((byte_mask >> lane) & 1);
    if (known_writer_mask & (1U << lane)) {
      if (!writers[lane].uid)
        return {CheckStatus::Incomplete, 0, "BOOM known byte writer has no stable instruction identity"};
      converted.writers.push_back(writers[lane]);
    } else {
      converted.writers.push_back(std::nullopt);
    }
  }
  result = std::move(converted);
  return {};
}

CheckResult merge_allocation(uint32_t hart, const ProbeInstruction &core,
                              const std::optional<ProbeQueueAllocation> &queue,
                              size_t ldq_entries, size_t stq_entries, const EventSource &source,
                              InstructionAllocation &result) {
  if (core.uses_ldq && core.uses_stq)
    return {CheckStatus::Unsupported, 0, "BOOM read/write allocation needs atomic lifecycle semantics"};
  const bool uses_queue = core.uses_ldq || core.uses_stq;
  if (uses_queue != queue.has_value())
    return {CheckStatus::Incomplete, 0, "BOOM core allocation has no matching queue allocation observation"};
  auto merged = core;
  if (queue) {
    if (!same_instruction(core.identity, queue->identity) || queue->load != core.uses_ldq ||
        !queue->identity.memory_generation)
      return {CheckStatus::Invalid, 0, "BOOM core and queue allocation identities or queue kinds differ"};
    uint32_t index = 0;
    auto status = physical_queue_index(core.uses_ldq ? core.ldq_index : core.stq_index,
                                       core.uses_ldq ? ldq_entries : stq_entries, index);
    if (!status)
      return status;
    if (index != queue->index)
      return {CheckStatus::Invalid, 0, "BOOM core circular queue slot differs from the queue allocation slot"};
    if (core.identity.memory_generation && core.identity.memory_generation != queue->identity.memory_generation)
      return {CheckStatus::Invalid, 0, "BOOM allocation already carries a conflicting queue generation"};
    merged.identity.memory_generation = queue->identity.memory_generation;
    if (core.uses_ldq)
      merged.ldq_index = index;
    else
      merged.stq_index = index;
  }
  return convert_allocation(hart, merged, source, result);
}

CheckResult merge_retirement(uint32_t hart, const ProbeInstruction &core,
                              const InstructionAllocation &allocation,
                              const std::optional<ProbeLoadRetirement> &load,
                              size_t ldq_entries, size_t stq_entries, const EventSource &source,
                              Retirement &result) {
  if (operation_id(hart, core.identity) != allocation.id ||
      core.identity.rob_generation != allocation.rob.generation || core.rob_index != allocation.rob.index ||
      core.pc != allocation.pc || core.instruction != allocation.instruction ||
      core.uses_ldq != allocation.ldq.has_value() || core.uses_stq != allocation.stq.has_value())
    return {CheckStatus::Invalid, 0, "BOOM core retirement differs from its live instruction allocation"};
  if (core.uses_ldq != load.has_value())
    return {CheckStatus::Incomplete, 0, "BOOM core retirement lacks its matching final LDQ retirement observation"};
  if (core.uses_ldq || core.uses_stq) {
    const auto &slot = core.uses_ldq ? *allocation.ldq : *allocation.stq;
    uint32_t index = 0;
    auto status = physical_queue_index(core.uses_ldq ? core.ldq_index : core.stq_index,
                                       core.uses_ldq ? ldq_entries : stq_entries, index);
    if (!status)
      return status;
    if (index != slot.index)
      return {CheckStatus::Invalid, 0, "BOOM retirement circular queue slot differs from its allocation"};
  }
  auto merged = core;
  if (load) {
    if (!same_instruction(core.identity, load->identity) ||
        load->identity.memory_generation != allocation.ldq->generation || load->queue_index != allocation.ldq->index)
      return {CheckStatus::Invalid, 0, "BOOM final LDQ retirement names a stale instruction or queue generation"};
    merged.identity.memory_generation = load->identity.memory_generation;
    merged.identity.attempt = load->identity.attempt;
    return convert_retirement(hart, merged, source, load->address, load->independent_data, result);
  }
  return convert_retirement(hart, merged, source, {}, {}, result);
}

CheckResult convert_allocation(uint32_t hart, const ProbeInstruction &probe, const EventSource &source,
                                InstructionAllocation &result) {
  // Allocations may be speculative. Confirm unsupported memory semantics only
  // at architectural commit/retirement; whole-instruction squash is supported.
  InstructionAllocation converted;
  converted.id = operation_id(hart, probe.identity);
  converted.rob = {probe.rob_index, probe.identity.rob_generation};
  if (probe.uses_ldq)
    converted.ldq = SlotGeneration{probe.ldq_index, probe.identity.memory_generation};
  if (probe.uses_stq)
    converted.stq = SlotGeneration{probe.stq_index, probe.identity.memory_generation};
  converted.pc = probe.pc;
  converted.instruction = probe.instruction;
  converted.length = (probe.instruction & 3) == 3 ? 4 : 2;
  converted.source = source;
  result = std::move(converted);
  return {};
}

LoadAttempt convert_attempt(uint32_t hart, const ProbeIdentity &identity, uint32_t queue_index) {
  return {operation_id(hart, identity), {queue_index, identity.memory_generation}, identity.attempt};
}

CheckResult convert_load(uint32_t hart, const ProbeLoad &probe, const EventSource &source, LoadObservation &result) {
  std::array<OperationId, 8> writers;
  for (unsigned byte = 0; byte < writers.size(); ++byte)
    writers[byte] = operation_id(hart, probe.writers[byte]);
  WordBytes converted;
  auto status = extract_word_bytes(probe.address, probe.log2_size, probe.raw_word, probe.byte_mask,
                                   WordLayout::AlignedMemoryWord, probe.known_writer_mask, writers, converted);
  if (!status)
    return status;
  result = {convert_attempt(hart, probe.identity, probe.queue_index), converted.address, std::move(converted.bytes),
            std::move(converted.byte_mask), std::move(converted.writers), probe.sampling_point,
            probe.source_complete, source};
  return {};
}

CheckResult convert_store(uint32_t hart, const ProbeStore &probe, const EventSource &source, StoreCommit &result) {
  auto status = unsupported_atomic(probe.atomic);
  if (!status)
    return status;
  WordBytes converted;
  status = extract_word_bytes(probe.address, probe.log2_size, probe.word, probe.byte_mask,
                              WordLayout::AlignedMemoryWord, 0, {}, converted);
  if (!status)
    return status;
  result = {operation_id(hart, probe.identity), {probe.queue_index, probe.identity.memory_generation},
            converted.address, std::move(converted.bytes), std::move(converted.byte_mask), true, source};
  return {};
}

CheckResult convert_single_store_publication(uint32_t hart, const ProbeStore &probe, const EventSource &source,
                                             uint64_t transaction_id, StorePublicationEvidence evidence,
                                             bool single_writer_complete, StorePublication &result) {
  auto status = unsupported_atomic(probe.atomic);
  if (!status)
    return status;
  if (evidence != StorePublicationEvidence::Unavailable &&
      evidence != StorePublicationEvidence::ExclusiveCacheDataWrite &&
      evidence != StorePublicationEvidence::CoherentRefillDataWrite)
    return {CheckStatus::Invalid, 0, "BOOM publication converter has an unknown evidence kind"};
  if (!single_writer_complete || evidence == StorePublicationEvidence::Unavailable)
    return {CheckStatus::Incomplete, 0, "BOOM publication needs explicit cache-effect and single-writer evidence"};
  if (!transaction_id)
    return {CheckStatus::Invalid, 0, "BOOM publication has no stable transaction identity"};
  WordBytes bytes;
  status = extract_word_bytes(probe.address, probe.log2_size, probe.word, probe.byte_mask,
                              WordLayout::AlignedMemoryWord, 0, {}, bytes);
  if (!status)
    return status;
  auto writer = operation_id(hart, probe.identity);
  result = {writer, {probe.queue_index, probe.identity.memory_generation}, transaction_id, bytes.address,
            std::move(bytes.bytes), std::move(bytes.byte_mask), {}, evidence, source};
  result.byte_writers.assign(result.bytes.size(), writer);
  return {};
}

CheckResult convert_retirement(uint32_t hart, const ProbeInstruction &probe, const EventSource &source,
                                std::optional<uint64_t> physical_load_address,
                                std::optional<uint64_t> independent_retire_data, Retirement &result) {
  auto status = unsupported_atomic(probe.atomic);
  if (!status)
    return status;
  if (!probe.architectural)
    return {CheckStatus::Incomplete, 0, "BOOM predicated-off retirement needs whole-instruction discard semantics"};
  Retirement converted{operation_id(hart, probe.identity), {probe.rob_index, probe.identity.rob_generation},
                       probe.pc, probe.instruction, {}, {}, source, {}, {}, probe.destination_type,
                       probe.logical_destination, probe.writeback_value};
  if (probe.uses_ldq) {
    if (!physical_load_address || !independent_retire_data)
      return {CheckStatus::Incomplete, 0, "BOOM load retirement lacks physical address or independent LDQ result"};
    if (probe.log2_size > 3)
      return {CheckStatus::Unsupported, 0, "BOOM load retirement exceeds scalar width"};
    const uint8_t mask = static_cast<uint8_t>((1U << (1U << probe.log2_size)) - 1);
    WordBytes bytes;
    status = extract_word_bytes(*physical_load_address, probe.log2_size, *independent_retire_data, mask,
                                WordLayout::LowBytes, 0, {}, bytes);
    if (!status)
      return status;
    converted.load_attempt = probe.identity.attempt;
    converted.load_address = *physical_load_address;
    converted.load_log2_size = probe.log2_size;
    converted.load_bytes = std::move(bytes.bytes);
  } else if (physical_load_address || independent_retire_data) {
    return {CheckStatus::Invalid, 0, "BOOM non-load retirement carries load-only fields"};
  }
  result = std::move(converted);
  return {};
}

} // namespace boom
} // namespace rvwmo
