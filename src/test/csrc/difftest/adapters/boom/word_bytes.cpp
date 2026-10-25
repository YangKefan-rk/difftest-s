#include "word_bytes.h"
#include <limits>

namespace rvwmo {
namespace boom {
namespace {
OperationId operation_id(uint32_t hart, const ProbeIdentity &identity) {
  return {hart, identity.epoch, identity.uid, 0};
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
  if (!(byte_mask & range_mask) || (byte_mask & ~range_mask) || (known_writer_mask & ~byte_mask))
    return {CheckStatus::Invalid, 0, "BOOM word byte/writer mask exceeds its physical scalar access"};
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

CheckResult convert_allocation(uint32_t hart, const ProbeInstruction &probe, const EventSource &source,
                                InstructionAllocation &result) {
  auto status = unsupported_atomic(probe.atomic);
  if (!status)
    return status;
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

CheckResult convert_retirement(uint32_t hart, const ProbeInstruction &probe, const EventSource &source,
                                std::optional<uint64_t> physical_load_address,
                                std::optional<uint64_t> independent_retire_data, Retirement &result) {
  auto status = unsupported_atomic(probe.atomic);
  if (!status)
    return status;
  if (!probe.architectural)
    return {CheckStatus::Incomplete, 0, "BOOM predicated-off retirement needs whole-instruction discard semantics"};
  Retirement converted{operation_id(hart, probe.identity), {probe.rob_index, probe.identity.rob_generation},
                       probe.pc, probe.instruction, {}, {}, source};
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
    converted.load_bytes = std::move(bytes.bytes);
  } else if (physical_load_address || independent_retire_data) {
    return {CheckStatus::Invalid, 0, "BOOM non-load retirement carries load-only fields"};
  }
  result = std::move(converted);
  return {};
}

} // namespace boom
} // namespace rvwmo
