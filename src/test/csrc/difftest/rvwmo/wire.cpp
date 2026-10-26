#include "wire.h"
#include "session.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <vector>

struct difftest_s_wire_ingress {
  rvwmo::ObservationSession *session;
  uint32_t max_events;
  uint32_t max_watermarks;
  std::optional<rvwmo::CheckResult> failure;
};

namespace {
using rvwmo::CheckResult;
using rvwmo::CheckStatus;

CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult unsupported(const char *message) { return {CheckStatus::Unsupported, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }

uint32_t check_status(CheckStatus status) {
  switch (status) {
  case CheckStatus::Pass: return DIFFTEST_S_WIRE_PASS;
  case CheckStatus::Violation: return DIFFTEST_S_WIRE_VIOLATION;
  case CheckStatus::Pending: return DIFFTEST_S_WIRE_PENDING;
  case CheckStatus::Incomplete: return DIFFTEST_S_WIRE_INCOMPLETE;
  case CheckStatus::Unsupported: return DIFFTEST_S_WIRE_UNSUPPORTED;
  case CheckStatus::Invalid: return DIFFTEST_S_WIRE_INVALID;
  }
  return DIFFTEST_S_WIRE_INVALID;
}

uint32_t transport_status(rvwmo::EventValidationStatus status) {
  switch (status) {
  case rvwmo::EventValidationStatus::Accepted: return DIFFTEST_S_WIRE_TRANSPORT_ACCEPTED;
  case rvwmo::EventValidationStatus::Pending: return DIFFTEST_S_WIRE_TRANSPORT_PENDING;
  case rvwmo::EventValidationStatus::Incomplete: return DIFFTEST_S_WIRE_TRANSPORT_INCOMPLETE;
  case rvwmo::EventValidationStatus::Unsupported: return DIFFTEST_S_WIRE_TRANSPORT_UNSUPPORTED;
  case rvwmo::EventValidationStatus::Invalid: return DIFFTEST_S_WIRE_TRANSPORT_INVALID;
  }
  return DIFFTEST_S_WIRE_TRANSPORT_INVALID;
}

bool valid_result(const difftest_s_wire_result_v1 *result) {
  return result && result->abi_version == DIFFTEST_S_WIRE_ABI_VERSION_1 && result->struct_size == sizeof(*result);
}

int write_result(difftest_s_wire_result_v1 *output, const CheckResult &check, uint32_t transport,
                 bool accepted, uint64_t pending) {
  output->check_status = check_status(check.status);
  output->transport_status = transport;
  output->accepted = accepted ? 1 : 0;
  output->rule = check.rule;
  output->pending_events = pending;
  std::memset(output->message, 0, sizeof(output->message));
  const size_t length = std::min(check.message.size(), sizeof(output->message) - 1);
  std::memcpy(output->message, check.message.data(), length);
  return static_cast<int>(output->check_status);
}

int finish(difftest_s_wire_ingress *ingress, difftest_s_wire_result_v1 *output, const CheckResult &check,
           uint32_t transport = DIFFTEST_S_WIRE_NOT_SUBMITTED, bool accepted = false) {
  if (ingress && check.status != CheckStatus::Pass && check.status != CheckStatus::Pending)
    ingress->failure = check;
  return write_result(output, check, transport, accepted, ingress ? ingress->session->pending_events() : 0);
}

rvwmo::OperationId operation(const difftest_s_wire_operation_v1 &id) {
  return {id.hart, id.epoch, id.uid, id.subaccess};
}

rvwmo::SourcePosition position(const difftest_s_wire_source_v1 &source) {
  return {source.cycle, source.qualified_phase, source.producer_sequence, source.order_qualified != 0};
}

bool zero_operation(const difftest_s_wire_operation_v1 &id) {
  return !id.hart && !id.subaccess && !id.epoch && !id.uid;
}

bool empty_writers(const difftest_s_wire_event_v1 &event) {
  return event.writer_known_mask == 0 &&
         std::all_of(std::begin(event.writers), std::end(event.writers), zero_operation);
}

CheckResult validate_source(const difftest_s_wire_source_v1 &source, bool watermark) {
  if (!source.producer_id || !source.producer_sequence || source.order_qualified > 1 || source.reserved)
    return invalid("wire source has invalid producer, sequence, flags or reserved bits");
  if (!watermark && source.qualified_phase == DIFFTEST_S_WIRE_END_OF_CYCLE_PHASE)
    return invalid("wire event uses the watermark-only end-of-cycle phase");
  if (!source.order_qualified && source.qualified_phase)
    return invalid("unqualified wire source must not claim a phase");
  if (watermark && source.qualified_phase == DIFFTEST_S_WIRE_END_OF_CYCLE_PHASE &&
      (!source.order_qualified || source.producer_sequence != UINT64_MAX))
    return invalid("wire end-of-cycle watermark lacks its explicit closed-prefix sentinel");
  return {};
}

enum Field : uint32_t {
  Attempt = 1 << 0,
  Instruction = 1 << 1,
  Memory = 1 << 2,
  Bytes = 1 << 3,
  Writers = 1 << 4,
  Transaction = 1 << 5,
  MemoryKind = 1 << 6,
  Destination = 1 << 7
};

CheckResult validate_unused_fields(const difftest_s_wire_event_v1 &event, uint32_t allowed) {
  if ((!(allowed & Attempt) && event.attempt) ||
      (!(allowed & Instruction) && (event.pc || event.instruction || event.instruction_length)) ||
      (!(allowed & Memory) && (event.address || event.width || event.byte_mask)) ||
      (!(allowed & Bytes) && std::any_of(std::begin(event.bytes), std::end(event.bytes),
                                       [](uint8_t byte) { return byte != 0; })) ||
      (!(allowed & Writers) && !empty_writers(event)) ||
      (!(allowed & Transaction) && event.transaction_id) ||
      (!(allowed & MemoryKind) && event.memory_kind) ||
      (!(allowed & Destination) && (event.destination_kind || event.destination_register || event.integer_value)))
    return invalid("wire event contains fields unused by its kind");
  return {};
}

CheckResult validate_instruction(const difftest_s_wire_event_v1 &event) {
  if (event.pc % 2)
    return invalid("wire instruction PC is not parcel-aligned");
  if (event.instruction_length != 2 && event.instruction_length != 4)
    return unsupported("wire v1 only transports two- or four-byte scalar instructions");
  if ((event.instruction_length == 2 && ((event.instruction & 3) == 3 || event.instruction >> 16)) ||
      (event.instruction_length == 4 && ((event.instruction & 3) != 3 || (event.instruction & 0x1f) == 0x1f)))
    return invalid("wire instruction encoding differs from its length");
  return {};
}

CheckResult validate_memory(const difftest_s_wire_event_v1 &event, bool load) {
  if ((event.width != 1 && event.width != 2 && event.width != 4 && event.width != 8) ||
      static_cast<uint64_t>(event.width - 1) > UINT64_MAX - event.address)
    return invalid("wire scalar memory width or address range is invalid");
  const uint8_t valid_mask = static_cast<uint8_t>((1u << event.width) - 1);
  if (!event.byte_mask || (event.byte_mask & ~valid_mask) || (event.writer_known_mask & ~event.byte_mask))
    return invalid("wire byte mask or writer-known mask exceeds its scalar access");
  if (load && event.byte_mask != valid_mask)
    return invalid("wire scalar load does not provide every accessed byte");
  for (size_t byte = 0; byte < DIFFTEST_S_WIRE_MAX_BYTES; ++byte) {
    if (byte >= event.width && event.bytes[byte])
      return invalid("wire byte payload exceeds its access width");
    const bool known = (event.writer_known_mask & (1u << byte)) != 0;
    if (!known && !zero_operation(event.writers[byte]))
      return invalid("wire unknown writer carries a nonzero identity");
    if (known && !event.writers[byte].uid && !zero_operation(event.writers[byte]))
      return invalid("wire known writer is neither a dynamic UID nor the initialization writer");
  }
  return {};
}

std::vector<uint8_t> mask_bytes(const difftest_s_wire_event_v1 &event) {
  std::vector<uint8_t> mask(event.width);
  for (size_t byte = 0; byte < event.width; ++byte)
    mask[byte] = (event.byte_mask >> byte) & 1;
  return mask;
}

std::vector<uint8_t> value_bytes(const difftest_s_wire_event_v1 &event) {
  return {event.bytes, event.bytes + event.width};
}

rvwmo::MemoryOperation memory_operation(const difftest_s_wire_event_v1 &event, bool load) {
  rvwmo::MemoryOperation access;
  access.id = operation(event.id);
  access.attempt = event.attempt;
  access.address = event.address;
  access.byte_mask = mask_bytes(event);
  access.load = load;
  access.store = !load;
  return access;
}

CheckResult convert_retirement(const difftest_s_wire_event_v1 &event, rvwmo::RuntimeEvent &converted,
                               std::vector<rvwmo::ArchitecturalRetirement> &snapshots) {
  auto shape = validate_instruction(event);
  if (!shape)
    return shape;
  rvwmo::InstructionRetireEvent retirement;
  retirement.instruction.hart = event.id.hart;
  retirement.instruction.epoch = event.id.epoch;
  retirement.instruction.uid = event.id.uid;
  retirement.instruction.pc = event.pc;
  retirement.instruction.instruction = event.instruction;
  if (event.memory_kind == DIFFTEST_S_WIRE_NO_MEMORY) {
    if (event.address || event.width || event.byte_mask || event.attempt ||
        std::any_of(std::begin(event.bytes), std::end(event.bytes), [](uint8_t byte) { return byte != 0; }))
      return invalid("wire non-memory retirement carries memory fields");
  } else if (event.memory_kind == DIFFTEST_S_WIRE_LOAD || event.memory_kind == DIFFTEST_S_WIRE_STORE) {
    const bool load = event.memory_kind == DIFFTEST_S_WIRE_LOAD;
    shape = validate_memory(event, load);
    if (!shape)
      return shape;
    if (!load && (event.attempt || std::any_of(std::begin(event.bytes), std::end(event.bytes),
                                              [](uint8_t byte) { return byte != 0; })))
      return invalid("wire store retirement carries an attempt or load result");
    retirement.instruction.memory.push_back(memory_operation(event, load));
    if (load)
      retirement.loads.push_back({operation(event.id), event.attempt, value_bytes(event)});
  } else {
    return invalid("wire retirement has an unknown memory kind");
  }

  rvwmo::ArchitecturalRetirement snapshot;
  snapshot.id = operation(event.id);
  snapshot.pc = event.pc;
  snapshot.instruction = event.instruction;
  if (event.destination_kind == DIFFTEST_S_WIRE_INTEGER_DESTINATION) {
    if (!event.destination_register || event.destination_register >= 32)
      return invalid("wire integer retirement has an invalid destination register");
    snapshot.destination = rvwmo::ArchitecturalDestination::Integer;
    snapshot.destination_register = event.destination_register;
    snapshot.destination_value = event.integer_value;
  } else if (event.destination_kind == DIFFTEST_S_WIRE_UNSUPPORTED_DESTINATION) {
    return unsupported("wire retirement destination is outside scalar integer comparison");
  } else if (event.destination_kind != DIFFTEST_S_WIRE_NO_DESTINATION || event.destination_register ||
             event.integer_value) {
    return invalid("wire non-writing retirement carries an integer destination");
  }
  snapshots.push_back(snapshot);
  converted.kind = rvwmo::RuntimeEventKind::InstructionRetire;
  converted.payload = std::move(retirement);
  return {};
}

CheckResult convert_event(const difftest_s_wire_event_v1 &event, rvwmo::RuntimeEvent &converted,
                          std::vector<rvwmo::ArchitecturalRetirement> &snapshots) {
  if (event.struct_size != sizeof(event) || event.flags || event.reserved || event.reserved_words[0] ||
      event.reserved_words[1])
    return invalid("wire event has invalid size, flags or reserved fields");
  auto result = validate_source(event.source, false);
  if (!result)
    return result;
  if (event.kind == DIFFTEST_S_WIRE_TRAP || event.kind == DIFFTEST_S_WIRE_HART_DONE ||
      event.kind == DIFFTEST_S_WIRE_ATOMIC)
    return unsupported("wire trap, hart completion and atomic lifecycle are not yet implemented");
  if (!event.id.uid)
    return invalid("wire instruction or memory event has no dynamic UID");
  if (event.id.subaccess)
    return unsupported("wire v1 does not yet transport split or vector subaccesses");
  converted.producer_id = event.source.producer_id;
  converted.source = position(event.source);
  const auto id = operation(event.id);
  uint32_t allowed = 0;
  switch (event.kind) {
  case DIFFTEST_S_WIRE_ALLOCATE: allowed = Instruction; break;
  case DIFFTEST_S_WIRE_CANCEL_ATTEMPT: allowed = Attempt; break;
  case DIFFTEST_S_WIRE_SQUASH: break;
  case DIFFTEST_S_WIRE_LOCAL_STORE: allowed = Memory | Bytes; break;
  case DIFFTEST_S_WIRE_LOAD_SAMPLE: allowed = Attempt | Memory | Bytes | Writers; break;
  case DIFFTEST_S_WIRE_STORE_PUBLISH: allowed = Memory | Bytes | Writers | Transaction; break;
  case DIFFTEST_S_WIRE_RETIRE: allowed = Attempt | Instruction | Memory | Bytes | MemoryKind | Destination; break;
  default: return invalid("wire event has an unknown kind");
  }
  result = validate_unused_fields(event, allowed);
  if (!result)
    return result;

  switch (event.kind) {
  case DIFFTEST_S_WIRE_ALLOCATE:
    result = validate_instruction(event);
    if (!result)
      return result;
    converted.kind = rvwmo::RuntimeEventKind::InstructionAllocate;
    converted.payload = rvwmo::InstructionAllocateEvent{id, event.pc, event.instruction, event.instruction_length};
    return {};
  case DIFFTEST_S_WIRE_CANCEL_ATTEMPT:
    converted.kind = rvwmo::RuntimeEventKind::InstructionCancelAttempt;
    converted.payload = rvwmo::InstructionCancelAttemptEvent{id, event.attempt};
    return {};
  case DIFFTEST_S_WIRE_SQUASH:
    converted.kind = rvwmo::RuntimeEventKind::InstructionSquash;
    converted.payload = rvwmo::InstructionSquashEvent{id};
    return {};
  case DIFFTEST_S_WIRE_RETIRE:
    return convert_retirement(event, converted, snapshots);
  default: break;
  }

  const bool load = event.kind == DIFFTEST_S_WIRE_LOAD_SAMPLE;
  result = validate_memory(event, load);
  if (!result)
    return result;
  if (event.kind == DIFFTEST_S_WIRE_LOCAL_STORE) {
    converted.kind = rvwmo::RuntimeEventKind::LocalStore;
    converted.payload = rvwmo::LocalStoreEvent{id, event.address, value_bytes(event), mask_bytes(event)};
  } else if (load) {
    rvwmo::LoadSampleEvent sample;
    sample.operation = memory_operation(event, true);
    sample.actual_bytes = value_bytes(event);
    for (size_t byte = 0; byte < event.width; ++byte)
      sample.forwarded_writers.push_back((event.writer_known_mask & (1u << byte))
                                            ? std::optional<rvwmo::OperationId>{operation(event.writers[byte])}
                                            : std::nullopt);
    converted.kind = rvwmo::RuntimeEventKind::LoadSample;
    converted.payload = std::move(sample);
  } else {
    if (!event.transaction_id)
      return invalid("wire store publication has no transaction identity");
    if (event.writer_known_mask != event.byte_mask)
      return incomplete("wire store publication lacks a known writer for an enabled byte");
    rvwmo::StorePublishEvent publish;
    publish.transaction_id = event.transaction_id;
    publish.address = event.address;
    publish.bytes = value_bytes(event);
    publish.byte_mask = mask_bytes(event);
    publish.members.push_back({id, converted.source});
    for (size_t byte = 0; byte < event.width; ++byte) {
      if ((event.byte_mask & (1u << byte)) && operation(event.writers[byte]) != id)
        return unsupported("wire v1 cannot publish bytes from another or merged store");
      publish.byte_writers.push_back(operation(event.writers[byte]));
    }
    converted.kind = rvwmo::RuntimeEventKind::StorePublish;
    converted.payload = std::move(publish);
  }
  return {};
}

CheckResult convert_batch(const difftest_s_wire_ingress &ingress, const difftest_s_wire_batch_v1 *batch,
                          rvwmo::EventBatch &events, std::vector<rvwmo::ArchitecturalRetirement> &snapshots) {
  if (!batch || batch->abi_version != DIFFTEST_S_WIRE_ABI_VERSION_1 || batch->struct_size != sizeof(*batch) ||
      batch->reserved || batch->event_count > ingress.max_events || batch->watermark_count > ingress.max_watermarks ||
      (batch->event_count && !batch->events) || (batch->watermark_count && !batch->watermarks))
    return invalid("wire batch has invalid version, size, bounds, pointers or reserved fields");
  events.events.reserve(batch->event_count);
  events.watermarks.reserve(batch->watermark_count);
  for (uint32_t index = 0; index < batch->event_count; ++index) {
    rvwmo::RuntimeEvent event;
    auto result = convert_event(batch->events[index], event, snapshots);
    if (!result)
      return result;
    events.events.push_back(std::move(event));
  }
  for (uint32_t index = 0; index < batch->watermark_count; ++index) {
    const auto &watermark = batch->watermarks[index];
    if (watermark.struct_size != sizeof(watermark) || watermark.reserved)
      return invalid("wire watermark has invalid size or reserved fields");
    auto result = validate_source(watermark.closed_through, true);
    if (!result)
      return result;
    events.watermarks.push_back({watermark.closed_through.producer_id, position(watermark.closed_through)});
  }
  return {};
}

template <typename Action>
int guarded_action(difftest_s_wire_ingress *ingress, difftest_s_wire_result_v1 *result, Action action) {
  try {
    if (!valid_result(result)) {
      if (ingress)
        ingress->failure = invalid("wire result has an invalid ABI or size");
      return DIFFTEST_S_WIRE_INVALID;
    }
    if (!ingress)
      return finish(nullptr, result, invalid("wire call has no ingress"));
    if (ingress->failure)
      return finish(ingress, result, *ingress->failure);
    return action();
  } catch (...) {
    if (ingress) {
      ingress->failure.emplace();
      ingress->failure->status = CheckStatus::Incomplete;
    }
    if (!valid_result(result))
      return DIFFTEST_S_WIRE_INVALID;
    CheckResult error;
    error.status = CheckStatus::Incomplete;
    write_result(result, error, DIFFTEST_S_WIRE_NOT_SUBMITTED, false, 0);
    const char message[] = "wire ingress encountered an exception; the session cannot continue";
    std::memcpy(result->message, message, sizeof(message));
    return DIFFTEST_S_WIRE_INCOMPLETE;
  }
}
} // namespace

extern "C" {
difftest_s_wire_ingress *difftest_s_wire_create_v1(void *borrowed_observation_session,
                                                  const difftest_s_wire_limits_v1 *limits,
                                                  difftest_s_wire_result_v1 *result) {
  if (!valid_result(result))
    return nullptr;
  try {
    if (!borrowed_observation_session || !limits || limits->abi_version != DIFFTEST_S_WIRE_ABI_VERSION_1 ||
        limits->struct_size != sizeof(*limits) || !limits->max_events || !limits->max_watermarks ||
        limits->max_events > DIFFTEST_S_WIRE_MAX_BATCH_EVENTS ||
        limits->max_watermarks > DIFFTEST_S_WIRE_MAX_BATCH_WATERMARKS) {
      finish(nullptr, result, invalid("wire ingress needs a borrowed session and valid bounded limits"));
      return nullptr;
    }
    auto *ingress = new difftest_s_wire_ingress{static_cast<rvwmo::ObservationSession *>(borrowed_observation_session),
                                              limits->max_events, limits->max_watermarks, std::nullopt};
    write_result(result, {}, DIFFTEST_S_WIRE_NOT_SUBMITTED, false, 0);
    return ingress;
  } catch (...) {
    CheckResult error;
    error.status = CheckStatus::Incomplete;
    write_result(result, error, DIFFTEST_S_WIRE_NOT_SUBMITTED, false, 0);
    return nullptr;
  }
}

void difftest_s_wire_destroy(difftest_s_wire_ingress *ingress) { delete ingress; }

int difftest_s_wire_submit_v1(difftest_s_wire_ingress *ingress, const difftest_s_wire_batch_v1 *batch,
                              difftest_s_wire_result_v1 *result) {
  return guarded_action(ingress, result, [&] {
    rvwmo::EventBatch converted;
    std::vector<rvwmo::ArchitecturalRetirement> snapshots;
    auto validation = convert_batch(*ingress, batch, converted, snapshots);
    if (!validation)
      return finish(ingress, result, validation);
    const auto submitted = ingress->session->submit(converted, snapshots);
    return finish(ingress, result, submitted.check, transport_status(submitted.transport.status), submitted.accepted);
  });
}

int difftest_s_wire_poll_v1(difftest_s_wire_ingress *ingress, difftest_s_wire_result_v1 *result) {
  return guarded_action(ingress, result, [&] { return finish(ingress, result, ingress->session->poll()); });
}

int difftest_s_wire_finalize_v1(difftest_s_wire_ingress *ingress, uint64_t completed_cycle,
                                difftest_s_wire_result_v1 *result) {
  return guarded_action(ingress, result, [&] { return finish(ingress, result, ingress->session->finalize(completed_cycle)); });
}
}
