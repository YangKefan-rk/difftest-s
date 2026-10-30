// Synthetic contract tests for the shared atomic-lifecycle consumer.
//
// These tests drive CheckerEventConsumer directly (no DUT, no REF stepper) and
// cover the LinkNan-style AMO/LR/SC event shapes:
//   Begin -> Request -> ReadEffect/WriteEffect -> Response -> Finish -> retire.
// The rank resolver assigns strictly increasing ranks; the memory callbacks are
// a tiny GlobalMem. A test passes only when the consumer/checker accepts the
// complete lifecycle and finalize() succeeds.

#include "checker_event_consumer.h"

#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace rvwmo;

namespace {

std::vector<uint8_t> all_mask(size_t size) { return std::vector<uint8_t>(size, 1); }

std::vector<uint8_t> bytes_of(uint64_t value, size_t size = 8) {
  std::vector<uint8_t> bytes(size);
  for (size_t i = 0; i < size; ++i)
    bytes[i] = static_cast<uint8_t>(value >> (8 * i));
  return bytes;
}

struct Env {
  std::map<uint64_t, uint8_t> memory;
  uint64_t next_rank = 1;
  uint64_t next_cycle = 1;
  CheckerEventConsumer consumer;

  Env()
      : consumer(
            [this](uint64_t address) {
              auto found = memory.find(address);
              return found == memory.end() ? uint8_t{0} : found->second;
            },
            [this](uint64_t address, uint8_t value) { memory[address] = value; },
            [this](const RuntimeEvent &) {
              ObservationTime time;
              time.rank = next_rank++;
              time.valid = true;
              return std::optional<ObservationTime>(time);
            }) {}

  void poke(uint64_t address, uint64_t value, size_t size = 8) {
    auto bytes = bytes_of(value, size);
    for (size_t i = 0; i < size; ++i)
      memory[address + i] = bytes[i];
  }

  CheckResult send(RuntimeEventKind kind, RuntimeEventPayload payload, uint64_t cycle = 0) {
    RuntimeEvent event;
    event.producer_id = 1;
    event.source.cycle = cycle ? cycle : next_cycle++;
    event.source.qualified_phase = 1;
    event.source.producer_sequence = event.source.cycle;
    event.source.order_qualified = true;
    event.kind = kind;
    event.payload = std::move(payload);
    return consumer.consume_closed(event);
  }

  OperationId id(uint64_t uid, uint32_t hart = 0) const { return {hart, 7, uid, 0}; }

  CheckResult allocate(uint64_t uid, uint32_t instruction, uint32_t hart = 0) {
    InstructionAllocateEvent event;
    event.id = id(uid, hart);
    event.pc = 0x1000 + uid * 4;
    event.instruction = instruction;
    event.length = 4;
    return send(RuntimeEventKind::InstructionAllocate, event);
  }

  CheckResult atomic(const OperationId &id, AtomicObservationPhase phase, uint8_t fuop, uint64_t address = 0,
                     uint8_t mask = 0xff, uint64_t data = 0, uint32_t attempt = 0, bool success = false) {
    AtomicLifecycleEvent event;
    event.id = id;
    event.attempt = attempt;
    event.phase = phase;
    event.address = address;
    event.mask = mask;
    event.fuop = fuop;
    event.data = data;
    event.success = success;
    return send(RuntimeEventKind::AtomicLifecycle, event);
  }

  CheckResult retire(uint64_t uid, uint32_t instruction, const std::vector<MemoryOperation> &operations,
                     const std::vector<ActualLoadValue> &loads, bool failed_sc = false, uint32_t hart = 0) {
    InstructionRetireEvent event;
    event.instruction.hart = hart;
    event.instruction.epoch = 7;
    event.instruction.uid = uid;
    event.instruction.pc = 0x1000 + uid * 4;
    event.instruction.instruction = instruction;
    event.instruction.failed_sc = failed_sc;
    event.instruction.memory = operations;
    event.loads = loads;
    return send(RuntimeEventKind::InstructionRetire, event);
  }

  MemoryOperation operation(const OperationId &id, uint64_t address, bool load, bool store, bool atomic, bool lr,
                            bool sc) const {
    MemoryOperation op;
    op.id = id;
    op.attempt = 0;
    op.address = address;
    op.byte_mask = all_mask(8);
    op.load = load;
    op.store = store;
    op.atomic = atomic;
    op.lr = lr;
    op.sc = sc;
    return op;
  }
};

int failures = 0;

void expect(const char *name, CheckResult result, CheckStatus expected) {
  if (result.status != expected) {
    std::printf("FAIL %-45s got %d expected %d: %s\n", name, static_cast<int>(result.status),
                static_cast<int>(expected), result.message.c_str());
    ++failures;
  } else {
    std::printf("pass %-45s\n", name);
  }
}

// AMOADD.D x3, x2, (x1): funct5=0, rs2=2, rs1=1, funct3=3, rd=3, opcode=0x2f.
constexpr uint32_t kAmoAddD = 0x0020B1AF;
// LR.D x3, (x1): funct5=2, rs1=1, funct3=3, rd=3.
constexpr uint32_t kLrD = 0x1000B1AF;
// SC.D x3, x2, (x1): funct5=3, rs2=2, rs1=1, funct3=3, rd=3.
constexpr uint32_t kScD = 0x1800B1AF;
// SD x1, 0(x2): ordinary store used to establish an LR source writer.
constexpr uint32_t kStoreD = 0x00113023;

CheckResult local_store(Env &env, uint64_t uid, uint32_t hart, uint64_t address, uint64_t value) {
  LocalStoreEvent event;
  event.id = env.id(uid, hart);
  event.address = address;
  event.bytes = bytes_of(value);
  event.byte_mask = all_mask(8);
  return env.send(RuntimeEventKind::LocalStore, event);
}

CheckResult publish_store(Env &env, uint64_t uid, uint32_t hart, uint64_t address, uint64_t value) {
  const auto id = env.id(uid, hart);
  RuntimeEvent event;
  event.producer_id = 1;
  event.source.cycle = env.next_cycle++;
  event.source.qualified_phase = 1;
  event.source.producer_sequence = event.source.cycle;
  event.source.order_qualified = true;
  StorePublishEvent publish;
  publish.transaction_id = uid + 1000;
  publish.address = address;
  publish.bytes = bytes_of(value);
  publish.byte_mask = all_mask(8);
  publish.byte_writers = std::vector<OperationId>(8, id);
  publish.members.push_back(StorePublishMember{id, event.source});
  event.kind = RuntimeEventKind::StorePublish;
  event.payload = publish;
  return env.consumer.consume_closed(event);
}

void amo_success() {
  Env env;
  const uint64_t address = 0x80000000;
  const uint64_t old_value = 0x0123456789ABCDEFULL;
  const uint64_t new_value = old_value + 1;
  env.poke(address, old_value);
  auto id = env.id(1);
  expect("amo allocate", env.allocate(1, kAmoAddD), CheckStatus::Pass);
  expect("amo begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Pass);
  expect("amo request", env.atomic(id, AtomicObservationPhase::Request, 0, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("amo read", env.atomic(id, AtomicObservationPhase::ReadEffect, 0, address, 0xff, old_value, 0),
         CheckStatus::Pass);
  expect("amo write", env.atomic(id, AtomicObservationPhase::WriteEffect, 0, address, 0xff, new_value, 0),
         CheckStatus::Pass);
  expect("amo response", env.atomic(id, AtomicObservationPhase::Response, 0, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("amo finish", env.atomic(id, AtomicObservationPhase::Finish, 0), CheckStatus::Pass);
  expect("amo audit", env.consumer.audit_store(id, address, bytes_of(new_value), all_mask(8)), CheckStatus::Pass);

  auto op = env.operation(id, address, true, true, true, false, false);
  std::vector<ActualLoadValue> loads{{id, 0, bytes_of(old_value)}};
  expect("amo retire", env.retire(1, kAmoAddD, {op}, loads), CheckStatus::Pass);
  expect("amo finalize", env.consumer.finalize(), CheckStatus::Pass);
}

void sc_without_lr() {
  Env env;
  const uint64_t address = 0x80000000;
  env.poke(address, 5);
  auto id = env.id(1);
  expect("no-lr allocate", env.allocate(1, kScD), CheckStatus::Pass);
  expect("no-lr begin", env.atomic(id, AtomicObservationPhase::Begin, 6), CheckStatus::Pass);
  expect("no-lr request", env.atomic(id, AtomicObservationPhase::Request, 6, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("no-lr write", env.atomic(id, AtomicObservationPhase::WriteEffect, 6, address, 0xff, 6, 0),
         CheckStatus::Pass);
  expect("no-lr response", env.atomic(id, AtomicObservationPhase::Response, 6, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("no-lr finish", env.atomic(id, AtomicObservationPhase::Finish, 6), CheckStatus::Pass);
  expect("no-lr audit", env.consumer.audit_store(id, address, bytes_of(6), all_mask(8)), CheckStatus::Pass);
  auto op = env.operation(id, address, false, true, false, false, true);
  expect("no-lr retire", env.retire(1, kScD, {op}, {}), CheckStatus::Violation);
}

void overlapping_lifecycle() {
  Env env;
  auto id = env.id(1);
  expect("overlap allocate", env.allocate(1, kAmoAddD), CheckStatus::Pass);
  expect("overlap begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Pass);
  expect("overlap second begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Invalid);
}

void failed_sc_still_consumes() {
  Env env;
  const uint64_t address = 0x80000000;
  env.poke(address, 5);
  auto id = env.id(1);
  expect("failed-sc allocate", env.allocate(1, kScD), CheckStatus::Pass);
  expect("failed-sc begin", env.atomic(id, AtomicObservationPhase::Begin, 6), CheckStatus::Pass);
  expect("failed-sc request", env.atomic(id, AtomicObservationPhase::Request, 6, address, 0xff, 0, 0),
         CheckStatus::Pass);
  expect("failed-sc response", env.atomic(id, AtomicObservationPhase::Response, 6, address, 0xff, 0, 0, false),
         CheckStatus::Pass);
  expect("failed-sc finish", env.atomic(id, AtomicObservationPhase::Finish, 6), CheckStatus::Pass);
  auto op = env.operation(id, address, false, false, false, false, true);
  expect("failed-sc retire", env.retire(1, kScD, {op}, {}, true), CheckStatus::Pass);
  expect("failed-sc finalize", env.consumer.finalize(), CheckStatus::Pass);
}


// Set up a checked global store for `address`, returning its instruction UID.
void establish_store(Env &env, uint64_t uid, uint32_t hart, uint64_t address, uint64_t value) {
  expect("store allocate", env.allocate(uid, kStoreD, hart), CheckStatus::Pass);
  expect("store local", local_store(env, uid, hart, address, value), CheckStatus::Pass);
  expect("store publish", publish_store(env, uid, hart, address, value), CheckStatus::Pass);
  expect("store audit", env.consumer.audit_store(env.id(uid, hart), address, bytes_of(value), all_mask(8)),
         CheckStatus::Pass);
  auto op = env.operation(env.id(uid, hart), address, false, true, false, false, false);
  expect("store retire", env.retire(uid, kStoreD, {op}, {}, false, hart), CheckStatus::Pass);
}

void lr_sc_success() {
  Env env;
  const uint64_t address = 0x80000000;
  const uint64_t old_value = 0x1111222233334444ULL;
  const uint64_t new_value = old_value + 5;
  establish_store(env, 1, 0, address, old_value);

  auto lr = env.id(2);
  expect("lr allocate", env.allocate(2, kLrD), CheckStatus::Pass);
  expect("lr begin", env.atomic(lr, AtomicObservationPhase::Begin, 2), CheckStatus::Pass);
  expect("lr request", env.atomic(lr, AtomicObservationPhase::Request, 2, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("lr read", env.atomic(lr, AtomicObservationPhase::ReadEffect, 2, address, 0xff, old_value, 0),
         CheckStatus::Pass);
  expect("lr response", env.atomic(lr, AtomicObservationPhase::Response, 2, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("lr finish", env.atomic(lr, AtomicObservationPhase::Finish, 2), CheckStatus::Pass);
  auto lr_op = env.operation(lr, address, true, false, false, true, false);
  expect("lr retire", env.retire(2, kLrD, {lr_op}, {{lr, 0, bytes_of(old_value)}}), CheckStatus::Pass);

  auto sc = env.id(3);
  expect("sc allocate", env.allocate(3, kScD), CheckStatus::Pass);
  expect("sc begin", env.atomic(sc, AtomicObservationPhase::Begin, 6), CheckStatus::Pass);
  expect("sc request", env.atomic(sc, AtomicObservationPhase::Request, 6, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("sc write", env.atomic(sc, AtomicObservationPhase::WriteEffect, 6, address, 0xff, new_value, 0),
         CheckStatus::Pass);
  expect("sc response", env.atomic(sc, AtomicObservationPhase::Response, 6, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("sc finish", env.atomic(sc, AtomicObservationPhase::Finish, 6), CheckStatus::Pass);
  expect("sc audit", env.consumer.audit_store(sc, address, bytes_of(new_value), all_mask(8)), CheckStatus::Pass);
  auto sc_op = env.operation(sc, address, false, true, false, false, true);
  expect("sc retire", env.retire(3, kScD, {sc_op}, {}), CheckStatus::Pass);
  expect("lr/sc finalize", env.consumer.finalize(), CheckStatus::Pass);
}

void sc_after_remote_write() {
  Env env;
  const uint64_t address = 0x80000000;
  const uint64_t old_value = 0x1111222233334444ULL;
  establish_store(env, 1, 0, address, old_value);

  auto lr = env.id(2);
  expect("rw lr allocate", env.allocate(2, kLrD), CheckStatus::Pass);
  expect("rw lr begin", env.atomic(lr, AtomicObservationPhase::Begin, 2), CheckStatus::Pass);
  expect("rw lr request", env.atomic(lr, AtomicObservationPhase::Request, 2, address, 0xff, 0, 0),
         CheckStatus::Pass);
  expect("rw lr read", env.atomic(lr, AtomicObservationPhase::ReadEffect, 2, address, 0xff, old_value, 0),
         CheckStatus::Pass);
  expect("rw lr response", env.atomic(lr, AtomicObservationPhase::Response, 2, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("rw lr finish", env.atomic(lr, AtomicObservationPhase::Finish, 2), CheckStatus::Pass);
  auto lr_op = env.operation(lr, address, true, false, false, true, false);
  expect("rw lr retire", env.retire(2, kLrD, {lr_op}, {{lr, 0, bytes_of(old_value)}}), CheckStatus::Pass);

  // A second hart publishes an intervening write between LR and SC.
  expect("rw remote allocate", env.allocate(1, kStoreD, 1), CheckStatus::Pass);
  expect("rw remote local", local_store(env, 1, 1, address, 0x7777777777777777ULL), CheckStatus::Pass);
  expect("rw remote publish", publish_store(env, 1, 1, address, 0x7777777777777777ULL), CheckStatus::Pass);

  auto sc = env.id(3);
  expect("rw sc allocate", env.allocate(3, kScD), CheckStatus::Pass);
  expect("rw sc begin", env.atomic(sc, AtomicObservationPhase::Begin, 6), CheckStatus::Pass);
  expect("rw sc request", env.atomic(sc, AtomicObservationPhase::Request, 6, address, 0xff, 0, 0),
         CheckStatus::Pass);
  expect("rw sc write", env.atomic(sc, AtomicObservationPhase::WriteEffect, 6, address, 0xff, 0x8888888888888888ULL, 0),
         CheckStatus::Pass);
  expect("rw sc response", env.atomic(sc, AtomicObservationPhase::Response, 6, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("rw sc finish", env.atomic(sc, AtomicObservationPhase::Finish, 6), CheckStatus::Pass);
  expect("rw sc audit", env.consumer.audit_store(sc, address, bytes_of(0x8888888888888888ULL), all_mask(8)),
         CheckStatus::Pass);
  auto sc_op = env.operation(sc, address, false, true, false, false, true);
  expect("rw sc retire", env.retire(3, kScD, {sc_op}, {}), CheckStatus::Violation);
}

void sc_different_address() {
  Env env;
  const uint64_t lr_address = 0x80000000;
  const uint64_t sc_address = 0x80000040;
  const uint64_t old_value = 0x1111222233334444ULL;
  establish_store(env, 1, 0, lr_address, old_value);

  auto lr = env.id(2);
  expect("da lr allocate", env.allocate(2, kLrD), CheckStatus::Pass);
  expect("da lr begin", env.atomic(lr, AtomicObservationPhase::Begin, 2), CheckStatus::Pass);
  expect("da lr request", env.atomic(lr, AtomicObservationPhase::Request, 2, lr_address, 0xff, 0, 0),
         CheckStatus::Pass);
  expect("da lr read", env.atomic(lr, AtomicObservationPhase::ReadEffect, 2, lr_address, 0xff, old_value, 0),
         CheckStatus::Pass);
  expect("da lr response", env.atomic(lr, AtomicObservationPhase::Response, 2, lr_address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("da lr finish", env.atomic(lr, AtomicObservationPhase::Finish, 2), CheckStatus::Pass);
  auto lr_op = env.operation(lr, lr_address, true, false, false, true, false);
  expect("da lr retire", env.retire(2, kLrD, {lr_op}, {{lr, 0, bytes_of(old_value)}}), CheckStatus::Pass);

  env.poke(sc_address, 0x2222333344445555ULL);
  auto sc = env.id(3);
  expect("da sc allocate", env.allocate(3, kScD), CheckStatus::Pass);
  expect("da sc begin", env.atomic(sc, AtomicObservationPhase::Begin, 6), CheckStatus::Pass);
  expect("da sc request", env.atomic(sc, AtomicObservationPhase::Request, 6, sc_address, 0xff, 0, 0),
         CheckStatus::Pass);
  expect("da sc write", env.atomic(sc, AtomicObservationPhase::WriteEffect, 6, sc_address, 0xff,
                                   0x3333444455556666ULL, 0),
         CheckStatus::Pass);
  expect("da sc response", env.atomic(sc, AtomicObservationPhase::Response, 6, sc_address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("da sc finish", env.atomic(sc, AtomicObservationPhase::Finish, 6), CheckStatus::Pass);
  expect("da sc audit", env.consumer.audit_store(sc, sc_address, bytes_of(0x3333444455556666ULL), all_mask(8)),
         CheckStatus::Pass);
  auto sc_op = env.operation(sc, sc_address, false, true, false, false, true);
  expect("da sc retire", env.retire(3, kScD, {sc_op}, {}), CheckStatus::Unsupported);
}

void amo_old_value_mismatch() {
  Env env;
  const uint64_t address = 0x80000000;
  const uint64_t old_value = 0x0123456789ABCDEFULL;
  env.poke(address, old_value);
  auto id = env.id(1);
  expect("mm allocate", env.allocate(1, kAmoAddD), CheckStatus::Pass);
  expect("mm begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Pass);
  expect("mm request", env.atomic(id, AtomicObservationPhase::Request, 0, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("mm read", env.atomic(id, AtomicObservationPhase::ReadEffect, 0, address, 0xff, old_value, 0),
         CheckStatus::Pass);
  expect("mm write", env.atomic(id, AtomicObservationPhase::WriteEffect, 0, address, 0xff, old_value + 1, 0),
         CheckStatus::Pass);
  expect("mm response", env.atomic(id, AtomicObservationPhase::Response, 0, address, 0xff, 0, 0, true),
         CheckStatus::Pass);
  expect("mm finish", env.atomic(id, AtomicObservationPhase::Finish, 0), CheckStatus::Pass);
  expect("mm audit", env.consumer.audit_store(id, address, bytes_of(old_value + 1), all_mask(8)),
         CheckStatus::Pass);
  auto op = env.operation(id, address, true, true, true, false, false);
  // The retirement claims a different old value than the sampled read effect.
  expect("mm retire", env.retire(1, kAmoAddD, {op}, {{id, 0, bytes_of(old_value + 2)}}), CheckStatus::Violation);
}

void atomic_replay() {
  Env env;
  const uint64_t address = 0x80000000;
  const uint64_t old_value = 0xABCDEF0123456789ULL;
  env.poke(address, old_value);
  auto id = env.id(1);
  expect("rp allocate", env.allocate(1, kAmoAddD), CheckStatus::Pass);
  expect("rp begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Pass);
  expect("rp request0", env.atomic(id, AtomicObservationPhase::Request, 0, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("rp replay", env.atomic(id, AtomicObservationPhase::Replay, 0), CheckStatus::Pass);
  expect("rp request1", env.atomic(id, AtomicObservationPhase::Request, 0, address, 0xff, 1, 1), CheckStatus::Pass);
  expect("rp read1", env.atomic(id, AtomicObservationPhase::ReadEffect, 0, address, 0xff, old_value, 1),
         CheckStatus::Pass);
  expect("rp write1", env.atomic(id, AtomicObservationPhase::WriteEffect, 0, address, 0xff, old_value + 1, 1),
         CheckStatus::Pass);
  expect("rp response1", env.atomic(id, AtomicObservationPhase::Response, 0, address, 0xff, 0, 1, true),
         CheckStatus::Pass);
  expect("rp finish1", env.atomic(id, AtomicObservationPhase::Finish, 0, address, 0xff, 0, 1),
         CheckStatus::Pass);
  expect("rp audit", env.consumer.audit_store(id, address, bytes_of(old_value + 1), all_mask(8)),
         CheckStatus::Pass);
  auto op = env.operation(id, address, true, true, true, false, false);
  op.attempt = 1;
  expect("rp retire", env.retire(1, kAmoAddD, {op}, {{id, 1, bytes_of(old_value)}}), CheckStatus::Pass);
  expect("rp finalize", env.consumer.finalize(), CheckStatus::Pass);
}

void word_lane_amo() {
  Env env;
  const uint64_t address = 0x80000000;
  const uint64_t old_value = 0xAABBCCDDULL;
  env.poke(address, old_value);
  auto id = env.id(1);
  expect("wl allocate", env.allocate(1, kAmoAddD), CheckStatus::Pass);
  expect("wl begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Pass);
  expect("wl request", env.atomic(id, AtomicObservationPhase::Request, 0, address, 0x0f, 0, 0), CheckStatus::Pass);
  expect("wl read", env.atomic(id, AtomicObservationPhase::ReadEffect, 0, address, 0x0f, old_value, 0),
         CheckStatus::Pass);
  expect("wl write", env.atomic(id, AtomicObservationPhase::WriteEffect, 0, address, 0x0f, old_value + 1, 0),
         CheckStatus::Pass);
  expect("wl response", env.atomic(id, AtomicObservationPhase::Response, 0, address, 0x0f, 0, 0, true),
         CheckStatus::Pass);
  expect("wl finish", env.atomic(id, AtomicObservationPhase::Finish, 0), CheckStatus::Pass);
  const std::vector<uint8_t> lane{1, 1, 1, 1, 0, 0, 0, 0};
  expect("wl audit", env.consumer.audit_store(id, address, bytes_of(old_value + 1), lane), CheckStatus::Pass);
  auto op = env.operation(id, address, true, true, true, false, false);
  op.byte_mask = lane;
  expect("wl retire", env.retire(1, kAmoAddD, {op}, {{id, 0, bytes_of(old_value)}}), CheckStatus::Pass);
  expect("wl finalize", env.consumer.finalize(), CheckStatus::Pass);
}

void cancel_after_read() {
  Env env;
  const uint64_t address = 0x80000000;
  auto id = env.id(1);
  expect("cx allocate", env.allocate(1, kAmoAddD), CheckStatus::Pass);
  expect("cx begin", env.atomic(id, AtomicObservationPhase::Begin, 0), CheckStatus::Pass);
  expect("cx request", env.atomic(id, AtomicObservationPhase::Request, 0, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("cx read", env.atomic(id, AtomicObservationPhase::ReadEffect, 0, address, 0xff, 1, 0), CheckStatus::Pass);
  expect("cx cancel", env.atomic(id, AtomicObservationPhase::Cancel, 0), CheckStatus::Invalid);
}

void sc_response_disagrees() {
  Env env;
  const uint64_t address = 0x80000000;
  auto id = env.id(1);
  expect("sd allocate", env.allocate(1, kScD), CheckStatus::Pass);
  expect("sd begin", env.atomic(id, AtomicObservationPhase::Begin, 6), CheckStatus::Pass);
  expect("sd request", env.atomic(id, AtomicObservationPhase::Request, 6, address, 0xff, 0, 0), CheckStatus::Pass);
  expect("sd write", env.atomic(id, AtomicObservationPhase::WriteEffect, 6, address, 0xff, 1, 0), CheckStatus::Pass);
  expect("sd response", env.atomic(id, AtomicObservationPhase::Response, 6, address, 0xff, 0, 0, false),
         CheckStatus::Invalid);
}

} // namespace

int main() {
  amo_success();
  sc_without_lr();
  overlapping_lifecycle();
  failed_sc_still_consumes();
  lr_sc_success();
  sc_after_remote_write();
  sc_different_address();
  amo_old_value_mismatch();
  atomic_replay();
  word_lane_amo();
  cancel_after_read();
  sc_response_disagrees();
  std::printf("%s (%d failures)\n", failures ? "FAILED" : "OK", failures);
  return failures ? 1 : 0;
}
