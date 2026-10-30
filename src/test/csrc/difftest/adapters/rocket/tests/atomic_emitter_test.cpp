// Rocket EventEmitter atomic contract test: an Atomic instruction accepts the
// canonical AMO lifecycle and converts retirement to an atomic operation.

#include "../event_emitter.h"
#include "producer_ids.h"

#include <cstdint>
#include <cstdio>
#include <vector>

using namespace rvwmo;
using namespace rocket_difftest;

namespace {
int failures = 0;

void expect(const char *name, CheckResult result) {
  if (result.status != CheckStatus::Pass) {
    std::printf("FAIL %-42s: %s\n", name, result.message.c_str());
    ++failures;
  } else {
    std::printf("pass %-42s\n", name);
  }
}

SourcePosition position(uint64_t sequence) { return {sequence, 0, sequence, false}; }

constexpr uint32_t kAmoAddD = 0x0020B1AF;
} // namespace

int main() {
  EmitterConfiguration configuration;
  configuration.hart = 0;
  configuration.producer = hart_producer_id(0);
  configuration.epoch = 7;
  configuration.capacity = 64;
  EventEmitter emitter(configuration);

  InstructionObservation allocation;
  allocation.token = 1;
  allocation.pc = 0x1000;
  allocation.instruction = kAmoAddD;
  allocation.length = 4;
  allocation.memory = true;
  allocation.source = position(1);
  OperationId id;
  expect("begin atomic instruction", emitter.begin(allocation, id));

  const uint64_t old_value = 0x0123456789ABCDEFULL;
  AtomicLifecycleEvent event;
  event.id = id;
  event.attempt = 0;
  event.fuop = 0;
  event.address = 0x80000000;
  event.mask = 0xff;
  event.phase = AtomicObservationPhase::Begin;
  expect("atomic begin", emitter.atomic(1, event, position(2)));
  event.phase = AtomicObservationPhase::Request;
  expect("atomic request", emitter.atomic(1, event, position(3)));
  event.phase = AtomicObservationPhase::ReadEffect;
  event.data = old_value;
  expect("atomic read", emitter.atomic(1, event, position(4)));
  event.phase = AtomicObservationPhase::WriteEffect;
  event.data = old_value + 1;
  expect("atomic write", emitter.atomic(1, event, position(5)));
  event.phase = AtomicObservationPhase::Response;
  event.success = true;
  expect("atomic response", emitter.atomic(1, event, position(6)));
  event.phase = AtomicObservationPhase::Finish;
  expect("atomic finish", emitter.atomic(1, event, position(7)));
  expect("atomic retire", emitter.retire(1, position(8)));

  auto batch = emitter.take_batch();
  if (batch.events.size() != 8) {
    std::printf("FAIL batch event count %zu expected 8\n", batch.events.size());
    ++failures;
  } else {
    std::printf("pass batch event count\n");
  }
  if (!batch.events.empty() && batch.events.back().kind == RuntimeEventKind::InstructionRetire) {
    const auto &retire = std::get<InstructionRetireEvent>(batch.events.back().payload);
    if (retire.instruction.memory.size() != 1 || retire.loads.size() != 1) {
      std::printf("FAIL retirement memory/load count\n");
      ++failures;
    } else {
      const auto &op = retire.instruction.memory.front();
      const bool shape = op.atomic && op.load && op.store && !op.lr && !op.sc;
      const auto &bytes = retire.loads.front().bytes;
      const bool value = bytes.size() == 8 && bytes == [&] {
        std::vector<uint8_t> expected(8);
        for (unsigned i = 0; i < 8; ++i)
          expected[i] = static_cast<uint8_t>(old_value >> (8 * i));
        return expected;
      }();
      if (!shape || !value) {
        std::printf("FAIL retirement AMO shape or actual bytes\n");
        ++failures;
      } else {
        std::printf("pass retirement AMO shape and actual bytes\n");
      }
    }
  } else {
    std::printf("FAIL batch does not end in retirement\n");
    ++failures;
  }

  std::printf("%s (%d failures)\n", failures ? "FAILED" : "OK", failures);
  return failures ? 1 : 0;
}
