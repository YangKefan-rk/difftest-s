#ifndef DIFFTEST_ROCKET_NATIVE_ADAPTER_H
#define DIFFTEST_ROCKET_NATIVE_ADAPTER_H

#include "cache_tracker.h"
#include "retirement_capture.h"
#include "../../rvwmo/session.h"

namespace rocket_difftest {

struct NativeConfiguration {
  EmitterConfiguration emitter;
  CacheConfiguration cache;
};

// consumed distinguishes retained asynchronous facts from caller-owned retry.
struct CaptureResult {
  rvwmo::CheckResult check;
  bool consumed = false;
};

struct NativeRetireFact {
  NativeRetirement retirement;
  // Same real WB cycle; separate hart-producer ordinal before retirement.
  rvwmo::SourcePosition local_store_source;
};

struct QualifiedStorePublication {
  CacheStoreValue actual;
  uint64_t transaction = 0;
};

struct NativeOutput {
  uint64_t serial = 0;
  rvwmo::EventBatch batch;
  std::vector<rvwmo::ArchitecturalRetirement> retirements;
};

// One hart's private native join. It neither decodes a shared RTL frame nor
// owns a Runtime, REF, fabric watermark, phase qualification or memory rank.
class NativeAdapter {
public:
  explicit NativeAdapter(NativeConfiguration configuration);
  CaptureResult allocate(const InstructionObservation &instruction);
  CaptureResult bind_request(const CoreRequest &core, const CacheRequest &cache);
  CaptureResult cancel_request(uint64_t request_id);
  CaptureResult sample_load(const CacheLoadResult &load);
  CaptureResult accept_store(const CacheStoreValue &store);
  CaptureResult retire(const NativeRetireFact &fact);
  CaptureResult late_write(const NativeLateWrite &write);
  CaptureResult squash(uint64_t token);
  // The caller proves publication; a raw SRAM drain alone is insufficient.
  CaptureResult publish(const QualifiedStorePublication &publication);
  rvwmo::CheckResult poll();
  rvwmo::CheckResult close_hart_prefix(uint64_t cycle);
  const NativeOutput *output() const;
  rvwmo::CheckResult acknowledge_output(uint64_t serial);
  rvwmo::CheckResult finalize() const;

private:
  struct Instruction {
    InstructionObservation allocation;
    rvwmo::OperationId id;
    std::optional<NativeRetireFact> retirement;
    std::optional<uint64_t> request;
    std::optional<NativeLateWrite> late_write;
    uint32_t next_attempt = 0;
    bool local_store_done = false;
    bool semantic_retire_done = false;
    bool snapshot_done = false;
    bool publication_done = false;
  };
  struct Request {
    CoreRequest core;
    bool sampled = false;
    bool store_accepted = false;
    std::optional<QualifiedStorePublication> publication;
  };

  NativeConfiguration configuration_;
  EventEmitter emitter_;
  CacheTracker cache_;
  RetirementCapture capture_;
  std::map<uint64_t, Instruction> instructions_;
  std::map<uint64_t, Request> requests_;
  std::map<uint64_t, uint64_t> tokens_by_uid_;
  std::set<uint64_t> pending_retirements_;
  std::set<uint64_t> pending_publications_;
  NativeOutput output_;
  uint64_t next_output_serial_ = 1;
  rvwmo::CheckResult failure_;

  rvwmo::CheckResult remember(rvwmo::CheckResult result);
  CaptureResult finish_input(rvwmo::CheckResult result);
  rvwmo::CheckResult flush_retirements();
  rvwmo::CheckResult flush_publications();
  void collect_output();
  void collect_instruction(uint64_t token);
};

} // namespace rocket_difftest
#endif
