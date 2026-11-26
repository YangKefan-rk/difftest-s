#ifndef DIFFTEST_RVWMO_UC_BRIDGE_H
#define DIFFTEST_RVWMO_UC_BRIDGE_H

#include "event.h"
#include "uc_raw_abi.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <tuple>
#include <vector>

namespace rvwmo {

struct UcRawProducer {
  uint64_t name_space = 0;
  uint64_t hart = 0;
  uint64_t source_id = 0;
  uint64_t role = 0;
  bool operator==(const UcRawProducer &other) const;
  bool operator<(const UcRawProducer &other) const;
};

struct UcRawPosition {
  UcRawProducer producer;
  uint64_t epoch = 0;
  uint64_t sequence = 0;
  uint64_t cycle = 0;
  uint64_t edge = 0;
  bool operator==(const UcRawPosition &other) const;
};

struct UcTransactionKey {
  uint64_t epoch = 0;
  unsigned hart = 0;
  uint64_t transaction_uid = 0;
  bool operator==(const UcTransactionKey &other) const;
  bool operator<(const UcTransactionKey &other) const;
};

struct UcBoundRequest {
  UcTransactionKey key;
  OperationId allocation;
  uint16_t robidx = 0;
  uint64_t store_uid = 0;
  uint64_t entry_id = 0;
  bool write = false;
  uint64_t address = 0;
  uint8_t mask = 0;
  std::array<uint8_t, 8> bytes{};
  UcRawPosition source;
  bool device = false;
  bool nc = false;
  // Raw load req.nc is DontCare in this model. False means no NC claim.
  bool nc_valid = false;
};

struct UcRouteProof {
  UcRawPosition core_bus, mmio_accept, axi_issue, endpoint_accept, endpoint_effect;
  UcRawPosition endpoint_response, core_grant;
  uint64_t mmio_entry = 0, mmio_generation = 0;
  uint64_t chi_src = 0, chi_txn = 0;
  uint64_t axi_slot = 0, axi_generation = 0, axi_id = 0, endpoint_uid = 0;
};

struct UcJoinedEffect {
  UcBoundRequest request;
  UcRouteProof proof;
  std::array<uint8_t, 8> bytes{};
  uint64_t sample_cycle = 0;
  uint64_t sample_edge = 0;
};

struct UcRawWatermark {
  UcRawProducer producer;
  uint64_t epoch = 0;
  uint64_t event_sequence = 0;
  std::optional<uint64_t> closed_through;
  bool reset_verified = false;
};

enum class UcBridgeLayout { LegacyNc41, PmaLite17 };

struct UcBridgeConfig {
  bool enabled = false;
  // A new build must pin shared SimTop.soc.observationCycle and root edges.
  bool common_clock_verified = false;
  unsigned harts = 4;
  uint64_t epoch = 1;
  std::vector<UcRawProducer> producers;
  size_t max_pending_transactions = 1024;
  size_t max_pending_records = 16384;
  size_t max_event_positions = 100000;
  UcBridgeLayout layout = UcBridgeLayout::LegacyNc41;
  // Required by PmaLite17: independently initialized absolute RAM pages.
  std::vector<uint64_t> zero_pages;
};

struct UcBridgeState {
  CheckResult status;
  bool catalog_complete = false;
  std::optional<uint64_t> raw_closed_through;
  std::optional<uint64_t> fully_joined_closed_through;
  size_t pending_records = 0;
  size_t pending_transactions = 0;
  size_t pending_prefixes = 0;
  size_t unacknowledged_requests = 0;
  size_t unacknowledged_effects = 0;
  size_t expected_producers = 0;
};

using UcAllocationResolver = std::function<CheckResult(unsigned hart, uint16_t robidx,
                                                     uint64_t store_uid, bool write,
                                                     OperationId &allocation)>;
using UcBoundRequestSink = std::function<CheckResult(const UcBoundRequest &)>;
using UcJoinedEffectSink = std::function<CheckResult(const UcJoinedEffect &)>;

// An independent external-source boundary and bounded identity join. Never
// mutates the legacy SourceBoundary or calls an allocation resolver from DPI.
class UcBridge {
public:
  explicit UcBridge(UcBridgeConfig config);
  ~UcBridge();
  UcBridge(UcBridge &&) noexcept;
  UcBridge &operator=(UcBridge &&) noexcept;
  UcBridge(const UcBridge &) = delete;
  UcBridge &operator=(const UcBridge &) = delete;

  CheckResult ingest(const SfuzzUcRawRecord &record);
  // Invoke after capturing ROB allocations and local stores. Only phase-1
  // requests with exact current per-hart MemoryTime frames may resolve ROB.
  CheckResult bind_frame(const std::vector<uint64_t> &frame_cycles,
                         const UcAllocationResolver &resolve);
  CheckResult drain_requests(const UcBoundRequestSink &sink);
  // A successful sink acknowledges the actual memory effect, not completion
  // of its instruction. PMA Lite RAM may arrive before response/core grant;
  // those proof positions remain empty until validate_qualified_effect passes.
  CheckResult drain_effects(const UcJoinedEffectSink &sink);
  CheckResult poll();
  UcBridgeState snapshot() const;
  std::vector<UcRawWatermark> producer_watermarks() const;
  CheckResult validate_position(const UcRawPosition &position) const;
  CheckResult validate_memory_effect(const UcTransactionKey &transaction,
                                     const UcRawPosition &position) const;
  // A matching memory-ready effect remains Pending until the successful
  // response and returned core bytes complete the proof.
  CheckResult validate_qualified_effect(const UcTransactionKey &transaction,
                                        const UcRawPosition &position) const;
  CheckResult finish() const;
  // No returned value means one participating boundary has not yet closed.
  std::optional<uint64_t> effective_watermark(std::optional<uint64_t> legacy_closed) const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace rvwmo

#endif
