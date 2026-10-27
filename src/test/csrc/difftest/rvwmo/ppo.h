#ifndef DIFFTEST_RVWMO_PPO_H
#define DIFFTEST_RVWMO_PPO_H
#include "dependency.h"
#include <array>
#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace rvwmo {

// Consumes final architectural attempts in each hart's retirement order.
// retire() retains the complete-timestamp contract. retire_deferred() also
// accepts ordinary stores before publication, retaining their ordering duties.
class PpoChecker {
public:
  CheckResult retire(const RetiredInstruction &instruction);
  CheckResult retire_deferred(const RetiredInstruction &instruction);
  CheckResult observe_store(const OperationId &store, ObservationTime time);
  // The caller certifies a closed source prefix in which this store has not
  // published. This is a strict order fact, not a substitute publication time.
  CheckResult observe_store_after(const OperationId &store, ObservationTime earlier);
  CheckResult finalize() const;
  void reset_hart(uint32_t hart, uint64_t epoch);
  void release_writer(const OperationId &writer);
  bool has_pending_reference(const OperationId &writer) const;
  size_t pending_store_count() const;
  size_t address_count() const;

private:
  struct StoreTime {
    OperationId id;
    ObservationTime time;
    std::optional<ObservationTime> after;
  };
  // Known predecessors need only their greatest rank. Unknown store times
  // remain shared tokens; resolving a token never replays retired instructions.
  struct OrderSummary {
    DependencySummary known;
    std::map<OperationId, std::shared_ptr<StoreTime>> stores;
    void normalize();
    void include(const DependencySummary &other);
    void include(OrderSummary other);
  };
  struct OrderPoint {
    OperationId id;
    ObservationTime time;
    bool ordinary_load = false;
    bool ordinary_store = false;
  };
  struct UpperBound {
    OrderPoint after;
  };
  struct PendingStore {
    std::shared_ptr<StoreTime> clock;
    // Keep a diagnostic witness for each rule. Long streams of later loads
    // tighten these bounds rather than retaining one constraint per load.
    std::array<DependencySummary, 14> lower;
    std::array<std::optional<UpperBound>, 14> upper;
  };
  struct Constraint {
    DependencySummary known_before;
    std::optional<OperationId> pending_before;
    OrderPoint after;
    unsigned rule = 0;
  };
  using StorePair = std::pair<OperationId, OperationId>;
  struct ReadSummary {
    OperationId writer;
    DependencySummary time;
  };
  struct ByteState {
    OrderSummary access;
    std::array<ReadSummary, 2> reads;
  };
  struct HartState {
    uint64_t epoch = 0;
    uint64_t last_uid = 0;
    bool has_retired = false;
    bool pending = false;
    uint64_t pending_uid = 0;
    DependencyTracker dependencies;
    OrderSummary all, writes, fence_read, fence_write;
    DependencySummary reads, acquire, rcsc, control, address_prefix;
    std::map<uint64_t, ByteState> bytes;
    std::map<OperationId, DependencySummary> store_dependencies;
    std::map<OperationId, DependencySummary> reservation_reads;
    std::map<OperationId, PendingStore> pending_stores;
    // A bit per rule merges repeated obligations between the same two stores.
    std::map<StorePair, uint16_t> pending_edges;
  };
  static constexpr size_t max_pending_stores = 65536;
  static constexpr size_t max_pending_edges = 262144;
  std::map<uint32_t, HartState> harts_;
  static OrderPoint point(const MemoryOperation &operation);
  static CheckResult compare(const DependencySummary &before, const OrderPoint &after, unsigned rule);
  static bool unordered(const OrderPoint &point);
  static CheckResult check_certified_after(const StoreTime &store, const OrderPoint &after, unsigned rule);
  static void tighten_upper(PendingStore &store, const OrderPoint &after, unsigned rule);
  static CheckResult require_before(OrderSummary before, const OrderPoint &after, unsigned rule,
                                    std::vector<Constraint> &constraints);
  static CheckResult require_before(const DependencySummary &before, const OrderPoint &after, unsigned rule,
                                    std::vector<Constraint> &constraints);
  CheckResult retire_instruction(const RetiredInstruction &instruction, bool allow_deferred_store);
  CheckResult check_operation(HartState &hart, const MemoryOperation &operation, const DependencyMetadata &metadata,
                              std::vector<Constraint> &constraints);
  CheckResult validate_constraints(const HartState &hart, const std::vector<Constraint> &constraints) const;
  static void apply_constraints(HartState &hart, const std::vector<Constraint> &constraints);
  void update_operation(HartState &hart, const MemoryOperation &operation, const DependencyMetadata &metadata);
};
} // namespace rvwmo
#endif
