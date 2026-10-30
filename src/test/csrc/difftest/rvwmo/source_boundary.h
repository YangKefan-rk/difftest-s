#ifndef DIFFTEST_RVWMO_SOURCE_BOUNDARY_H
#define DIFFTEST_RVWMO_SOURCE_BOUNDARY_H

#include "event.h"
#include <deque>
#include <map>
#include <mutex>

namespace rvwmo {

struct SourceEventDelivery {
  unsigned hart;
  unsigned producer;
  unsigned kind;
  unsigned lane;
  uint64_t sequence;
  uint64_t timestamp;
};

struct SourcePrefixDelivery {
  unsigned hart;
  unsigned producer;
  unsigned kind;
  unsigned lane;
  unsigned contract;
  unsigned delay_edges;
  uint64_t source_cycle;
  uint64_t closed_through;
  uint64_t produced_count;
  uint64_t sequence;
};

struct SourceResetDelivery {
  unsigned hart;
  bool asserted;
  uint64_t source_cycle;
  uint64_t sequence;
};

struct SourceBoundaryState {
  CheckResult status;
  std::optional<uint64_t> closed_through;
  size_t pending_prefixes = 0;
  size_t observed_producers = 0;
  size_t expected_producers = 0;
  bool catalog_complete = false;
};

// A producer's heartbeat closes a source-time prefix only after all events
// counted by that heartbeat have actually arrived. Callback order across
// different producers never establishes memory order.
class SourceBoundary {
public:
  void reset(unsigned harts, unsigned producers_per_hart);
  void receive(const SourceEventDelivery &event);
  void receive(const SourcePrefixDelivery &prefix);
  void receive(const SourceResetDelivery &reset);
  SourceBoundaryState snapshot() const;

private:
  struct Prefix {
    uint64_t closed_through;
    uint64_t produced_count;
  };
  struct Producer {
    unsigned kind = 0;
    unsigned lane = 0;
    uint64_t event_sequence = 0;
    uint64_t prefix_sequence = 0;
    uint64_t last_source_cycle = 0;
    uint64_t last_prefix_closed = 0;
    uint64_t last_produced_count = 0;
    std::optional<uint64_t> closed_through;
    std::deque<Prefix> pending;
  };
  struct ResetState {
    uint64_t sequence = 0;
    uint64_t source_cycle = 0;
    bool ever_active = false;
    std::optional<uint64_t> startup_closed;
  };
  mutable std::mutex mutex_;
  unsigned harts_ = 0;
  unsigned producers_per_hart_ = 0;
  std::map<std::pair<unsigned, unsigned>, Producer> producers_;
  CheckResult failure_;
  std::vector<ResetState> resets_;
  Producer *producer(unsigned hart, unsigned id, unsigned kind, unsigned lane);
  void fail(CheckStatus status, const std::string &message);
  static void advance(Producer &producer);
};

SourceBoundary &source_boundary();

} // namespace rvwmo

extern "C" void difftest_rvwmo_source_event(unsigned hart, unsigned producer, unsigned kind, unsigned lane,
                                            uint64_t sequence, uint64_t timestamp);
extern "C" void difftest_rvwmo_source_reset(unsigned hart, unsigned asserted, uint64_t source_cycle,
                                            uint64_t sequence);
extern "C" void difftest_rvwmo_source_prefix(unsigned hart, unsigned producer, unsigned kind, unsigned lane,
                                             unsigned contract, unsigned delay_edges, uint64_t source_cycle,
                                             uint64_t closed_through, uint64_t produced_count, uint64_t sequence);
#endif
