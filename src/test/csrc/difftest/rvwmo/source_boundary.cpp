#include "source_boundary.h"
#include <algorithm>
#include <limits>

namespace rvwmo {
namespace {
constexpr size_t max_pending_prefixes = 4096;
constexpr unsigned max_harts = 4096;
constexpr unsigned max_producers_per_hart = 256;
} // namespace

void SourceBoundary::reset(unsigned harts, unsigned producers_per_hart) {
  std::lock_guard<std::mutex> lock(mutex_);
  harts_ = harts;
  producers_per_hart_ = producers_per_hart;
  producers_.clear();
  resets_.assign(harts <= max_harts ? harts : 0, ResetState{});
  failure_ = {};
  if (!harts || harts > max_harts || producers_per_hart > max_producers_per_hart)
    fail(CheckStatus::Invalid, "source producer catalog exceeds its configured bounds");
}

void SourceBoundary::fail(CheckStatus status, const std::string &message) {
  if (failure_)
    failure_ = {status, 0, message};
}

SourceBoundary::Producer *SourceBoundary::producer(unsigned hart, unsigned id, unsigned kind, unsigned lane) {
  if (hart >= harts_ || id >= producers_per_hart_ || kind < 1 || kind > 8 || lane >= 256) {
    fail(CheckStatus::Invalid, "source event or prefix has an unregistered producer identity");
    return nullptr;
  }
  auto &source = producers_[{hart, id}];
  if (source.kind && (source.kind != kind || source.lane != lane)) {
    fail(CheckStatus::Invalid, "source producer identity changed kind or lane");
    return nullptr;
  }
  resets_[hart].ever_active = true;
  source.kind = kind;
  source.lane = lane;
  return &source;
}

void SourceBoundary::advance(Producer &source) {
  while (!source.pending.empty() && source.pending.front().produced_count <= source.event_sequence) {
    source.closed_through = source.pending.front().closed_through;
    source.pending.pop_front();
  }
}

void SourceBoundary::receive(const SourceEventDelivery &event) {
  std::lock_guard<std::mutex> lock(mutex_);
  // Unqualified older builds leave sourceSequence zero and publish no catalog.
  // They cannot obtain a certified closed prefix from this observer.
  if (!producers_per_hart_ || !failure_)
    return;
  auto *source = producer(event.hart, event.producer, event.kind, event.lane);
  if (!source)
    return;
  if (source->event_sequence == std::numeric_limits<uint64_t>::max() ||
      event.sequence != source->event_sequence + 1) {
    fail(CheckStatus::Invalid, "source event sequence has a gap, duplicate or reset");
    return;
  }
  auto closed = source->closed_through;
  const auto startup_closed = resets_[event.hart].startup_closed;
  if (startup_closed && (!closed || *startup_closed > *closed))
    closed = startup_closed;
  if (event.timestamp != std::numeric_limits<uint64_t>::max() && closed && event.timestamp <= *closed) {
    fail(CheckStatus::Invalid, "source event arrived behind its closed prefix");
    return;
  }
  source->event_sequence = event.sequence;
  advance(*source);
}

void SourceBoundary::receive(const SourcePrefixDelivery &prefix) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!producers_per_hart_ || !failure_)
    return;
  auto *source = producer(prefix.hart, prefix.producer, prefix.kind, prefix.lane);
  if (!source)
    return;
  if (prefix.contract != 1 || prefix.delay_edges != (prefix.kind == 6 ? 2u : 0u)) {
    fail(CheckStatus::Unsupported, "source prefix has no supported pipeline-delay contract");
    return;
  }
  if (source->prefix_sequence == std::numeric_limits<uint64_t>::max() ||
      prefix.sequence != source->prefix_sequence + 1) {
    fail(CheckStatus::Invalid, "source prefix sequence has a gap, duplicate or reset");
    return;
  }
  if (!prefix.source_cycle || prefix.closed_through >= prefix.source_cycle ||
      (source->prefix_sequence && (prefix.source_cycle < source->last_source_cycle ||
       prefix.closed_through < source->last_prefix_closed || prefix.produced_count < source->last_produced_count))) {
    fail(CheckStatus::Invalid, "source prefix time or production count moved backwards");
    return;
  }
  if (source->pending.size() == max_pending_prefixes) {
    fail(CheckStatus::Incomplete, "source prefix backlog exceeds the bounded delivery window");
    return;
  }
  source->prefix_sequence = prefix.sequence;
  source->last_source_cycle = prefix.source_cycle;
  source->last_prefix_closed = prefix.closed_through;
  source->last_produced_count = prefix.produced_count;
  source->pending.push_back({prefix.closed_through, prefix.produced_count});
  advance(*source);
}

void SourceBoundary::receive(const SourceResetDelivery &reset) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!producers_per_hart_ || !failure_)
    return;
  if (reset.hart >= harts_) {
    fail(CheckStatus::Invalid, "source reset observer has an unregistered hart");
    return;
  }
  auto &state = resets_[reset.hart];
  if (state.sequence == std::numeric_limits<uint64_t>::max() || reset.sequence != state.sequence + 1 ||
      (state.sequence && reset.source_cycle < state.source_cycle)) {
    fail(CheckStatus::Invalid, "source reset observer sequence or time moved backwards");
    return;
  }
  if (reset.asserted && state.ever_active) {
    fail(CheckStatus::Unsupported, "mid-session functional hart reset is outside the source epoch contract");
    return;
  }
  state.sequence = reset.sequence;
  state.source_cycle = reset.source_cycle;
  // A real asserted functional reset excludes source events before activation.
  // Deassertion freezes this bootstrap boundary until each producer delivers
  // its own active-clock prefix. Missing heartbeats never imply reset.
  if (reset.asserted && reset.source_cycle)
    state.startup_closed = reset.source_cycle - 1;
}

SourceBoundaryState SourceBoundary::snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  SourceBoundaryState result;
  result.status = failure_;
  result.expected_producers = size_t(harts_) * producers_per_hart_;
  result.observed_producers = producers_.size();
  if (!failure_ || !producers_per_hart_)
    return result;
  bool can_advance = true;
  bool catalog_complete = true;
  uint64_t through = std::numeric_limits<uint64_t>::max();
  for (unsigned hart = 0; hart < harts_; ++hart)
    for (unsigned id = 0; id < producers_per_hart_; ++id) {
      const auto found = producers_.find({hart, id});
      const Producer *source = found == producers_.end() ? nullptr : &found->second;
      if (source)
        result.pending_prefixes += source->pending.size();
      const auto closed = source && source->closed_through ? source->closed_through : resets_[hart].startup_closed;
      catalog_complete &= source && source->closed_through.has_value();
      can_advance &= closed.has_value();
      if (closed)
        through = std::min(through, *closed);
    }
  result.catalog_complete = catalog_complete;
  if (can_advance)
    result.closed_through = through;
  return result;
}

SourceBoundary &source_boundary() {
  static SourceBoundary instance;
  return instance;
}
} // namespace rvwmo

extern "C" void difftest_rvwmo_source_event(unsigned hart, unsigned producer, unsigned kind, unsigned lane,
                                            uint64_t sequence, uint64_t timestamp) {
  rvwmo::source_boundary().receive(rvwmo::SourceEventDelivery{hart, producer, kind, lane, sequence, timestamp});
}
extern "C" void difftest_rvwmo_source_prefix(unsigned hart, unsigned producer, unsigned kind, unsigned lane,
                                             unsigned contract, unsigned delay_edges, uint64_t source_cycle,
                                             uint64_t closed_through, uint64_t produced_count, uint64_t sequence) {
  rvwmo::source_boundary().receive(rvwmo::SourcePrefixDelivery{hart, producer, kind, lane, contract, delay_edges,
                                                           source_cycle, closed_through, produced_count, sequence});
}

extern "C" void difftest_rvwmo_source_reset(unsigned hart, unsigned asserted, uint64_t source_cycle,
                                            uint64_t sequence) {
  rvwmo::source_boundary().receive(rvwmo::SourceResetDelivery{hart, asserted != 0, source_cycle, sequence});
}
