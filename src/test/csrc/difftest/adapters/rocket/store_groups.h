#ifndef DIFFTEST_ROCKET_STORE_GROUPS_H
#define DIFFTEST_ROCKET_STORE_GROUPS_H

#include "cache_tracker.h"
#include <array>

namespace rocket_difftest {

struct StoreGroupConfiguration {
  uint8_t ecc_bytes = 1;
  size_t capacity = 65536;
};

struct CacheStoreDrain {
  CacheStoreValue actual;
  uint8_t physical_mask = 0;
  bool second_slot = false;
};

struct StoreGroupObservation {
  uint64_t anchor_request_id = 0;
  std::vector<CacheStoreMember> members;
  uint64_t word_address = 0;
  std::array<uint8_t, 8> actual_bytes{};
  uint8_t logical_mask = 0;
  uint8_t physical_mask = 0;
  std::array<std::optional<uint64_t>, 8> byte_writer_requests{};
  rvwmo::SourcePosition source;
};

// Private blocking-DCache slot collector. It preserves one physical drain
// observation and all logical originals; it assigns no per-member GMO ranks.
// A shared decoder must qualify publication and the public consumer must still
// audit each member, resolve group ordering, and check PPO before final Pass.
class StoreGroupTracker {
public:
  explicit StoreGroupTracker(StoreGroupConfiguration configuration);
  rvwmo::CheckResult accept(const CacheStoreMember &member);
  rvwmo::CheckResult advance(uint64_t request_id, rvwmo::SourcePosition source);
  rvwmo::CheckResult merge(uint64_t request_id, uint64_t target_request_id, rvwmo::SourcePosition source);
  rvwmo::CheckResult capture_drain(const CacheStoreDrain &drain, StoreGroupObservation &observation);
  // Acknowledges lossless downstream ownership, not semantic acceptance. The
  // physical slot was already released at capture_drain's observed SRAM edge.
  rvwmo::CheckResult acknowledge_drain(uint64_t anchor_request_id);
  rvwmo::CheckResult finalize() const;
  size_t pending_groups() const { return groups_.size(); }

private:
  struct Group {
    StoreGroupObservation observation;
    std::array<uint8_t, 8> expected_bytes{};
    rvwmo::SourcePosition latest_transition;
    bool transitioned = false;
    bool drained = false;
  };

  StoreGroupConfiguration configuration_;
  std::map<uint64_t, Group> groups_;
  std::optional<uint64_t> first_slot_;
  std::optional<uint64_t> second_slot_;
  std::optional<uint64_t> last_request_;
  std::optional<uint64_t> last_source_cycle_;
  std::optional<uint64_t> last_accept_cycle_;
  std::optional<uint64_t> last_drain_cycle_;
  size_t live_members_ = 0;
  rvwmo::CheckResult failure_;

  rvwmo::CheckResult reject(rvwmo::CheckStatus status, const char *message);
  bool valid_source(rvwmo::SourcePosition source) const;
  uint8_t physical_mask(uint8_t logical_mask) const;
  static void append_member(Group &group, const CacheStoreMember &member);
};

} // namespace rocket_difftest
#endif
