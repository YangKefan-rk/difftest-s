#ifndef DIFFTEST_RVWMO_MEMORY_H
#define DIFFTEST_RVWMO_MEMORY_H

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace rvwmo {

struct MemoryWriter {
  uint32_t hart = 0;
  uint64_t uid = 0;
  bool operator==(const MemoryWriter &other) const;
  bool operator<(const MemoryWriter &other) const;
};

struct MemoryStore {
  MemoryWriter writer;
  uint64_t po = 0;
  uint64_t address = 0;
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;
};

struct MemoryByte {
  uint8_t value = 0;
  std::optional<MemoryWriter> writer;
  // Explicit SQ forwarding can precede the source store's local commit.
  bool deferred = false;
  bool local_forward = false;
  std::optional<uint64_t> sampled_local_po;
  // Retained with the final witness for LR/SC atomicity, independent of GC.
  std::optional<uint64_t> writer_time;
};

struct MemorySnapshot {
  uint64_t id = 0;
  uint32_t hart = 0;
  uint64_t po = 0;
  uint64_t time = 0;
  uint64_t address = 0;
  std::vector<uint8_t> mask;
  std::vector<MemoryByte> bytes;
};

// Backing callbacks access the independently owned GlobalMem storage.
// Store bytes may be provisional; Checker must audit them against REF before
// accepting dependent retirements. DUT load-result bytes never populate this model.
class Memory {
public:
  using ReadGlobal = std::function<uint8_t(uint64_t)>;
  using WriteGlobal = std::function<void(uint64_t, uint8_t)>;
  Memory(ReadGlobal read, WriteGlobal write);

  std::string commit_local(const MemoryStore &store);
  // Translation/fetch view only; architectural data loads use timed snapshots.
  bool read_local(uint32_t hart, uint64_t before_po, uint64_t address, uint8_t &byte) const;
  // writers[i] names the logical store responsible for transaction byte i.
  // completed contains all merged logical stores, including overwritten stores.
  std::string commit_global(uint64_t address, const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
                            const std::vector<MemoryWriter> &writers, const std::vector<MemoryWriter> &completed,
                            const std::vector<uint64_t> &completion_times = {});
  std::string sample(uint32_t hart, uint64_t po, uint64_t time, uint64_t address, const std::vector<uint8_t> &mask,
                     const std::vector<std::optional<MemoryWriter>> &forwarded, MemorySnapshot &snapshot,
                     bool source_prefix_closed = false);
  std::string resolve(MemorySnapshot &snapshot) const;
  // Derives a specification witness independently of observed forwarding tags.
  // A complete ordered source prefix may certify a pending local writer after
  // the sample. Other candidates still need their actual publication rank.
  std::string resolve_modeled(MemorySnapshot &snapshot) const;
  // Provisional REF input only: unknown local write ranks may be estimated
  // from same-address program order. This is never a consistency certificate;
  // final retirement must resolve_modeled and check PPO and actual bytes.
  std::string resolve_candidate(MemorySnapshot &snapshot) const;
  // Checks physical ECC preservation lanes against the independent GlobalMem
  // prefix without changing their logical writer identities.
  std::string compare_global_bytes(uint64_t address, const std::vector<uint8_t> &actual,
                                   const std::vector<uint8_t> &mask) const;
  std::vector<MemoryWriter> unpublished_sources(const MemorySnapshot &snapshot) const;
  std::string compare(MemorySnapshot &snapshot, const std::vector<uint8_t> &actual) const;
  // Release on retirement or cancellation. Double release is an error.
  std::string release(uint64_t snapshot_id);
  size_t pending_stores() const;
  bool has_global_reference(const MemoryWriter &writer) const { return global_byte_references_.count(writer) != 0; }
  // Notifications are opportunities: the caller must also check its own PPO
  // and retirement references, retaining blocked candidates for later retry.
  std::vector<MemoryWriter> take_reclaimable_writers();
  bool has_snapshot_reference(const MemoryWriter &writer) const {
    return references_.count(writer) != 0;
  }
  size_t pending_snapshots() const {
    return snapshots_.size();
  }

private:
  struct StoreRecord {
    MemoryStore store;
    bool pending = true;
    std::optional<uint64_t> global_time;
  };
  struct SnapshotRecord {
    uint32_t hart = 0;
    uint64_t po = 0;
    uint64_t address = 0;
    uint64_t time = 0;
    std::vector<MemoryWriter> sources;
    std::vector<std::optional<uint64_t>> latest_local_po;
    std::vector<uint8_t> mask;
    std::vector<MemoryByte> global_bytes;
    std::vector<std::optional<uint64_t>> global_times;
    std::set<MemoryWriter> candidates;
    // Only a consumer which has delivered every preceding memory effect may
    // certify this. An absent publication is then an ordering lower bound.
    bool source_prefix_closed = false;
    std::set<MemoryWriter> unpublished_after_sample;
  };
  ReadGlobal read_;
  WriteGlobal write_;
  uint64_t next_snapshot_ = 1;
  std::map<MemoryWriter, StoreRecord> stores_;
  std::map<MemoryWriter, size_t> references_;
  std::map<uint64_t, MemoryWriter> global_writers_;
  std::map<MemoryWriter, size_t> global_byte_references_;
  std::set<MemoryWriter> reclaimable_writers_;
  std::map<uint64_t, uint64_t> global_times_;
  std::map<uint32_t, std::map<uint64_t, std::vector<MemoryWriter>>> local_;
  std::map<uint64_t, SnapshotRecord> snapshots_;
  void retain_candidate(SnapshotRecord &snapshot, const MemoryWriter &writer);
  void retire_store(const MemoryWriter &writer);
  void collect_store(const MemoryWriter &writer);
};

} // namespace rvwmo
#endif
