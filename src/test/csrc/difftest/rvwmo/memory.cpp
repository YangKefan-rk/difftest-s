#include "memory.h"
#include <algorithm>
#include <limits>
#include <set>
#include <stdexcept>
#include <utility>

namespace rvwmo {
namespace {
std::string check_range(uint64_t address, size_t size) {
  if (size == 0)
    return "empty memory access";
  if (size - 1 > std::numeric_limits<uint64_t>::max() - address)
    return "memory address overflow";
  return {};
}
std::string byte_error(const char *reason, uint64_t address) {
  return std::string(reason) + " at byte address " + std::to_string(address);
}
} // namespace

bool MemoryWriter::operator==(const MemoryWriter &other) const {
  return hart == other.hart && uid == other.uid;
}
bool MemoryWriter::operator<(const MemoryWriter &other) const {
  return hart < other.hart || (hart == other.hart && uid < other.uid);
}
Memory::Memory(ReadGlobal read, WriteGlobal write) : read_(std::move(read)), write_(std::move(write)) {
  if (!read_ || !write_)
    throw std::invalid_argument("GlobalMem callbacks are required");
}

bool Memory::read_local(uint32_t hart, uint64_t before_po, uint64_t address, uint8_t &byte) const {
  auto local = local_.find(hart);
  if (local == local_.end())
    return false;
  auto versions = local->second.find(address);
  if (versions == local->second.end())
    return false;
  const MemoryStore *selected = nullptr;
  for (const auto &writer : versions->second) {
    const auto &store = stores_.at(writer).store;
    if (store.po < before_po && (!selected || store.po > selected->po))
      selected = &store;
  }
  if (!selected)
    return false;
  byte = selected->bytes.at(address - selected->address);
  return true;
}

std::string Memory::commit_local(const MemoryStore &store) {
  auto error = check_range(store.address, store.bytes.size());
  if (!error.empty())
    return error;
  if (store.mask.size() != store.bytes.size())
    return "store mask size mismatch";
  if (std::none_of(store.mask.begin(), store.mask.end(), [](uint8_t byte) { return byte != 0; }))
    return "store has no enabled bytes";
  if (store.writer.uid == 0)
    return "store UID zero is reserved";
  if (stores_.count(store.writer))
    return "duplicate live store UID";
  stores_.emplace(store.writer, StoreRecord{store, true, std::nullopt});
  // An early load sample can precede retirement of any of its older stores.
  // Preserve the newest eligible byte version until that sample is checked.
  for (auto &entry: snapshots_) {
    auto &sample = entry.second;
    if (sample.hart != store.writer.hart || sample.po <= store.po)
      continue;
    for (size_t i = 0; i < store.mask.size(); ++i) {
      uint64_t at = store.address + i;
      if (!store.mask[i] || at < sample.address || at - sample.address >= sample.latest_local_po.size() ||
          !sample.mask[at - sample.address])
        continue;
      retain_candidate(sample, store.writer);
      auto &latest = sample.latest_local_po[at - sample.address];
      if (!latest || *latest < store.po)
        latest = store.po;
    }
  }
  for (size_t i = 0; i < store.mask.size(); ++i) {
    if (store.mask[i])
      local_[store.writer.hart][store.address + i].push_back(store.writer);
  }
  return {};
}

std::string Memory::commit_global(uint64_t address, const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
                                  const std::vector<MemoryWriter> &writers, const std::vector<MemoryWriter> &completed,
                                  const std::vector<uint64_t> &completion_times) {
  auto error = check_range(address, bytes.size());
  if (!error.empty())
    return error;
  if (mask.size() != bytes.size() || writers.size() != bytes.size())
    return "global transaction size mismatch";
  if (!completion_times.empty() && completion_times.size() != completed.size())
    return "global timestamp count mismatch";
  std::map<MemoryWriter, uint64_t> times;
  for (size_t i = 0; i < completion_times.size(); ++i)
    times.emplace(completed[i], completion_times[i]);
  std::set<MemoryWriter> members(completed.begin(), completed.end());
  if (members.size() != completed.size() || members.empty())
    return "invalid global completion members";
  for (const auto &writer: members) {
    auto found = stores_.find(writer);
    if (found == stores_.end() || !found->second.pending)
      return "global completion has no pending local store";
  }
  // Validate the whole transaction before changing either memory model.
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (!mask[i])
      continue;
    if (!members.count(writers[i]))
      return "global byte writer is not a completion member";
    const auto &store = stores_.at(writers[i]).store;
    uint64_t at = address + i;
    if (at < store.address || at - store.address >= store.bytes.size())
      return byte_error("global writer address mismatch", at);
    size_t offset = at - store.address;
    if (!store.mask[offset] || store.bytes[offset] != bytes[i])
      return byte_error("global store value mismatch", at);
  }
  // Each completed byte must be represented, possibly overwritten by a later member.
  for (const auto &writer: members) {
    const auto &store = stores_.at(writer).store;
    for (size_t i = 0; i < store.bytes.size(); ++i) {
      if (!store.mask[i])
        continue;
      uint64_t at = store.address + i;
      if (at < address || at - address >= mask.size() || !mask[at - address])
        return byte_error("completion omitted a local store byte", at);
      const auto &last = stores_.at(writers[at - address]).store;
      if (last.writer.hart != writer.hart || last.po < store.po)
        return byte_error("merged completion discarded a newer local store", at);
      if (!times.empty() && times.at(last.writer) < times.at(writer))
        return byte_error("merged byte writer is not the latest global member", at);
    }
  }
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (!mask[i] || times.empty())
      continue;
    auto previous = global_times_.find(address + i);
    if (previous != global_times_.end() && times.at(writers[i]) <= previous->second)
      return byte_error("global writes were not replayed in increasing rank", address + i);
  }
  for (const auto &entry: times)
    stores_.at(entry.first).global_time = entry.second;
  // Store metadata can arrive after an already observed load. Reconstruct its
  // global prefix from independently checked logical writes, including merged
  // members whose bytes have been overwritten in the final transaction.
  for (const auto &entry: times) {
    const auto &store = stores_.at(entry.first).store;
    for (auto &sample_entry: snapshots_) {
      auto &sample = sample_entry.second;
      if (entry.second >= sample.time)
        continue;
      for (size_t i = 0; i < store.mask.size(); ++i) {
        uint64_t at = store.address + i;
        if (!store.mask[i] || at < sample.address || at - sample.address >= sample.mask.size())
          continue;
        size_t offset = at - sample.address;
        if (!sample.mask[offset] || (sample.global_bytes[offset].writer && sample.global_times[offset] &&
                                     *sample.global_times[offset] >= entry.second))
          continue;
        const auto previous = sample.global_bytes[offset].writer;
        if (previous) {
          auto reference = references_.find(*previous);
          if (--reference->second == 0)
            references_.erase(reference);
          collect_store(*previous);
        }
        sample.global_times[offset] = entry.second;
        sample.global_bytes[offset] = MemoryByte{};
        sample.global_bytes[offset].value = store.bytes[i];
        sample.global_bytes[offset].writer = store.writer;
        ++references_[store.writer];
      }
    }
  }
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (!mask[i])
      continue;
    write_(address + i, bytes[i]);
    auto previous_writer = global_writers_.find(address + i);
    if (previous_writer == global_writers_.end() || !(previous_writer->second == writers[i])) {
      if (previous_writer != global_writers_.end()) {
        const auto previous = previous_writer->second;
        auto count = global_byte_references_.find(previous);
        if (--count->second == 0) global_byte_references_.erase(count);
        collect_store(previous);
      }
      ++global_byte_references_[writers[i]];
    }
    global_writers_[address + i] = writers[i];
    if (times.empty())
      global_times_.erase(address + i);
    else
      global_times_[address + i] = times.at(writers[i]);
  }
  for (const auto &writer: members)
    retire_store(writer);
  return {};
}

std::string Memory::sample(uint32_t hart, uint64_t po, uint64_t time, uint64_t address,
                           const std::vector<uint8_t> &mask, const std::vector<std::optional<MemoryWriter>> &forwarded,
                           MemorySnapshot &snapshot) {
  auto error = check_range(address, mask.size());
  if (!error.empty())
    return error;
  if (!forwarded.empty() && forwarded.size() != mask.size())
    return "forwarding size mismatch";
  for (const auto &writer: forwarded) {
    if (writer && (writer->hart != hart || writer->uid == 0))
      return "invalid local forwarding identity";
  }
  if (next_snapshot_ == 0)
    return "snapshot identity exhausted";
  snapshot = MemorySnapshot{next_snapshot_++, hart, po, time, address, mask, {}};
  snapshot.bytes.resize(mask.size());
  SnapshotRecord record;
  record.hart = hart;
  record.po = po;
  record.address = address;
  record.time = time;
  record.latest_local_po.resize(mask.size());
  record.mask = mask;
  record.global_bytes.resize(mask.size());
  record.global_times.resize(mask.size());
  for (size_t i = 0; i < mask.size(); ++i) {
    if (!mask[i])
      continue;
    auto &byte = snapshot.bytes[i];
    uint64_t at = address + i;
    byte.value = read_(at);
    auto global = global_writers_.find(at);
    if (global != global_writers_.end()) {
      byte.writer = global->second;
      auto rank = global_times_.find(at);
      if (rank != global_times_.end())
        record.global_times[i] = rank->second;
    } else
      record.global_times[i] = 0;
    byte.writer_time = record.global_times[i];
    record.global_bytes[i] = byte;
    if (byte.writer)
      ++references_[*byte.writer];
    const MemoryStore *newest = nullptr;
    auto local = local_.find(hart);
    if (local != local_.end()) {
      auto versions = local->second.find(at);
      if (versions != local->second.end()) {
        for (const auto &writer: versions->second) {
          const auto &store = stores_.at(writer).store;
          if (store.po < po) {
            retain_candidate(record, writer);
            if (!newest || store.po > newest->po)
              newest = &store;
          }
        }
      }
    }
    if (newest) {
      byte.value = newest->bytes[at - newest->address];
      byte.writer = newest->writer;
      byte.writer_time = stores_.at(newest->writer).global_time;
      record.latest_local_po[i] = newest->po;
      byte.sampled_local_po = newest->po;
    }
    if (!forwarded.empty() && forwarded[i]) {
      // Keep an independent source-store reference, not the DUT's returned value.
      byte.writer = forwarded[i];
      byte.deferred = true;
      byte.local_forward = true;
      record.sources.push_back(*forwarded[i]);
      ++references_[*forwarded[i]];
    }
  }
  snapshots_.emplace(snapshot.id, std::move(record));
  return {};
}

std::string Memory::resolve(MemorySnapshot &snapshot) const {
  auto active = snapshots_.find(snapshot.id);
  if (active == snapshots_.end())
    return "unknown or released memory snapshot";
  if (snapshot.bytes.size() != snapshot.mask.size())
    return "invalid memory snapshot size";
  for (size_t i = 0; i < snapshot.bytes.size(); ++i) {
    auto &byte = snapshot.bytes[i];
    if (!snapshot.mask[i])
      continue;
    if (!byte.local_forward) {
      auto latest = active->second.latest_local_po[i];
      if (latest && (!byte.sampled_local_po || *latest > *byte.sampled_local_po))
        return byte_error("older store retired after sampling; forwarding identity required", snapshot.address + i);
      if (byte.writer && byte.sampled_local_po) {
        auto source = stores_.find(*byte.writer);
        if (source == stores_.end())
          return "forwarded source store has not locally committed";
        byte.writer_time = source->second.global_time;
      }
      continue;
    }
    if (!byte.writer)
      return "forwarded byte has no source identity";
    auto found = stores_.find(*byte.writer);
    if (found == stores_.end())
      return "forwarded source store has not locally committed";
    const auto &store = found->second.store;
    uint64_t at = snapshot.address + i;
    if (store.writer.hart != snapshot.hart || store.po >= snapshot.po)
      return byte_error("forwarding source is not an older local store", at);
    auto latest = active->second.latest_local_po[i];
    if (latest && store.po < *latest)
      return byte_error("forwarding bypassed a newer local store", at);
    if (at < store.address || at - store.address >= store.bytes.size() || !store.mask[at - store.address])
      return byte_error("forwarding source does not write load byte", at);
    byte.value = store.bytes[at - store.address];
    byte.deferred = false;
    byte.writer_time = found->second.global_time;
  }
  return {};
}
std::string Memory::resolve_modeled(MemorySnapshot &snapshot) const {
  auto active = snapshots_.find(snapshot.id);
  if (active == snapshots_.end())
    return "unknown or released memory snapshot";
  const auto &record = active->second;
  if (snapshot.bytes.size() != record.global_bytes.size() || snapshot.mask != record.mask ||
      snapshot.hart != record.hart || snapshot.po != record.po || snapshot.address != record.address ||
      snapshot.time != record.time)
    return "invalid memory snapshot identity, size or mask";
  std::vector<MemoryByte> resolved = record.global_bytes;
  auto latest = record.global_times;
  for (size_t i = 0; i < record.mask.size(); ++i) {
    if (!record.mask[i])
      continue;
    if (!latest[i])
      return "modeled read awaits global baseline timestamp";
    if (record.global_bytes[i].writer && *latest[i] >= snapshot.time)
      return byte_error("global baseline does not precede load observation", snapshot.address + i);
  }
  for (const auto &writer: record.candidates) {
    auto found = stores_.find(writer);
    if (found == stores_.end())
      return "modeled read awaits source store record";
    const auto &candidate = found->second;
    if (!candidate.global_time)
      return "modeled read awaits store global timestamp";
    const auto &store = candidate.store;
    if (store.writer.hart != snapshot.hart || store.po >= snapshot.po)
      return "invalid modeled local-store candidate";
    for (size_t i = 0; i < record.mask.size(); ++i) {
      uint64_t at = snapshot.address + i;
      if (!record.mask[i] || at < store.address || at - store.address >= store.mask.size() ||
          !store.mask[at - store.address])
        continue;
      if (!resolved[i].writer || *candidate.global_time > *latest[i]) {
        latest[i] = candidate.global_time;
        resolved[i].value = store.bytes[at - store.address];
        resolved[i].writer = writer;
      } else if (*candidate.global_time == *latest[i] && resolved[i].writer && !(*resolved[i].writer == writer)) {
        return byte_error("distinct candidate stores share one global rank", at);
      }
    }
  }
  for (size_t i = 0; i < resolved.size(); ++i)
    resolved[i].writer_time = latest[i];
  snapshot.bytes = std::move(resolved);
  return {};
}

std::string Memory::resolve_candidate(MemorySnapshot &snapshot) const {
  auto error = resolve_modeled(snapshot);
  if (error.empty())
    return {};
  if (error.find("modeled read awaits") != 0)
    return error;
  auto active = snapshots_.find(snapshot.id);
  if (active == snapshots_.end())
    return "unknown or released memory snapshot";
  const auto &record = active->second;
  std::vector<MemoryByte> provisional = record.global_bytes;
  auto latest = record.global_times;
  std::vector<const StoreRecord *> newest_local(record.mask.size(), nullptr);
  for (const auto &writer: record.candidates) {
    auto found = stores_.find(writer);
    if (found == stores_.end())
      return "candidate read awaits source store record";
    const auto &candidate = found->second;
    const auto &store = candidate.store;
    if (store.writer.hart != snapshot.hart || store.po >= snapshot.po)
      return "invalid provisional local-store candidate";
    for (size_t i = 0; i < record.mask.size(); ++i) {
      uint64_t at = snapshot.address + i;
      if (!record.mask[i] || at < store.address || at - store.address >= store.mask.size() ||
          !store.mask[at - store.address])
        continue;
      if (!newest_local[i] || store.po > newest_local[i]->store.po)
        newest_local[i] = &candidate;
      if (candidate.global_time && (!provisional[i].writer || !latest[i] || *candidate.global_time > *latest[i])) {
        latest[i] = candidate.global_time;
        provisional[i].value = store.bytes[at - store.address];
        provisional[i].writer = writer;
      }
    }
  }
  for (size_t i = 0; i < record.mask.size(); ++i) {
    if (!record.mask[i])
      continue;
    const auto *candidate = newest_local[i];
    // The same-address store PPO will ultimately order all local versions.
    // Only an unresolved latest local version needs this provisional override.
    if (candidate && !candidate->global_time) {
      provisional[i].value = candidate->store.bytes[snapshot.address + i - candidate->store.address];
      provisional[i].writer = candidate->store.writer;
      latest[i].reset();
    } else if (!latest[i])
      return "candidate read awaits global baseline timestamp";
  }
  for (size_t i = 0; i < provisional.size(); ++i)
    provisional[i].writer_time = latest[i];
  snapshot.bytes = std::move(provisional);
  return {};
}

void Memory::retain_candidate(SnapshotRecord &snapshot, const MemoryWriter &writer) {
  if (snapshot.candidates.insert(writer).second)
    ++references_[writer];
}

std::string Memory::compare(MemorySnapshot &snapshot, const std::vector<uint8_t> &actual) const {
  if (actual.size() != snapshot.bytes.size())
    return "load value size mismatch";
  auto error = resolve(snapshot);
  if (!error.empty())
    return error;
  for (size_t i = 0; i < actual.size(); ++i) {
    if (snapshot.mask[i] && actual[i] != snapshot.bytes[i].value)
      return byte_error("load value mismatch", snapshot.address + i);
  }
  return {};
}
void Memory::collect_store(const MemoryWriter &writer) {
  auto found = stores_.find(writer);
  if (found != stores_.end() && found->second.pending) return;
  if (references_.count(writer)) return;
  if (found != stores_.end()) stores_.erase(found);
  if (!has_global_reference(writer)) reclaimable_writers_.insert(writer);
}
std::vector<MemoryWriter> Memory::take_reclaimable_writers() {
  std::vector<MemoryWriter> writers(reclaimable_writers_.begin(), reclaimable_writers_.end());
  reclaimable_writers_.clear();
  return writers;
}
void Memory::retire_store(const MemoryWriter &writer) {
  auto &record = stores_.at(writer);
  auto &addresses = local_.at(writer.hart);
  for (size_t i = 0; i < record.store.mask.size(); ++i) {
    if (!record.store.mask[i])
      continue;
    auto found = addresses.find(record.store.address + i);
    auto &versions = found->second;
    versions.erase(std::remove(versions.begin(), versions.end(), writer), versions.end());
    if (versions.empty())
      addresses.erase(found);
  }
  if (addresses.empty())
    local_.erase(writer.hart);
  record.pending = false;
  collect_store(writer);
}
std::string Memory::release(uint64_t snapshot_id) {
  auto found = snapshots_.find(snapshot_id);
  if (found == snapshots_.end())
    return "unknown or already released memory snapshot";
  for (const auto &writer: found->second.sources) {
    auto ref = references_.find(writer);
    if (--ref->second == 0)
      references_.erase(ref);
    collect_store(writer);
  }
  for (size_t i = 0; i < found->second.global_bytes.size(); ++i) {
    const auto &writer = found->second.global_bytes[i].writer;
    if (!found->second.mask[i] || !writer)
      continue;
    auto ref = references_.find(*writer);
    if (--ref->second == 0)
      references_.erase(ref);
    collect_store(*writer);
  }
  for (const auto &writer: found->second.candidates) {
    auto ref = references_.find(writer);
    if (--ref->second == 0)
      references_.erase(ref);
    collect_store(writer);
  }
  snapshots_.erase(found);
  return {};
}
size_t Memory::pending_stores() const {
  return std::count_if(stores_.begin(), stores_.end(), [](const auto &entry) { return entry.second.pending; });
}
} // namespace rvwmo
