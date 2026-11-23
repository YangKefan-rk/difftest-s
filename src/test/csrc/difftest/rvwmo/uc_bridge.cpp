// Some simulators compile every rvwmo source even without the external UC transport.
#ifdef DIFFTEST_S_UC_NATIVE_V1
#include "uc_bridge.h"
#include <algorithm>
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace rvwmo {
namespace {
constexpr uint64_t global_hart = SFUZZ_UC_GLOBAL_HART, uc_begin = 0x30000000000, uc_end = 0x40000000000;
constexpr uint64_t write_flag = 1, device_flag = 2, denied_flag = 4, corrupt_flag = 8;
constexpr uint64_t last_flag = 16, reset_flag = 32, poison_flag = 64;
constexpr uint64_t nc_flag = 128, nc_valid_flag = 256;
using ProducerKey = std::tuple<uint64_t, uint64_t, uint64_t>;
using PositionKey = std::tuple<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t>;
using Time = std::pair<uint64_t, uint64_t>;
ProducerKey key(const UcRawProducer &source) { return {source.name_space, source.hart, source.source_id}; }
UcRawProducer producer(const SfuzzUcRawRecord &record) {
  return {record.producer_namespace, record.hart, record.source_id, record.role};
}
UcRawPosition position(const SfuzzUcRawRecord &record) {
  return {producer(record), record.epoch, record.sequence, record.emit_cycle, record.emit_edge};
}
PositionKey position_key(const UcRawPosition &where) {
  return {where.producer.name_space, where.producer.hart, where.producer.source_id, where.epoch, where.sequence};
}
Time time(const SfuzzUcRawRecord &record) { return {record.emit_cycle, record.emit_edge}; }
bool write(const SfuzzUcRawRecord &record) { return record.flags & write_flag; }
bool scalar_address(uint64_t address) { return address >= uc_begin && address <= uc_end - 8 && address % 8 == 0; }
CheckResult invalid(const std::string &message) { return {CheckStatus::Invalid, 0, "UC bridge: " + message}; }
CheckResult incomplete(const std::string &message) { return {CheckStatus::Incomplete, 0, "UC bridge: " + message}; }
CheckResult pending(const std::string &message) { return {CheckStatus::Pending, 0, "UC bridge: " + message}; }
std::array<uint8_t, 8> bytes(uint64_t value) {
  std::array<uint8_t, 8> result{};
  for (unsigned i = 0; i < 8; ++i) result[i] = value >> (8 * i);
  return result;
}
unsigned chi_hart(UcBridgeLayout layout, uint64_t source) {
  const std::array<uint64_t, 4> legacy_sources{0, 0x48, 0x50, 0xa8};
  const std::array<uint64_t, 4> pma_sources{1, 0x49, 0x51, 0xa9};
  const auto &sources = layout == UcBridgeLayout::PmaLite17 ? pma_sources : legacy_sources;
  const auto found = std::find(sources.begin(), sources.end(), source);
  return static_cast<unsigned>(found - sources.begin());
}
unsigned route_slots(UcBridgeLayout layout) { return layout == UcBridgeLayout::PmaLite17 ? 8 : 32; }
uint64_t endpoint_id(UcBridgeLayout layout, uint64_t slot) {
  return (layout == UcBridgeLayout::PmaLite17 ? 0x80 : 0xa0) | slot;
}
std::set<UcRawProducer> pinned_roster(UcBridgeLayout layout) {
  std::set<UcRawProducer> result;
  for (unsigned hart = 0; hart < 4; ++hart) {
    result.insert({1, hart, 0, SFUZZ_UC_CORE});
    result.insert({1, hart, 16, SFUZZ_UC_MMIO});
  }
  for (unsigned slot = 0; slot < route_slots(layout); ++slot) result.insert({2, global_hart, slot, SFUZZ_UC_AXI});
  result.insert({2, global_hart, 32, SFUZZ_UC_ENDPOINT});
  return result;
}
} // namespace

bool UcRawProducer::operator==(const UcRawProducer &other) const {
  return key(*this) == key(other) && role == other.role;
}
bool UcRawProducer::operator<(const UcRawProducer &other) const {
  return std::tie(name_space, hart, source_id, role) < std::tie(other.name_space, other.hart, other.source_id, other.role);
}
bool UcRawPosition::operator==(const UcRawPosition &other) const {
  return producer == other.producer && epoch == other.epoch && sequence == other.sequence &&
         cycle == other.cycle && edge == other.edge;
}
bool UcTransactionKey::operator==(const UcTransactionKey &other) const {
  return std::tie(epoch, hart, transaction_uid) == std::tie(other.epoch, other.hart, other.transaction_uid);
}
bool UcTransactionKey::operator<(const UcTransactionKey &other) const {
  return std::tie(epoch, hart, transaction_uid) < std::tie(other.epoch, other.hart, other.transaction_uid);
}

struct UcBridge::Impl {
  struct Prefix { uint64_t closed, count; };
  struct Source {
    UcRawProducer identity;
    bool asserted = false, released = false;
    uint64_t sequence = 0, prefix_sequence = 0, prefix_count = 0, prefix_closed = 0, prefix_emit = 0;
    Time last_event{};
    std::optional<uint64_t> closed;
    std::deque<Prefix> prefixes;
  };
  struct Transaction {
    UcBoundRequest bound;
    SfuzzUcRawRecord request{};
    std::optional<SfuzzUcRawRecord> bus, grant, mmio, axi, accept, effect, response;
    bool request_delivered = false, effect_delivered = false;
  };
  UcBridgeConfig config;
  CheckResult status;
  std::map<ProducerKey, Source> sources;
  std::map<PositionKey, UcRawPosition> positions;
  std::vector<SfuzzUcRawRecord> records;
  std::vector<SfuzzUcRawRecord> mappings;
  std::map<UcTransactionKey, Transaction> transactions;
  std::set<UcTransactionKey> seen_transactions;
  std::set<OperationId> seen_allocations;
  std::map<UcTransactionKey, UcJoinedEffect> memory_ready;
  std::map<PositionKey, UcTransactionKey> memory_positions;
  std::map<UcTransactionKey, UcJoinedEffect> qualified;
  std::map<uint64_t, PositionKey> undelivered_effects;
  std::map<std::pair<uint64_t, uint64_t>, uint64_t> mmio_generations;
  std::map<uint64_t, uint64_t> axi_generations;
  std::set<uint64_t> endpoint_uids;
  std::set<std::pair<uint64_t, uint64_t>> endpoint_phases;

  explicit Impl(UcBridgeConfig selected) : config(std::move(selected)) {
    if (!config.enabled) { status = {CheckStatus::Unsupported, 0, "UC bridge is disabled"}; return; }
    if (!config.common_clock_verified || config.harts != 4 || !config.epoch ||
        !config.max_pending_transactions || !config.max_pending_records || !config.max_event_positions) {
      status = invalid("missing pinned clock, hart roster, epoch or bounded capacities"); return;
    }
    if (config.layout != UcBridgeLayout::LegacyNc41 && config.layout != UcBridgeLayout::PmaLite17) {
      status = invalid("unknown pinned source layout"); return;
    }
    if (config.layout == UcBridgeLayout::PmaLite17) {
      const std::set<uint64_t> pages(config.zero_pages.begin(), config.zero_pages.end());
      if (pages.empty() || pages.size() > 64 || pages.size() != config.zero_pages.size() ||
          std::any_of(pages.begin(), pages.end(), [](uint64_t page) {
            return page % 4096 || page < uc_begin || page >= uc_end;
          })) {
        status = invalid("PMA Lite profile requires explicit independent aligned RAM zero pages"); return;
      }
    }
    const std::set<UcRawProducer> declared(config.producers.begin(), config.producers.end());
    if (declared != pinned_roster(config.layout) || declared.size() != config.producers.size()) {
      status = invalid("external producer roster differs from its pinned source layout"); return;
    }
    for (const auto &identity : config.producers) {
      Source source;
      source.identity = identity;
      sources.emplace(key(identity), std::move(source));
    }
  }
  CheckResult fail(CheckResult result) { if (status) status = std::move(result); return status; }
  bool address_is_declared(uint64_t address) const {
    return scalar_address(address) && (config.layout == UcBridgeLayout::LegacyNc41 ||
        std::find(config.zero_pages.begin(), config.zero_pages.end(), address & ~UINT64_C(4095)) !=
            config.zero_pages.end());
  }
  bool core_class_is_valid(const SfuzzUcRawRecord &record) const {
    if (config.layout == UcBridgeLayout::LegacyNc41) return !(record.flags & device_flag);
    // This is the actual PMA-device classification of declared RAM, not an
    // admission for arbitrary peripherals. A store has a real SQ NC bit;
    // loads leave req.nc unknown and must not invent its value.
    if (!(record.flags & device_flag) || (record.flags & nc_flag)) return false;
    return !write(record) || (record.flags & nc_valid_flag);
  }
  void close(Source &source) {
    while (!source.prefixes.empty() && source.prefixes.front().count <= source.sequence) {
      source.closed = source.prefixes.front().closed;
      source.prefixes.pop_front();
    }
  }
  std::optional<uint64_t> raw_closed() const {
    std::optional<uint64_t> result;
    for (const auto &entry : sources) {
      const auto &source = entry.second;
      if (!source.asserted || !source.released || !source.closed) return {};
      result = result ? std::min(*result, *source.closed) : source.closed;
    }
    return result;
  }
  bool role_accepts(uint64_t role, uint64_t kind) const {
    return (role == SFUZZ_UC_CORE && kind >= SFUZZ_UC_CORE_REQUEST && kind <= SFUZZ_UC_CORE_GRANT) ||
           (role == SFUZZ_UC_MMIO && kind == SFUZZ_UC_MMIO_ACCEPT) ||
           (role == SFUZZ_UC_AXI && kind == SFUZZ_UC_AXI_ISSUE) ||
           (role == SFUZZ_UC_ENDPOINT && kind >= SFUZZ_UC_ENDPOINT_ACCEPT && kind <= SFUZZ_UC_ENDPOINT_RESPONSE) ||
           kind == SFUZZ_UC_ERROR;
  }
  CheckResult ingest(const SfuzzUcRawRecord &record) {
    if (!status) return status;
    const auto found = sources.find(key(producer(record)));
    if (record.abi_version != 1 || found == sources.end() ||
        !(found->second.identity == producer(record)) || record.emit_edge > 1 ||
        record.epoch != config.epoch || record.reserved3 || record.reserved4)
      return fail(invalid("unregistered source, epoch or ABI"));
    if (record.flags & poison_flag)
      return fail(invalid("external producer is poisoned, error=" + std::to_string(record.error_code)));
    auto &source = found->second;
    if (record.kind == SFUZZ_UC_RESET) {
      if (record.flags & reset_flag) {
        if (source.asserted || source.released) return fail(invalid("duplicate or mid-session reset"));
        source.asserted = true;
      } else {
        if (!source.asserted || source.released) return fail(invalid("reset release lacks its assertion"));
        source.released = true;
      }
      return {};
    }
    if (!source.released) return fail(invalid("event or prefix precedes verified reset release"));
    if (record.kind == SFUZZ_UC_PREFIX) {
      if (source.prefix_sequence == UINT64_MAX || record.prefix_sequence != source.prefix_sequence + 1 ||
          record.produced_count < source.prefix_count || record.sequence != record.produced_count ||
          record.closed_edge != 1 || record.emit_edge != 1 ||
          (source.prefix_sequence && record.emit_cycle <= source.prefix_emit))
        return fail(invalid("prefix sequence/count/edge is inconsistent"));
      source.prefix_sequence = record.prefix_sequence;
      source.prefix_count = record.produced_count;
      source.prefix_emit = record.emit_cycle;
      if (record.closed_cycle == UINT64_MAX) return {};
      if (record.closed_cycle >= record.emit_cycle || record.closed_cycle < source.prefix_closed)
        return fail(invalid("prefix moved backward or closed its active cycle"));
      source.prefix_closed = record.closed_cycle;
      if (source.prefixes.size() >= config.max_pending_records)
        return fail(incomplete("raw prefix capacity exhausted"));
      source.prefixes.push_back({record.closed_cycle, record.produced_count});
      close(source);
      return {};
    }
    if (!role_accepts(record.role, record.kind) || source.sequence == UINT64_MAX ||
        record.sequence != source.sequence + 1 || !record.emit_cycle || time(record) < source.last_event ||
        (source.closed && record.emit_cycle <= *source.closed))
      return fail(invalid("raw event gap, duplicate, wrong role or closed source time"));
    if (record.kind == SFUZZ_UC_AXI_ISSUE && chi_hart(config.layout, record.chi_src) >= config.harts)
      return fail(invalid("AXI issue carries an unregistered CHI source/tag for this layout"));
    if (positions.size() >= config.max_event_positions || records.size() + mappings.size() >= config.max_pending_records)
      return fail(incomplete("raw event ledger or pending record capacity exhausted"));
    source.sequence = record.sequence;
    source.last_event = time(record);
    positions.emplace(position_key(position(record)), position(record));
    close(source);
    if (record.kind == SFUZZ_UC_ERROR) return fail(invalid("producer reported a raw observation error"));
    if (record.role == SFUZZ_UC_ENDPOINT) {
      if (!record.endpoint_uid || !endpoint_phases.emplace(record.endpoint_uid, record.kind).second)
        return fail(invalid("endpoint UID/phase is missing or repeated"));
      if (record.kind == SFUZZ_UC_ENDPOINT_WRITE || record.kind == SFUZZ_UC_ENDPOINT_READ)
        undelivered_effects.emplace(record.sequence, position_key(position(record)));
    }
    records.push_back(record);
    return {};
  }
  CheckResult bind(const std::vector<uint64_t> &frames, const UcAllocationResolver &resolve) {
    if (!status) return status;
    if (frames.size() != config.harts) return fail(invalid("request frame has the wrong hart count"));
    for (const auto &record : records) {
      if (record.kind != SFUZZ_UC_CORE_REQUEST) continue;
      UcTransactionKey id{record.epoch, unsigned(record.hart), record.transaction_uid};
      const auto existing = transactions.find(id);
      if (existing != transactions.end() && existing->second.bound.source == position(record)) continue;
      if (record.emit_cycle != frames[record.hart] || record.emit_edge != 0)
        return fail(invalid("request cannot bind outside its original capture frame"));
      if (!resolve || !record.transaction_uid || record.entry_id >= 16 || record.robidx >= 1024 ||
          !address_is_declared(record.address) || record.mask != 0xff || !core_class_is_valid(record) ||
          record.access_size != 3 || record.burst_length || record.opcode != (write(record) ? 1u : 0u) ||
          (write(record) ? record.store_uid == 0 : record.store_uid != 0))
        return fail(invalid("request lacks exact scalar RAM identity"));
      if (seen_transactions.count(id)) return fail(invalid("core transaction UID was reused"));
      if (transactions.size() == config.max_pending_transactions)
        return fail(incomplete("pending transaction capacity exhausted"));
      OperationId allocation;
      const auto result = resolve(unsigned(record.hart), uint16_t(record.robidx), record.store_uid, write(record), allocation);
      if (!result) return fail(result);
      if (allocation.hart != record.hart || !allocation.uid || allocation.subaccess)
        return fail(invalid("allocation resolver returned an invalid scalar identity"));
      if (!seen_allocations.insert(allocation).second)
        return fail(invalid("one scalar allocation was bound to multiple UC transactions"));
      Transaction transaction;
      transaction.request = record;
      transaction.bound = {id, allocation, uint16_t(record.robidx), record.store_uid, record.entry_id,
                           write(record), record.address, uint8_t(record.mask), bytes(record.data0), position(record),
                           bool(record.flags & device_flag), bool(record.flags & nc_flag),
                           bool(record.flags & nc_valid_flag)};
      transactions.emplace(id, std::move(transaction));
      seen_transactions.insert(id);
    }
    return {};
  }
  bool request_matches(const Transaction &transaction, const SfuzzUcRawRecord &record) const {
    const auto &request = transaction.request;
    return record.entry_id == request.entry_id && record.robidx == request.robidx &&
           record.store_uid == request.store_uid && record.address == request.address && record.mask == request.mask &&
           write(record) == write(request) &&
           (record.flags & (device_flag | nc_flag | nc_valid_flag)) ==
               (request.flags & (device_flag | nc_flag | nc_valid_flag)) &&
           core_class_is_valid(record) && time(record) >= time(request);
  }
  CheckResult stage_core(const SfuzzUcRawRecord &record) {
    const UcTransactionKey id{record.epoch, unsigned(record.hart), record.transaction_uid};
    const auto found = transactions.find(id);
    if (found == transactions.end())
      return seen_transactions.count(id) ? invalid("core phase repeats a completed transaction")
                                         : pending("core phase awaits exact frame binding");
    auto &transaction = found->second;
    if (record.kind == SFUZZ_UC_CORE_REQUEST) return {};
    if (!request_matches(transaction, record)) return invalid("core phase changed its bound request");
    if (record.flags & (denied_flag | corrupt_flag))
      return {CheckStatus::Unsupported, 0, "UC bridge: denied/corrupt core grant"};
    if (record.kind == SFUZZ_UC_CORE_GRANT && !(record.flags & last_flag))
      return invalid("core grant lacks the admitted single-beat contract");
    auto &target = record.kind == SFUZZ_UC_CORE_BUS ? transaction.bus : transaction.grant;
    if (target) return invalid("duplicate core bus or grant phase");
    if (record.kind == SFUZZ_UC_CORE_BUS && write(record) && record.data0 != transaction.request.data0)
      return invalid("core bus write bytes changed");
    target = record;
    return {};
  }
  Transaction *match(const SfuzzUcRawRecord &record) {
    Transaction *result = nullptr;
    Time earliest{UINT64_MAX, UINT64_MAX};
    for (auto &entry : transactions) {
      auto &candidate = entry.second;
      const SfuzzUcRawRecord *previous = nullptr;
      bool matches = false;
      if (record.kind == SFUZZ_UC_MMIO_ACCEPT) {
        matches = candidate.bus && !candidate.mmio && candidate.bound.key.hart == record.hart &&
                  candidate.bound.entry_id == record.tl_source;
        if (candidate.bus) previous = &*candidate.bus;
      } else if (record.kind == SFUZZ_UC_AXI_ISSUE) {
        matches = candidate.mmio && !candidate.axi &&
                  candidate.bound.key.hart == chi_hart(config.layout, record.chi_src) &&
                  record.chi_txn == (0x800 | candidate.mmio->mmio_entry);
        if (candidate.mmio) previous = &*candidate.mmio;
      } else if (record.kind == SFUZZ_UC_ENDPOINT_ACCEPT) {
        matches = candidate.axi && !candidate.accept && candidate.axi->axi_id == record.axi_id &&
                  write(candidate.request) == write(record);
        if (candidate.axi) previous = &*candidate.axi;
      } else {
        matches = candidate.accept && candidate.accept->endpoint_uid == record.endpoint_uid;
        if (candidate.accept) previous = &*candidate.accept;
      }
      if (matches && previous && time(*previous) <= time(record) && time(*previous) < earliest) {
        earliest = time(*previous);
        result = &candidate;
      } else if (matches && previous && time(*previous) == earliest) {
        fail(invalid("route has more than one same-time identity candidate"));
        return nullptr;
      }
    }
    return result;
  }
  CheckResult attach(Transaction &transaction, const SfuzzUcRawRecord &record) {
    if (record.address != transaction.bound.address || write(record) != transaction.bound.write)
      return invalid("route/endpoint differs from the bound scalar request");
    if (record.kind != SFUZZ_UC_MMIO_ACCEPT && (record.flags & device_flag))
      return invalid("physical route/endpoint carries a core-only device qualifier");
    if (record.kind == SFUZZ_UC_MMIO_ACCEPT) {
      if (record.mmio_entry >= 16 || !record.mmio_generation || record.chi_txn != (0x800 | record.mmio_entry) ||
          record.mask != 0xff || (write(record) ? record.opcode > 1 : record.opcode != 4) ||
          bool(record.flags & device_flag) != transaction.bound.device ||
          (write(record) && record.data0 != transaction.request.data0))
        return invalid("MMIO map has inconsistent entry, opcode, mask or write bytes");
      auto &generation = mmio_generations[{record.hart, record.mmio_entry}];
      if (record.mmio_generation <= generation) return invalid("MMIO entry generation was reused");
      generation = record.mmio_generation;
      transaction.mmio = record;
    } else if (record.kind == SFUZZ_UC_AXI_ISSUE) {
      if (record.axi_slot != record.source_id || record.axi_slot >= route_slots(config.layout) ||
          !record.axi_generation || record.axi_id != endpoint_id(config.layout, record.axi_slot) ||
          record.access_size != 3 || record.burst_length)
        return invalid("AXI map has an inconsistent slot, generation, size or endpoint ID");
      auto &generation = axi_generations[record.axi_slot];
      if (record.axi_generation <= generation) return invalid("AXI CM generation was reused");
      generation = record.axi_generation;
      transaction.axi = record;
    } else if (record.kind == SFUZZ_UC_ENDPOINT_ACCEPT) {
      if (!record.endpoint_uid || record.access_size != 3 || record.burst_length ||
          !endpoint_uids.insert(record.endpoint_uid).second)
        return invalid("endpoint request UID, size or generation is invalid");
      transaction.accept = record;
    } else {
      if (record.axi_id != transaction.accept->axi_id) return invalid("endpoint response/effect ID changed");
      auto &target = record.kind == SFUZZ_UC_ENDPOINT_RESPONSE ? transaction.response : transaction.effect;
      if (target) return invalid("duplicate physical effect or endpoint response");
      if (record.flags & (denied_flag | corrupt_flag))
        return {CheckStatus::Unsupported, 0, "UC bridge: unsuccessful endpoint response"};
      if (record.kind == SFUZZ_UC_ENDPOINT_RESPONSE) {
        if (!(record.flags & last_flag)) return invalid("endpoint response was not single beat");
      } else {
        if (record.kind != (transaction.bound.write ? SFUZZ_UC_ENDPOINT_WRITE : SFUZZ_UC_ENDPOINT_READ) ||
            record.sample_cycle != record.emit_cycle || record.sample_edge != record.emit_edge ||
            record.sample_edge != (transaction.bound.write ? 0u : 1u) ||
            record.sample_time_ps != record.emit_time_ps || record.lane != (record.address & 31) ||
            record.beat_address != (record.address & ~uint64_t(31)) ||
            record.array_index != ((record.beat_address & ((uint64_t(1) << 40) - 1)) >> 5) ||
            record.mask != (uint64_t(0xff) << record.lane))
          return invalid("physical effect changed its actual sample time, beat address or byte lanes");
      }
      target = record;
    }
    return {};
  }
  CheckResult qualify(const UcTransactionKey &key_value, Transaction &transaction) {
    if (qualified.count(key_value) || !transaction.bus || !transaction.mmio || !transaction.axi ||
        !transaction.accept || !transaction.effect) return {};
    const auto &effect = *transaction.effect;
    if (time(*transaction.bus) > time(*transaction.mmio) || time(*transaction.mmio) > time(*transaction.axi) ||
        time(*transaction.axi) > time(*transaction.accept) || time(*transaction.accept) > time(effect))
      return invalid("route/effect causal order differs from actual source time");
    const uint64_t words[] = {effect.data0, effect.data1, effect.data2, effect.data3};
    const auto actual = bytes(words[effect.lane / 8]);
    if (transaction.bound.write && actual != transaction.bound.bytes)
      return {CheckStatus::Violation, 0, "UC bridge: physical write bytes differ from core request"};
    const bool complete = transaction.response && transaction.grant;
    if (complete) {
      if (time(effect) > time(*transaction.response) || time(*transaction.response) > time(*transaction.grant))
        return invalid("response/grant causal order differs from actual source time");
      if (!transaction.bound.write && actual != bytes(transaction.grant->data0))
        return {CheckStatus::Violation, 0, "UC bridge: physical read bytes differ from returned load"};
    }
    UcRouteProof proof{position(*transaction.bus), position(*transaction.mmio), position(*transaction.axi),
        position(*transaction.accept), position(effect),
        transaction.response ? position(*transaction.response) : UcRawPosition{},
        transaction.grant ? position(*transaction.grant) : UcRawPosition{},
        transaction.mmio->mmio_entry, transaction.mmio->mmio_generation, transaction.axi->chi_src,
        transaction.axi->chi_txn, transaction.axi->axi_slot, transaction.axi->axi_generation,
        transaction.axi->axi_id, transaction.accept->endpoint_uid};
    const UcJoinedEffect joined{transaction.bound, proof, actual, effect.sample_cycle, effect.sample_edge};
    // Only this pinned RAM layout proves that actual i_we / sampled o_rd is a
    // successful physical memory action before the later response and grant.
    if ((config.layout == UcBridgeLayout::PmaLite17 || complete) && !memory_ready.count(key_value)) {
      if (!memory_positions.emplace(position_key(position(effect)), key_value).second)
        return invalid("one physical effect was joined to two core transactions");
      memory_ready.emplace(key_value, joined);
    }
    if (complete) qualified.emplace(key_value, joined);
    return {};
  }
  CheckResult poll() {
    if (!status) return status;
    const auto closed = raw_closed();
    if (!closed) return {};
    std::stable_sort(records.begin(), records.end(), [](const auto &left, const auto &right) {
      return time(left) < time(right);
    });
    for (auto record = records.begin(); record != records.end();) {
      if (record->emit_cycle > *closed) { ++record; continue; }
      if (record->role == SFUZZ_UC_CORE) {
        const auto result = stage_core(*record);
        if (result.status == CheckStatus::Pending) { ++record; continue; }
        if (!result) return fail(result);
      } else mappings.push_back(*record);
      record = records.erase(record);
    }
    std::stable_sort(mappings.begin(), mappings.end(), [](const auto &left, const auto &right) {
      return time(left) < time(right);
    });
    bool progress;
    do {
      progress = false;
      for (auto record = mappings.begin(); record != mappings.end();) {
        auto *transaction = match(*record);
        if (!status) return status;
        if (!transaction) { ++record; continue; }
        const auto result = attach(*transaction, *record);
        if (!result) return fail(result);
        record = mappings.erase(record);
        progress = true;
      }
    } while (progress);
    for (auto &entry : transactions) {
      const auto result = qualify(entry.first, entry.second);
      if (!result) return fail(result);
    }
    for (auto entry = transactions.begin(); entry != transactions.end();) {
      if (entry->second.effect_delivered && qualified.count(entry->first)) entry = transactions.erase(entry);
      else ++entry;
    }
    return {};
  }
  UcBridgeState snapshot() const {
    UcBridgeState state;
    state.status = status;
    state.expected_producers = pinned_roster(config.layout).size();
    state.catalog_complete = sources.size() == state.expected_producers;
    for (const auto &entry : sources) {
      state.catalog_complete &= entry.second.asserted && entry.second.released;
      state.pending_prefixes += entry.second.prefixes.size();
    }
    state.raw_closed_through = raw_closed();
    state.fully_joined_closed_through = state.raw_closed_through;
    state.pending_records = records.size() + mappings.size();
    state.pending_transactions = transactions.size();
    auto hold = [&](uint64_t cycle) {
      if (!cycle) state.fully_joined_closed_through.reset();
      else if (state.fully_joined_closed_through)
        state.fully_joined_closed_through = std::min(*state.fully_joined_closed_through, cycle - 1);
    };
    // Prefixes prove that no earlier endpoint effects are hidden. Requests,
    // route mappings and late grants remain finish obligations, but cannot
    // invent a memory action or hold unrelated harts before an effect exists.
    for (const auto &effect : undelivered_effects) hold(positions.at(effect.second).cycle);
    for (const auto &entry : transactions) {
      const auto &transaction = entry.second;
      state.unacknowledged_requests += !transaction.request_delivered;
    }
    state.unacknowledged_effects = undelivered_effects.size();
    return state;
  }
};

UcBridge::UcBridge(UcBridgeConfig config) : impl_(new Impl(std::move(config))) {}
UcBridge::~UcBridge() = default;
UcBridge::UcBridge(UcBridge &&) noexcept = default;
UcBridge &UcBridge::operator=(UcBridge &&) noexcept = default;
CheckResult UcBridge::ingest(const SfuzzUcRawRecord &record) { return impl_->ingest(record); }
CheckResult UcBridge::bind_frame(const std::vector<uint64_t> &frames, const UcAllocationResolver &resolve) {
  return impl_->bind(frames, resolve);
}
CheckResult UcBridge::poll() { return impl_->poll(); }
UcBridgeState UcBridge::snapshot() const { return impl_->snapshot(); }
std::vector<UcRawWatermark> UcBridge::producer_watermarks() const {
  std::vector<UcRawWatermark> result;
  for (const auto &entry : impl_->sources) {
    const auto &source = entry.second;
    result.push_back({source.identity, impl_->config.epoch, source.sequence, source.closed,
                      source.asserted && source.released});
  }
  return result;
}
CheckResult UcBridge::drain_requests(const UcBoundRequestSink &sink) {
  if (!impl_->status) return impl_->status;
  std::vector<UcTransactionKey> pending_requests;
  for (const auto &entry : impl_->transactions)
    if (!entry.second.request_delivered) pending_requests.push_back(entry.first);
  std::sort(pending_requests.begin(), pending_requests.end(), [&](const auto &left, const auto &right) {
    const auto &a = impl_->transactions.at(left).bound.source;
    const auto &b = impl_->transactions.at(right).bound.source;
    return std::tie(a.producer, a.sequence) < std::tie(b.producer, b.sequence);
  });
  for (const auto &id : pending_requests) {
    auto &transaction = impl_->transactions.at(id);
    if (!sink) return impl_->fail(invalid("missing request consumer"));
    const auto result = sink(transaction.bound);
    if (!result) return result.status == CheckStatus::Pending ? result : impl_->fail(result);
    transaction.request_delivered = true;
  }
  return {};
}
CheckResult UcBridge::drain_effects(const UcJoinedEffectSink &sink) {
  auto result = impl_->poll();
  if (!result) return result;
  while (!impl_->undelivered_effects.empty()) {
    const auto first = impl_->undelivered_effects.begin();
    const auto binding = impl_->memory_positions.find(first->second);
    if (binding == impl_->memory_positions.end()) break;
    const auto &id = binding->second;
    auto &transaction = impl_->transactions.at(id);
    if (!transaction.request_delivered) break;
    if (!sink) return impl_->fail(invalid("missing effect consumer"));
    result = sink(impl_->memory_ready.at(id));
    if (!result) return result.status == CheckStatus::Pending ? result : impl_->fail(result);
    transaction.effect_delivered = true;
    if (impl_->qualified.count(id)) impl_->transactions.erase(id);
    impl_->undelivered_effects.erase(first);
  }
  return {};
}
CheckResult UcBridge::validate_position(const UcRawPosition &where) const {
  if (!impl_->status) return impl_->status;
  const auto found = impl_->positions.find(position_key(where));
  return found != impl_->positions.end() && found->second == where ? CheckResult{} : invalid("raw source position was relabeled");
}
CheckResult UcBridge::validate_qualified_effect(const UcTransactionKey &transaction, const UcRawPosition &where) const {
  auto result = validate_position(where);
  if (!result) return result;
  const auto found = impl_->qualified.find(transaction);
  if (found != impl_->qualified.end() && found->second.proof.endpoint_effect == where) return {};
  const auto memory = impl_->memory_ready.find(transaction);
  if (memory != impl_->memory_ready.end() && memory->second.proof.endpoint_effect == where)
    return pending("memory effect awaits its successful response and core grant");
  return invalid("raw event has no complete qualified transaction proof");
}
CheckResult UcBridge::validate_memory_effect(const UcTransactionKey &transaction, const UcRawPosition &where) const {
  auto result = validate_position(where);
  if (!result) return result;
  const auto found = impl_->memory_ready.find(transaction);
  return found != impl_->memory_ready.end() && found->second.proof.endpoint_effect == where
      ? CheckResult{} : invalid("raw event has no exact memory-ready transaction proof");
}
std::optional<uint64_t> UcBridge::effective_watermark(std::optional<uint64_t> legacy_closed) const {
  const auto state = snapshot();
  if (!state.status || !legacy_closed || !state.fully_joined_closed_through) return {};
  return std::min(*legacy_closed, *state.fully_joined_closed_through);
}
CheckResult UcBridge::finish() const {
  const auto state = snapshot();
  if (!state.status) return state.status;
  if (!state.catalog_complete || !state.raw_closed_through || state.pending_prefixes || state.pending_records ||
      state.pending_transactions || state.unacknowledged_requests || state.unacknowledged_effects)
    return pending("raw producer prefixes, identity joins or consumer acknowledgements remain open");
  return {};
}
} // namespace rvwmo
#endif // DIFFTEST_S_UC_NATIVE_V1
