#include "adapter.h"
#include <algorithm>
#include <functional>
#include <limits>
#include <map>
#include <queue>
#include <set>
#include <utility>

namespace blackparrot {
namespace {
ConversionResult invalid(const char *message) { return {ConversionStatus::Invalid, message}; }
ConversionResult waiting(const char *message) { return {ConversionStatus::Waiting, message}; }
ConversionResult incomplete(const char *message) { return {ConversionStatus::Incomplete, message}; }
ConversionResult unsupported(const char *message) { return {ConversionStatus::Unsupported, message}; }

rvwmo::OperationId parent_id(const rvwmo::OperationId &id) { return {id.hart, id.epoch, id.uid, 0}; }

bool same_position(const rvwmo::SourcePosition &left, const rvwmo::SourcePosition &right) {
  return left.cycle == right.cycle && left.qualified_phase == right.qualified_phase &&
         left.producer_sequence == right.producer_sequence && left.order_qualified == right.order_qualified;
}

bool closes(const rvwmo::SourcePosition &watermark, const rvwmo::SourcePosition &position) {
  if (position.cycle != watermark.cycle)
    return position.cycle < watermark.cycle;
  if (watermark.order_qualified && watermark.qualified_phase == rvwmo::SourcePosition::cycle_closed_phase)
    return true;
  if (!watermark.order_qualified || !position.order_qualified)
    return false;
  if (position.qualified_phase != watermark.qualified_phase)
    return position.qualified_phase < watermark.qualified_phase;
  return position.producer_sequence <= watermark.producer_sequence;
}

ConversionResult validate_range(uint64_t address, const std::vector<uint8_t> &bytes,
                                const std::vector<uint8_t> &mask) {
  if (bytes.empty() || bytes.size() != mask.size() ||
      bytes.size() - 1 > std::numeric_limits<uint64_t>::max() - address)
    return invalid("memory bytes/mask are empty, mismatched or wrap the address space");
  if (bytes.size() > 8)
    return unsupported("split/vector memory effects exceed the scalar BlackParrot adapter profile");
  if (std::any_of(mask.begin(), mask.end(), [](uint8_t byte) { return byte > 1; }) ||
      std::none_of(mask.begin(), mask.end(), [](uint8_t byte) { return byte == 1; }))
    return invalid("byte masks must contain binary lanes and at least one enabled byte");
  return {};
}

bool needs_writeback(const RetireRecord &record) {
  return record.integer_writeback && record.rd != 0 && !record.register_value;
}

void clear_model_times(rvwmo::MemoryOperation &operation) {
  // GMO is resolved by the caller after stream closure, never at conversion.
  operation.read_time = {};
  operation.write_time = {};
}

using CandidateQueue = std::priority_queue<size_t, std::vector<size_t>, std::greater<size_t>>;

void normalize_cycle(std::vector<rvwmo::RuntimeEvent> &events, size_t begin, size_t end,
                     std::vector<ConversionDiagnostic> &diagnostics) {
  struct ProducerEvents {
    std::vector<size_t> indices;
    size_t next = 0;
  };

  std::map<uint32_t, ProducerEvents> by_producer;
  std::map<uint16_t, size_t> remaining_phases;
  for (size_t index = begin; index < end; ++index) {
    const auto &event = events[index];
    by_producer[event.producer_id].indices.push_back(index);
    if (event.source.order_qualified)
      ++remaining_phases[event.source.qualified_phase];
  }
  for (auto &producer : by_producer)
    std::sort(producer.second.indices.begin(), producer.second.indices.end(), [&](size_t left, size_t right) {
      return events[left].source.producer_sequence < events[right].source.producer_sequence;
    });

  CandidateQueue unqualified_fronts;
  std::map<uint16_t, CandidateQueue> phase_fronts;
  const auto enqueue_front = [&](ProducerEvents &producer) {
    if (producer.next == producer.indices.size())
      return;
    const size_t index = producer.indices[producer.next];
    const auto &source = events[index].source;
    if (source.order_qualified)
      phase_fronts[source.qualified_phase].push(index);
    else
      unqualified_fronts.push(index);
  };
  for (auto &producer : by_producer)
    enqueue_front(producer.second);

  const auto is_current_front = [&](size_t index) {
    const auto producer = by_producer.find(events[index].producer_id);
    return producer != by_producer.end() && producer->second.next < producer->second.indices.size() &&
           producer->second.indices[producer->second.next] == index;
  };
  const auto discard_stale = [&](CandidateQueue &candidates) {
    while (!candidates.empty() && !is_current_front(candidates.top()))
      candidates.pop();
  };

  std::vector<size_t> order;
  order.reserve(end - begin);
  while (order.size() < end - begin) {
    discard_stale(unqualified_fronts);
    CandidateQueue *qualified_front = nullptr;
    if (!remaining_phases.empty()) {
      qualified_front = &phase_fronts[remaining_phases.begin()->first];
      discard_stale(*qualified_front);
    }

    const bool has_unqualified = !unqualified_fronts.empty();
    const bool has_qualified = qualified_front && !qualified_front->empty();
    if (!has_unqualified && !has_qualified) {
      diagnostics.push_back({rvwmo::CheckStatus::Incomplete, {},
                             "same-cycle per-producer sequences conflict with qualified source phases"});
      order.clear();
      for (size_t index = begin; index < end; ++index)
        order.push_back(index);
      break;
    }

    CandidateQueue *selected_front = nullptr;
    if (!has_qualified || (has_unqualified && unqualified_fronts.top() < qualified_front->top()))
      selected_front = &unqualified_fronts;
    else
      selected_front = qualified_front;
    const size_t selected = selected_front->top();
    selected_front->pop();
    order.push_back(selected);

    const auto &source = events[selected].source;
    if (source.order_qualified) {
      auto phase = remaining_phases.find(source.qualified_phase);
      if (--phase->second == 0)
        remaining_phases.erase(phase);
    }
    auto &producer = by_producer.at(events[selected].producer_id);
    ++producer.next;
    enqueue_front(producer);
  }

  std::vector<rvwmo::RuntimeEvent> ordered;
  ordered.reserve(end - begin);
  for (const auto index : order)
    ordered.push_back(std::move(events[index]));
  std::move(ordered.begin(), ordered.end(), events.begin() + begin);
}

void normalize_source_order(ConvertedOutput &output) {
  auto &events = output.batch.events;
  // Source cycles share a clock domain. Within one cycle, retain each producer's
  // factual sequence and only apply cross-producer phase evidence when qualified.
  std::stable_sort(events.begin(), events.end(), [](const auto &left, const auto &right) {
    return left.source.cycle < right.source.cycle;
  });
  for (size_t begin = 0; begin < events.size();) {
    size_t end = begin + 1;
    while (end < events.size() && events[end].source.cycle == events[begin].source.cycle)
      ++end;
    normalize_cycle(events, begin, end, output.diagnostics);
    begin = end;
  }
}
} // namespace

struct Adapter::State {
  struct Instruction {
    rvwmo::InstructionAllocateEvent allocation;
    Origin allocated_at;
    std::map<uint32_t, rvwmo::LoadSampleEvent> loads;
    std::map<uint32_t, Origin> sampled_at;
    std::set<uint32_t> cancelled;
    std::optional<uint32_t> highest_attempt;
    std::optional<WritebackRecord> writeback;
    std::optional<RetireRecord> retirement;
    Origin retired_at;
  };
  struct Store {
    rvwmo::LocalStoreEvent local;
    Origin local_origin;
    bool retired = false;
    bool published = false;
  };

  Configuration options;
  ConversionResult configured;
  std::map<uint32_t, HartChannels> harts;
  std::set<uint32_t> producers;
  std::set<uint32_t> publication_producers;
  std::map<uint32_t, rvwmo::SourcePosition> last_sources;
  std::map<uint32_t, rvwmo::SourcePosition> watermarks;
  std::map<uint32_t, std::pair<uint64_t, uint64_t>> last_allocation;
  std::map<uint32_t, uint64_t> last_retirement;
  std::set<uint32_t> done_harts;
  std::map<rvwmo::OperationId, Instruction> instructions;
  std::map<rvwmo::OperationId, Store> stores;
  std::set<uint64_t> transactions;
  ConvertedOutput output;

  explicit State(Configuration configuration) : options(std::move(configuration)) {
    if (options.harts.empty() || options.max_live_instructions == 0 ||
        options.max_publication_transactions == 0) {
      configured = invalid("adapter needs an explicit hart/channel roster and nonzero instruction/transaction bounds");
      return;
    }
    std::map<uint32_t, uint32_t> owners;
    for (const auto &channels : options.harts) {
      if (!harts.emplace(channels.hart, channels).second) {
        configured = invalid("duplicate architectural hart in adapter configuration");
        return;
      }
      for (auto producer : {channels.instruction, channels.memory, channels.control}) {
        if (!producer || (owners.count(producer) && owners.at(producer) != channels.hart)) {
          configured = invalid("hart channels must be nonzero and may be merged only within one hart");
          return;
        }
        owners[producer] = channels.hart;
        producers.insert(producer);
      }
    }
    for (auto producer : options.publication_producers) {
      if (!producer || producers.count(producer) || !publication_producers.insert(producer).second) {
        configured = invalid("publication channels must be unique and separate from hart-private channels");
        return;
      }
      producers.insert(producer);
    }
  }

  ConversionResult validate_id(const rvwmo::OperationId &id) const {
    if (!configured)
      return configured;
    if (!harts.count(id.hart) || !id.uid)
      return invalid("operation has an unconfigured hart or zero dispatch UID");
    return {};
  }

  ConversionResult validate_origin(const Origin &origin, uint32_t expected_producer) const {
    if (!configured)
      return configured;
    if (!origin.producer_id || origin.producer_id != expected_producer || !producers.count(origin.producer_id))
      return invalid("observation producer does not match its configured source channel");
    const auto &source = origin.source;
    if (!source.producer_sequence || source.qualified_phase == rvwmo::SourcePosition::cycle_closed_phase)
      return invalid("event source sequence is zero or uses the reserved cycle-closure phase");
    const auto previous = last_sources.find(origin.producer_id);
    if (previous != last_sources.end()) {
      const auto &last = previous->second;
      if (source.producer_sequence <= last.producer_sequence || source.cycle < last.cycle ||
          (source.cycle == last.cycle && source.order_qualified && last.order_qualified &&
           source.qualified_phase < last.qualified_phase))
        return invalid("producer sequence/cycle/qualified phase is duplicated or regressed");
    }
    const auto watermark = watermarks.find(origin.producer_id);
    if (watermark != watermarks.end()) {
      if (closes(watermark->second, source))
        return invalid("observation arrived inside an already closed source prefix");
      if (source.cycle == watermark->second.cycle &&
          (!source.order_qualified || !watermark->second.order_qualified))
        return waiting("same-cycle observation cannot be ordered after a partial source watermark");
    }
    for (const auto &watermark : output.batch.watermarks)
      if (watermark.producer_id == origin.producer_id)
        return waiting("deliver the queued producer watermark with take_output before appending its next prefix");
    return {};
  }

  ConversionResult validate_live(const rvwmo::OperationId &id, const Origin &origin, uint32_t channel,
                                 bool allow_retired = false) const {
    auto result = validate_id(id);
    if (!result)
      return result;
    if (id.subaccess != 0)
      return unsupported("split/vector operation identities exceed the scalar adapter profile");
    result = validate_origin(origin, channel);
    if (!result)
      return result;
    const auto instruction = instructions.find(id);
    if (instruction == instructions.end())
      return invalid("observation has no live dispatch allocation");
    if (!allow_retired && instruction->second.retirement)
      return invalid("instruction observation arrived after its architectural retirement record");
    if (origin.source.cycle < instruction->second.allocated_at.source.cycle)
      return invalid("instruction observation predates its dispatch allocation");
    return {};
  }

  uint32_t channel(const rvwmo::OperationId &id, uint32_t HartChannels::*member) const {
    const auto hart = harts.find(id.hart);
    return hart == harts.end() ? 0 : hart->second.*member;
  }

  void append(const Origin &origin, rvwmo::RuntimeEventKind kind, rvwmo::RuntimeEventPayload payload) {
    last_sources[origin.producer_id] = origin.source;
    output.batch.events.push_back({origin.producer_id, origin.source, kind, std::move(payload)});
  }

  static size_t missing_load_samples(const Instruction &live) {
    if (!live.retirement)
      return 0;
    size_t missing = 0;
    for (const auto &operation : live.retirement->memory)
      if (operation.load && !operation.atomic && !operation.lr && !operation.sc &&
          !live.loads.count(operation.attempt))
        ++missing;
    return missing;
  }

  void flush_retirements(uint32_t hart) {
    for (auto instruction = instructions.begin(); instruction != instructions.end();) {
      if (instruction->first.hart != hart) {
        ++instruction;
        continue;
      }
      auto &live = instruction->second;
      if (!live.retirement || needs_writeback(*live.retirement) || missing_load_samples(live))
        return;
      auto record = *live.retirement;
      for (const auto &operation : record.memory) {
        const auto sample = live.sampled_at.find(operation.attempt);
        if (operation.load && sample != live.sampled_at.end() &&
            sample->second.source.cycle > live.retired_at.source.cycle)
          output.diagnostics.push_back({rvwmo::CheckStatus::Incomplete, record.id,
                                        "load sample occurs after architectural retirement; current source-ordered "
                                        "consumer requires its sample before retirement"});
      }
      rvwmo::RetiredInstruction retired;
      retired.hart = record.id.hart;
      retired.epoch = record.id.epoch;
      retired.uid = record.id.uid;
      retired.pc = record.pc;
      retired.instruction = record.instruction;
      retired.failed_sc = record.failed_sc;
      retired.memory = record.memory;
      for (auto &operation : retired.memory)
        clear_model_times(operation);
      // The source record was validated when it arrived, possibly before WB.
      output.batch.events.push_back({live.retired_at.producer_id, live.retired_at.source,
                                    rvwmo::RuntimeEventKind::InstructionRetire,
                                    rvwmo::InstructionRetireEvent{std::move(retired), record.loads}});
      output.retirements.push_back({live.retired_at, std::move(record),
                                   live.writeback ? std::optional<uint64_t>{live.writeback->source_cycle}
                                                  : std::nullopt});
      auto store = stores.find(instruction->first);
      if (store != stores.end()) {
        store->second.retired = true;
        if (store->second.published)
          stores.erase(store);
      }
      instruction = instructions.erase(instruction);
    }
  }
};

Adapter::Adapter(Configuration configuration) : state_(new State(std::move(configuration))) {}
Adapter::~Adapter() = default;
Adapter::Adapter(Adapter &&) noexcept = default;
Adapter &Adapter::operator=(Adapter &&) noexcept = default;
const ConversionResult &Adapter::configuration() const { return state_->configured; }

ConversionResult Adapter::allocate(const Origin &origin, const rvwmo::InstructionAllocateEvent &record) {
  auto &state = *state_;
  auto result = state.validate_id(record.id);
  if (!result)
    return result;
  if (record.id.subaccess != 0)
    return invalid("instruction allocation requires a parent identity with subaccess zero");
  result = state.validate_origin(origin, state.channel(record.id, &HartChannels::instruction));
  if (!result)
    return result;
  if (state.done_harts.count(record.id.hart))
    return invalid("instruction allocated after the hart's architectural done notification");
  if (record.pc % 2)
    return invalid("instruction allocation PC is not halfword aligned");
  if (record.length == 6 || record.length == 8)
    return unsupported("extended-length instruction allocation exceeds the scalar adapter profile");
  if (record.length != 2 && record.length != 4)
    return invalid("instruction length must be 2 or 4 bytes");
  if (((record.instruction & 3) != 3) != (record.length == 2) ||
      (record.length == 2 && (record.instruction >> 16) != 0))
    return invalid("instruction bits and declared length disagree");
  if (record.length == 4 && ((record.instruction >> 2) & 7) == 7)
    return unsupported("extended instruction encoding exceeds the scalar adapter profile");
  auto previous = state.last_allocation.find(record.id.hart);
  if (previous != state.last_allocation.end()) {
    if (record.id.epoch != previous->second.first)
      return unsupported("epoch changes need a fresh generic checker session; squash is not represented");
    if (record.id.uid <= previous->second.second)
      return invalid("dispatch UID is not strictly increasing within the hart/epoch");
  }
  if (state.instructions.size() >= state.options.max_live_instructions)
    return waiting("live instruction limit reached; retain and retry allocation after retirement");
  State::Instruction live;
  live.allocation = record;
  live.allocated_at = origin;
  state.instructions.emplace(record.id, std::move(live));
  state.last_allocation[record.id.hart] = {record.id.epoch, record.id.uid};
  state.append(origin, rvwmo::RuntimeEventKind::InstructionAllocate, record);
  return {};
}

ConversionResult Adapter::load_sample(const Origin &origin, const rvwmo::LoadSampleEvent &record) {
  auto &state = *state_;
  const auto &operation = record.operation;
  auto result = state.validate_live(operation.id, origin, state.channel(operation.id, &HartChannels::memory), true);
  if (!result)
    return result;
  if (operation.atomic || operation.lr || operation.sc)
    return unsupported("atomic/LRSC samples require their actual atomic lifecycle, not ordinary LoadSample");
  if (!operation.load || operation.store)
    return invalid("ordinary load sample must contain exactly a load effect");
  result = validate_range(operation.address, record.actual_bytes, operation.byte_mask);
  if (!result)
    return result;
  if ((!record.forwarded_writers.empty() && record.forwarded_writers.size() != record.actual_bytes.size()) ||
      (!operation.read_sources.empty() && operation.read_sources.size() != record.actual_bytes.size()))
    return invalid("load provenance does not have one entry per byte lane");
  auto &live = state.instructions.at(operation.id);
  if (state.stores.count(operation.id))
    return invalid("ordinary instruction cannot contain both a local store and a load sample");
  if (live.retirement) {
    const auto &selected = live.retirement->memory;
    if (selected.size() != 1 || !selected[0].load || selected[0].atomic || selected[0].lr || selected[0].sc ||
        selected[0].attempt != operation.attempt || selected[0].address != operation.address ||
        selected[0].byte_mask != operation.byte_mask)
      return invalid("late sample differs from the final attempt selected by architectural retirement");
  }
  if (live.cancelled.count(operation.attempt) || live.loads.count(operation.attempt) ||
      (live.highest_attempt && operation.attempt <= *live.highest_attempt))
    return invalid("load attempt is cancelled, duplicated or older than an observed attempt");
  auto sample = record;
  clear_model_times(sample.operation);
  live.loads.emplace(operation.attempt, sample);
  live.sampled_at.emplace(operation.attempt, origin);
  live.highest_attempt = operation.attempt;
  state.append(origin, rvwmo::RuntimeEventKind::LoadSample, std::move(sample));
  state.flush_retirements(operation.id.hart);
  return {};
}

ConversionResult Adapter::cancel_load(const Origin &origin, const rvwmo::InstructionCancelAttemptEvent &record) {
  auto &state = *state_;
  auto result = state.validate_live(record.id, origin, state.channel(record.id, &HartChannels::memory));
  if (!result)
    return result;
  auto &live = state.instructions.at(record.id);
  if (state.stores.count(record.id) || live.cancelled.count(record.attempt))
    return invalid("attempt cancellation is duplicated or targets an ordinary store");
  live.cancelled.insert(record.attempt);
  live.loads.erase(record.attempt);
  live.sampled_at.erase(record.attempt);
  if (!live.highest_attempt || *live.highest_attempt < record.attempt)
    live.highest_attempt = record.attempt;
  state.append(origin, rvwmo::RuntimeEventKind::InstructionCancelAttempt, record);
  return {};
}

ConversionResult Adapter::local_store(const Origin &origin, const rvwmo::LocalStoreEvent &record) {
  auto &state = *state_;
  auto result = state.validate_live(record.id, origin, state.channel(record.id, &HartChannels::memory));
  if (!result)
    return result;
  result = validate_range(record.address, record.bytes, record.byte_mask);
  if (!result)
    return result;
  const auto &live = state.instructions.at(record.id);
  if (state.stores.count(record.id) || !live.loads.empty() || !live.cancelled.empty())
    return invalid("LocalStore is duplicated or shares an ordinary load instruction identity");
  if (state.stores.size() >= state.options.max_live_instructions)
    return waiting("outstanding LocalStore limit reached; retain and retry after publication/retirement");
  state.stores.emplace(record.id, State::Store{record, origin, false, false});
  state.append(origin, rvwmo::RuntimeEventKind::LocalStore, record);
  return {};
}

ConversionResult Adapter::publish_store(const Origin &origin, const rvwmo::StorePublishEvent &record) {
  auto &state = *state_;
  if (!state.configured)
    return state.configured;
  if (!state.publication_producers.count(origin.producer_id))
    return invalid("StorePublish did not come from a configured publication source");
  auto result = state.validate_origin(origin, origin.producer_id);
  if (!result)
    return result;
  if (record.members.size() != 1)
    return unsupported("current generic consumer supports exactly one logical writer per StorePublish");
  result = validate_range(record.address, record.bytes, record.byte_mask);
  if (!result)
    return result;
  if (!record.transaction_id || state.transactions.count(record.transaction_id) ||
      record.byte_writers.size() != record.bytes.size())
    return invalid("publication transaction is zero/duplicated or byte-writer shape is invalid");
  const auto &member = record.members.front();
  if (!same_position(member.publish_position, origin.source))
    return invalid("single-store publication member must retain the envelope source position");
  auto store = state.stores.find(member.id);
  if (store == state.stores.end() || store->second.published)
    return invalid("publication has no unique unpublished LocalStore identity");
  const auto &local_origin = store->second.local_origin;
  if (local_origin.source.cycle > origin.source.cycle)
    return invalid("StorePublish source time predates its LocalStore");
  if (local_origin.source.cycle == origin.source.cycle) {
    if (!local_origin.source.order_qualified || !origin.source.order_qualified)
      return incomplete("same-cycle LocalStore and StorePublish lack a qualified source order");
    if (local_origin.source.qualified_phase > origin.source.qualified_phase)
      return invalid("StorePublish source phase predates its LocalStore phase");
    if (local_origin.source.qualified_phase == origin.source.qualified_phase) {
      if (local_origin.producer_id != origin.producer_id)
        return incomplete("same-cycle LocalStore and StorePublish share a phase across unordered producers");
      if (local_origin.source.producer_sequence >= origin.source.producer_sequence)
        return invalid("StorePublish does not follow its LocalStore in their shared producer sequence");
    }
  }
  const auto &local = store->second.local;
  if (record.address != local.address || record.byte_mask != local.byte_mask ||
      record.bytes.size() != local.bytes.size())
    return invalid("StorePublish address/mask/size differs from its LocalStore");
  for (size_t byte = 0; byte < record.bytes.size(); ++byte) {
    if (record.byte_mask[byte] && (record.byte_writers[byte] != member.id || record.bytes[byte] != local.bytes[byte]))
      return invalid("enabled publication byte has the wrong writer identity or LocalStore value");
  }
  if (state.transactions.size() >= state.options.max_publication_transactions)
    return unsupported("exact publication transaction history bound exhausted; safe deduplication cannot continue");
  store->second.published = true;
  if (store->second.retired)
    state.stores.erase(store);
  state.transactions.insert(record.transaction_id);
  state.append(origin, rvwmo::RuntimeEventKind::StorePublish, record);
  return {};
}

ConversionResult Adapter::retire(const Origin &origin, const RetireRecord &record) {
  auto &state = *state_;
  auto result = state.validate_live(record.id, origin, state.channel(record.id, &HartChannels::instruction));
  if (!result)
    return result;
  auto &live = state.instructions.at(record.id);
  if (record.pc != live.allocation.pc || record.instruction != live.allocation.instruction ||
      record.length != live.allocation.length || record.rd >= 32)
    return invalid("retirement PC/instruction/length/rd differs from its dispatch allocation");
  auto last_retired = state.last_retirement.find(record.id.hart);
  if (last_retired != state.last_retirement.end() && record.id.uid <= last_retired->second)
    return invalid("retirement UID is not strictly increasing per hart");
  for (const auto &earlier : state.instructions)
    if (earlier.first.hart == record.id.hart && earlier.first.uid < record.id.uid && !earlier.second.retirement)
      return invalid("retirement bypassed an earlier live instruction in this in-order hart");
  if (!record.integer_writeback && record.register_value)
    return invalid("retirement provides a register value without integer writeback");
  if (record.integer_writeback && record.length == 4 && record.rd != ((record.instruction >> 7) & 31))
    return invalid("architectural writeback register differs from the retired instruction rd");
  if (live.writeback && (!record.integer_writeback || record.rd != live.writeback->rd ||
                         (record.register_value && *record.register_value != live.writeback->value)))
    return invalid("retirement and its identified writeback disagree");
  if (record.memory.size() > 1)
    return unsupported("split/vector retirement exceeds the scalar adapter profile");

  bool selected_load = false;
  bool selected_store = false;
  bool atomic_retirement = false;
  std::optional<uint32_t> selected_attempt;
  for (const auto &operation : record.memory) {
    if (operation.id != record.id)
      return invalid("retired memory effect has a different hart/epoch/UID/subaccess");
    if (operation.atomic || operation.lr || operation.sc) {
      // Transport true atomic effects and DUT actual values. Do not synthesize
      // ordinary samples/stores to bypass the public consumer's missing path.
      atomic_retirement = true;
      if (!operation.load && !operation.store)
        return invalid("atomic retirement has no read or write effect");
      const std::vector<uint8_t> lanes(operation.byte_mask.size());
      result = validate_range(operation.address, lanes, operation.byte_mask);
      if (!result)
        return result;
      continue;
    }
    if (operation.load == operation.store)
      return invalid("ordinary retirement must select exactly a load or a store effect");
    if (operation.load) {
      auto sample = live.loads.find(operation.attempt);
      if (live.cancelled.count(operation.attempt) ||
          (sample == live.loads.end() && live.highest_attempt && operation.attempt <= *live.highest_attempt))
        return invalid("retirement selected a cancelled or superseded load attempt");
      if (sample != live.loads.end() &&
          (sample->second.operation.address != operation.address ||
           sample->second.operation.byte_mask != operation.byte_mask))
        return invalid("retired load address/mask differs from its selected sample");
      if (record.loads.size() != 1 || record.loads.front().id != record.id ||
          record.loads.front().attempt != operation.attempt ||
          record.loads.front().bytes.size() != operation.byte_mask.size())
        return invalid("retirement lacks exactly one architectural value for its selected load attempt");
      result = validate_range(operation.address, record.loads.front().bytes, operation.byte_mask);
      if (!result)
        return result;
      selected_load = true;
      selected_attempt = operation.attempt;
    } else {
      const auto store = state.stores.find(record.id);
      if (store == state.stores.end() || store->second.local.address != operation.address ||
          store->second.local.byte_mask != operation.byte_mask)
        return invalid("retired store has no matching LocalStore address/mask");
      selected_store = true;
    }
  }
  if ((!selected_load && (!live.loads.empty() || (!atomic_retirement && !record.loads.empty()))) ||
      (selected_load && (live.loads.size() > 1 ||
                         (!live.loads.empty() && live.loads.begin()->first != *selected_attempt))) ||
      (state.stores.count(record.id) && !selected_store))
    return invalid("retirement omitted a live memory effect or left an uncancelled attempt unselected");

  live.retirement = record;
  live.retired_at = origin;
  if (live.writeback)
    live.retirement->register_value = live.writeback->value;
  state.last_retirement[record.id.hart] = record.id.uid;
  state.last_sources[origin.producer_id] = origin.source;
  state.flush_retirements(record.id.hart);
  return {};
}

ConversionResult Adapter::writeback(const WritebackRecord &record) {
  auto &state = *state_;
  auto result = state.validate_id(record.id);
  if (!result)
    return result;
  const auto instruction = state.instructions.find(record.id);
  if (record.id.subaccess || record.rd == 0 || record.rd >= 32 || instruction == state.instructions.end())
    return invalid("architectural writeback has no live parent identity or nonzero integer rd");
  auto &live = instruction->second;
  if (live.allocation.length == 4 && record.rd != ((live.allocation.instruction >> 7) & 31))
    return invalid("architectural writeback rd differs from its allocated instruction");
  if (live.writeback || record.source_cycle < live.allocated_at.source.cycle)
    return invalid("architectural writeback is duplicated or predates its dispatch allocation");
  if (live.retirement && (!needs_writeback(*live.retirement) || live.retirement->rd != record.rd))
    return invalid("delayed writeback does not match the pending retirement rd/identity");
  live.writeback = record;
  if (live.retirement)
    live.retirement->register_value = record.value;
  state.flush_retirements(record.id.hart);
  return {};
}

ConversionResult Adapter::atomic(const Origin &origin, const rvwmo::AtomicLifecycleEvent &record) {
  auto &state = *state_;
  auto result = state.validate_live(parent_id(record.id), origin, state.channel(record.id, &HartChannels::control));
  if (!result)
    return result;
  const auto phase = static_cast<unsigned>(record.phase);
  if (phase < static_cast<unsigned>(rvwmo::AtomicObservationPhase::ReadEffect) ||
      phase > static_cast<unsigned>(rvwmo::AtomicObservationPhase::Cancel) ||
      ((record.phase == rvwmo::AtomicObservationPhase::ReadEffect ||
        record.phase == rvwmo::AtomicObservationPhase::WriteEffect) && !record.mask))
    return invalid("atomic lifecycle phase or effect mask is invalid");
  state.append(origin, rvwmo::RuntimeEventKind::AtomicLifecycle, record);
  return {};
}

ConversionResult Adapter::trap(const Origin &origin, const rvwmo::TrapEvent &record) {
  auto &state = *state_;
  if (record.hart != record.instruction.hart)
    return invalid("trap hart differs from its instruction identity");
  auto result = state.validate_live(record.instruction, origin,
                                    state.channel(record.instruction, &HartChannels::control), true);
  if (!result)
    return result;
  if (record.pc != state.instructions.at(record.instruction).allocation.pc)
    return invalid("trap PC differs from its live dispatch allocation");
  state.append(origin, rvwmo::RuntimeEventKind::Trap, record);
  return {};
}

ConversionResult Adapter::hart_done(const Origin &origin, const rvwmo::HartDoneEvent &record) {
  auto &state = *state_;
  const auto hart = state.harts.find(record.hart);
  if (hart == state.harts.end())
    return invalid("HartDone names an unconfigured architectural hart");
  auto result = state.validate_origin(origin, hart->second.control);
  if (!result)
    return result;
  if (!state.done_harts.insert(record.hart).second)
    return invalid("duplicate HartDone notification");
  state.append(origin, rvwmo::RuntimeEventKind::HartDone, record);
  return {};
}

ConversionResult Adapter::close_prefix(const rvwmo::ProducerWatermark &watermark) {
  auto &state = *state_;
  if (!state.configured)
    return state.configured;
  if (!state.producers.count(watermark.producer_id))
    return invalid("watermark names a producer outside the caller-configured roster");
  const auto previous = state.watermarks.find(watermark.producer_id);
  if (previous != state.watermarks.end() && !closes(watermark.closed_through, previous->second))
    return invalid("producer watermark regressed or cannot be ordered against the prior prefix");
  const auto last = state.last_sources.find(watermark.producer_id);
  if (last != state.last_sources.end() && !closes(watermark.closed_through, last->second))
    return waiting("source prefix does not cover every observed event on this producer");
  for (const auto &instruction : state.instructions) {
    const auto &live = instruction.second;
    if (live.retirement && live.retired_at.producer_id == watermark.producer_id &&
        closes(watermark.closed_through, live.retired_at.source))
      return waiting("source prefix contains a retirement awaiting writeback, load sample or an earlier retirement");
  }
  state.watermarks[watermark.producer_id] = watermark.closed_through;
  auto &pending = state.output.batch.watermarks;
  auto same_producer = std::find_if(pending.begin(), pending.end(), [&](const rvwmo::ProducerWatermark &entry) {
    return entry.producer_id == watermark.producer_id;
  });
  if (same_producer == pending.end())
    pending.push_back(watermark);
  else
    *same_producer = watermark;
  return {};
}

ConversionResult Adapter::squash(const Origin &origin, const rvwmo::OperationId &id) {
  auto &state = *state_;
  auto result = state.validate_id(id);
  if (!result)
    return result;
  if (id.subaccess != 0)
    return unsupported("split instruction squash is not covered by this scalar adapter");
  result = state.validate_origin(origin, state.channel(id, &HartChannels::memory));
  if (!result)
    return result;
  const auto instruction = state.instructions.find(id);
  if (instruction == state.instructions.end())
    return invalid("instruction squash has no live allocation");
  if (instruction->second.retirement)
    return invalid("architecturally retired instruction cannot be squashed");
  if (origin.source.cycle < instruction->second.allocated_at.source.cycle)
    return invalid("instruction squash source time predates its allocation");
  if (state.stores.count(id))
    return invalid("instruction with a committed LocalStore cannot be squashed");
  for (const auto &sample : instruction->second.sampled_at)
    if (origin.source.cycle < sample.second.source.cycle)
      return invalid("instruction squash source time predates a captured load sample");

  state.append(origin, rvwmo::RuntimeEventKind::InstructionSquash, rvwmo::InstructionSquashEvent{id});
  state.instructions.erase(instruction);
  return {};
}

ConvertedOutput Adapter::take_output() {
  auto output = std::move(state_->output);
  state_->output = {};
  normalize_source_order(output);
  return output;
}

PendingState Adapter::pending() const {
  PendingState pending;
  pending.instructions = state_->instructions.size();
  for (const auto &instruction : state_->instructions)
    if (instruction.second.retirement && needs_writeback(*instruction.second.retirement))
      ++pending.writebacks;
  for (const auto &instruction : state_->instructions)
    pending.load_samples += State::missing_load_samples(instruction.second);
  for (const auto &store : state_->stores)
    if (!store.second.published)
      ++pending.unpublished_stores;
  return pending;
}

std::vector<std::string> Adapter::consumer_gaps() {
  return {"generic atomic/AMO/LRSC lifecycle semantic consumption",
          "generic trap/interrupt and HartDone semantic consumption and memory-drain finalization",
          "epoch transition in an existing checker session",
          "source-ordered retirement before a physically later load sample (BlackParrot refill miss)",
          "merged multi-store publication, split/vector memory effects and cache-block operations"};
}

} // namespace blackparrot
