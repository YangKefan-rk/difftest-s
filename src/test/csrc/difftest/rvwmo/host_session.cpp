#include "host_session.h"
#include "producer_ids.h"
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace rvwmo {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult incomplete(const char *message) { return {CheckStatus::Incomplete, 0, message}; }

std::vector<uint32_t> event_harts(const RuntimeEvent &event) {
  switch (event.kind) {
  case RuntimeEventKind::InstructionAllocate:
    return {std::get<InstructionAllocateEvent>(event.payload).id.hart};
  case RuntimeEventKind::InstructionCancelAttempt:
    return {std::get<InstructionCancelAttemptEvent>(event.payload).id.hart};
  case RuntimeEventKind::InstructionSquash:
    return {std::get<InstructionSquashEvent>(event.payload).id.hart};
  case RuntimeEventKind::LocalStore:
    return {std::get<LocalStoreEvent>(event.payload).id.hart};
  case RuntimeEventKind::LoadSample:
    return {std::get<LoadSampleEvent>(event.payload).operation.id.hart};
  case RuntimeEventKind::InstructionRetire:
    return {std::get<InstructionRetireEvent>(event.payload).instruction.hart};
  case RuntimeEventKind::StorePublish: {
    std::vector<uint32_t> harts;
    for (const auto &member : std::get<StorePublishEvent>(event.payload).members)
      harts.push_back(member.id.hart);
    return harts;
  }
  case RuntimeEventKind::AtomicLifecycle:
    return {std::get<AtomicLifecycleEvent>(event.payload).id.hart};
  case RuntimeEventKind::HartDone:
    return {std::get<HartDoneEvent>(event.payload).hart};
  case RuntimeEventKind::Trap:
    return {std::get<TrapEvent>(event.payload).hart};
  }
  return {};
}
} // namespace

HostSession::HostSession(GlobalMem &memory, HostSessionConfiguration configuration)
    : memory_(memory), configuration_(std::move(configuration)),
      references_(memory_, configuration_.reference_profile, configuration_.initial_harts) {
  if (!references_.configuration()) {
    failure_ = references_.configuration();
    return;
  }
  if (configuration_.platform.empty() || configuration_.stream.required_producers.empty()) {
    failure_ = invalid("host session needs a platform name and explicit required producer roster");
    return;
  }
  for (uint32_t hart = 0; hart < configuration_.initial_harts.size(); ++hart) {
    const auto &required = configuration_.stream.required_producers;
    if (std::none_of(required.begin(), required.end(), [hart](const auto &producer) {
          return producer.producer_id == hart_producer_id(hart);
        })) {
      failure_ = invalid("fixed host profile is missing a required hart observation producer");
      return;
    }
  }
  session_ = std::make_unique<ObservationSession>(
      configuration_.stream, configuration_.producers,
      [this](uint64_t address) {
        uint8_t byte = 0;
        if (!memory_.read(address, &byte, 1))
          throw std::runtime_error("host session read outside independent initialized memory");
        return byte;
      },
      [this](uint64_t address, uint8_t byte) {
        if (!memory_.write(address, &byte, 1))
          throw std::runtime_error("host session publication outside independent initialized memory");
      }, references_.callback());
}

bool HostSession::registered_hart(uint32_t hart) const {
  return hart < configuration_.initial_harts.size();
}

CheckResult HostSession::reject(CheckResult result) {
  if (result.status != CheckStatus::Pass && result.status != CheckStatus::Pending)
    failure_ = result;
  return result;
}

CheckResult HostSession::validate_batch(const EventBatch &batch) const {
  for (const auto &event : batch.events) {
    if (event.payload.index() != static_cast<size_t>(event.kind))
      return invalid("host event kind differs from its typed payload");
    if (drained_producers_.count(event.producer_id))
      return invalid("event arrived after its source was declared drained");
    if (event.kind == RuntimeEventKind::StorePublish && event.producer_id < kMemoryFabricProducerBase)
      return invalid("store publication is not on a registered fabric source channel");
    for (const uint32_t hart : event_harts(event)) {
      if (!registered_hart(hart))
        return invalid("host event names a hart outside the fixed reference roster");
      if (event.kind != RuntimeEventKind::StorePublish && event.producer_id != hart_producer_id(hart))
        return invalid("hart event is not on its registered private source channel");
      const auto done = completed_harts_.find(hart);
      const bool architectural = event.kind == RuntimeEventKind::InstructionAllocate ||
                                 event.kind == RuntimeEventKind::InstructionRetire ||
                                 event.kind == RuntimeEventKind::Trap;
      if (architectural && done != completed_harts_.end() && event.source.cycle > done->second.source_cycle)
        return invalid("architectural event occurs after the declared hart completion boundary");
    }
  }
  return {};
}

SessionSubmitResult HostSession::submit(const EventBatch &batch,
                                        const std::vector<ArchitecturalRetirement> &retirements) {
  SessionSubmitResult output;
  if (!failure_) {
    output.check = failure_;
    return output;
  }
  if (finalized_ || !session_) {
    output.check = reject(invalid("batch submitted to a finalized or unconfigured host session"));
    return output;
  }
  auto checked = validate_batch(batch);
  if (checked)
    for (const auto &snapshot : retirements)
      if (!registered_hart(snapshot.id.hart)) {
        checked = invalid("architectural snapshot names an unregistered hart");
        break;
      }
  if (!checked) {
    output.check = reject(checked);
    return output;
  }
  try {
    output = session_->submit(batch, retirements);
    if (output.accepted) {
      for (const auto &watermark : batch.watermarks)
        source_watermarks_[watermark.producer_id] = watermark.closed_through;
      for (const auto &event : batch.events) {
        auto &last_cycle = last_source_cycles_[event.producer_id];
        last_cycle = std::max(last_cycle, event.source.cycle);
        if (event.kind == RuntimeEventKind::InstructionRetire || event.kind == RuntimeEventKind::InstructionAllocate ||
            event.kind == RuntimeEventKind::Trap)
          for (const auto hart : event_harts(event))
            last_architectural_cycles_[hart] = std::max(last_architectural_cycles_[hart], event.source.cycle);
      }
    }
    reject(output.check);
    return output;
  } catch (const std::exception &error) {
    output.check = reject({CheckStatus::Incomplete, 0, std::string("host session exception: ") + error.what()});
    return output;
  }
}

CheckResult HostSession::complete_hart(const HartCompletion &completion) {
  if (!failure_)
    return failure_;
  if (finalized_ || !registered_hart(completion.hart) || completed_harts_.count(completion.hart))
    return reject(invalid("invalid or duplicate hart completion notification"));
  const auto last_cycle = last_architectural_cycles_.find(completion.hart);
  if (last_cycle != last_architectural_cycles_.end() && last_cycle->second > completion.source_cycle)
    return reject(invalid("hart completion predates an already received architectural event"));
  if (completion.exit_code != 0)
    return reject({CheckStatus::Violation, 0, "DUT hart reported a failing architectural completion code"});
  completed_harts_.emplace(completion.hart, completion);
  return {};
}

CheckResult HostSession::drain_producer(const ProducerDrain &drain) {
  if (!failure_)
    return failure_;
  const auto &required = configuration_.stream.required_producers;
  const bool registered = std::any_of(required.begin(), required.end(), [&](const auto &producer) {
    return producer.producer_id == drain.producer_id;
  });
  if (finalized_ || !registered || drained_producers_.count(drain.producer_id))
    return reject(invalid("invalid or duplicate producer drain notification"));
  if (!drain.physically_idle || !drain.fully_delivered)
    return {CheckStatus::Pending, 0, "source still has physical or native transport work"};
  const auto last_cycle = last_source_cycles_.find(drain.producer_id);
  if (last_cycle != last_source_cycles_.end() && last_cycle->second > drain.source_cycle)
    return reject(invalid("producer drain predates an already received source event"));
  drained_producers_.emplace(drain.producer_id, drain);
  return {};
}

CheckResult HostSession::poll() {
  if (!failure_)
    return failure_;
  if (!session_)
    return reject(incomplete("host session has no configured checker"));
  try {
    return reject(session_->poll());
  } catch (const std::exception &error) {
    return reject({CheckStatus::Incomplete, 0, std::string("host polling exception: ") + error.what()});
  }
}

CheckResult HostSession::finalize(uint64_t completed_cycle) {
  if (!failure_)
    return failure_;
  if (finalized_)
    return {};
  if (completed_harts_.size() != configuration_.initial_harts.size())
    return reject(incomplete("host session finalized before every required hart completed"));
  for (const auto &hart : completed_harts_)
    if (hart.second.source_cycle > completed_cycle)
      return reject(incomplete("requested final source cycle precedes a hart completion"));
  for (const auto &producer : configuration_.stream.required_producers) {
    const auto drain = drained_producers_.find(producer.producer_id);
    const auto watermark = source_watermarks_.find(producer.producer_id);
    if (drain == drained_producers_.end() || drain->second.source_cycle < completed_cycle ||
        watermark == source_watermarks_.end() || watermark->second.cycle < completed_cycle)
      return reject(incomplete("host finalization lacks source drain and closed-delivery evidence"));
  }
  auto progress = poll();
  if (!progress)
    return reject(progress.status == CheckStatus::Pending
                      ? incomplete("host finalized with pending checker observations") : progress);
  const auto result = session_->finalize(completed_cycle);
  if (!result)
    return reject(result);
  const auto &statistics = session_->hart_statistics();
  for (uint32_t hart = 0; hart < configuration_.initial_harts.size(); ++hart) {
    const auto executed = statistics.find(hart);
    if (executed == statistics.end() || executed->second.retired_instructions == 0 ||
        executed->second.reference_steps != executed->second.retired_instructions ||
        executed->second.architecture_compared != executed->second.retired_instructions)
      return reject(incomplete("required hart did not retire and complete every independent architecture comparison"));
  }
  finalized_ = true;
  return {};
}

} // namespace rvwmo
