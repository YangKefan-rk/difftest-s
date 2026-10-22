#include "lrsc.h"
#include <algorithm>
#include <limits>

namespace rvwmo {
namespace {
CheckResult invalid(const std::string &reason) { return {CheckStatus::Invalid, 0, reason}; }
CheckResult violation(const std::string &reason) { return {CheckStatus::Violation, 0, reason}; }
CheckResult check_range(const MemoryOperation &operation) {
  if (operation.byte_mask.empty() || operation.byte_mask.size() - 1 >
                                         std::numeric_limits<uint64_t>::max() - operation.address)
    return invalid("LR/SC observation has an empty or overflowing address range");
  if (std::none_of(operation.byte_mask.begin(), operation.byte_mask.end(), [](uint8_t byte) { return byte != 0; }))
    return invalid("LR/SC observation has no enabled bytes");
  return {};
}
CheckResult check_operand(const MemoryOperation &operation) {
  auto result = check_range(operation);
  if (!result)
    return result;
  const auto width = operation.byte_mask.size();
  if ((width != 4 && width != 8) || operation.address % width != 0 ||
      std::any_of(operation.byte_mask.begin(), operation.byte_mask.end(), [](uint8_t byte) { return byte != 1; }))
    return {CheckStatus::Unsupported, 0, "LR/SC checker requires aligned, unmasked word or doubleword operands"};
  return {};
}
bool same_observation(const MemoryOperation &left, const MemoryOperation &right) {
  return left.id == right.id && left.address == right.address && left.byte_mask == right.byte_mask &&
         left.write_time.valid == right.write_time.valid && left.write_time.rank == right.write_time.rank;
}
} // namespace

CheckResult LrScChecker::observe_store(const MemoryOperation &operation) {
  auto result = check_range(operation);
  if (!result)
    return result;
  if (!operation.store || !operation.write_time.valid || !operation.write_time.rank)
    return invalid("reservation write observation requires a nonzero global store rank");
  if (operation.write_time.rank < frontier_)
    return invalid("reservation writes were not replayed in global-rank order");
  frontier_ = operation.write_time.rank;
  for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte) {
    if (!operation.byte_mask[byte])
      continue;
    auto &writers = writes_[operation.address + byte];
    if (writers[0].hart != operation.id.hart)
      writers[1] = writers[0];
    writers[0] = {operation.id.hart, operation.write_time.rank};
  }
  return {};
}

CheckResult LrScChecker::capture_sc(const MemoryOperation &operation, StoreConditionalEvidence &evidence) const {
  auto result = check_operand(operation);
  if (!result)
    return result;
  if (!operation.sc || !operation.store || !operation.write_time.valid || !operation.write_time.rank)
    return invalid("successful SC evidence requires a global store observation");
  if (operation.write_time.rank <= frontier_)
    return invalid("SC evidence must be captured before its global write in rank order");
  StoreConditionalEvidence captured{operation, std::vector<uint64_t>(operation.byte_mask.size())};
  for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte) {
    auto writers = writes_.find(operation.address + byte);
    if (writers == writes_.end())
      continue;
    for (const auto &writer : writers->second)
      if (writer.hart != operation.id.hart)
        captured.remote_writes[byte] = std::max(captured.remote_writes[byte], writer.rank);
  }
  evidence = std::move(captured);
  return {};
}

CheckResult LrScChecker::retire_lr(const MemoryOperation &operation, const std::vector<uint64_t> &source_ranks) {
  auto result = check_operand(operation);
  if (!result)
    return result;
  if (!operation.lr || !operation.load || operation.store || !operation.read_time.valid || !operation.read_time.rank)
    return invalid("LR reservation requires a final architectural read observation");
  if (source_ranks.size() != operation.byte_mask.size())
    return invalid("LR source rank count differs from its operand width");
  reservations_[operation.id.hart] = {operation, source_ranks};
  return {};
}

CheckResult LrScChecker::retire_sc(const MemoryOperation &operation, const StoreConditionalEvidence *evidence,
                                  bool success, OperationId &paired_lr) {
  if (!operation.sc)
    return invalid("SC retirement is missing its instruction kind");
  auto found = reservations_.find(operation.id.hart);
  if (!success) {
    reservations_.erase(operation.id.hart);
    return {};
  }
  if (found == reservations_.end())
    return violation("successful SC has no unconsumed preceding LR");
  const auto &reservation = found->second;
  const auto &lr = reservation.operation;
  if (operation.id.epoch != lr.id.epoch || operation.id.uid <= lr.id.uid)
    return invalid("successful SC does not follow its paired LR in architectural order");
  if (!evidence || !same_observation(operation, evidence->operation) ||
      evidence->remote_writes.size() != operation.byte_mask.size())
    return invalid("successful SC lacks matching write-point evidence");
  auto result = check_operand(operation);
  if (!result)
    return result;
  if (operation.address != lr.address || operation.byte_mask != lr.byte_mask)
    return {CheckStatus::Unsupported, 0, "successful SC with a different LR address or width needs reservation-set metadata"};
  if (lr.read_time.rank >= operation.write_time.rank)
    return {CheckStatus::Violation, 8, "paired LR must precede successful SC in global order"};
  for (size_t byte = 0; byte < operation.byte_mask.size(); ++byte) {
    const auto source = reservation.source_ranks[byte];
    const auto remote = evidence->remote_writes[byte];
    if (source >= operation.write_time.rank)
      return violation("LR/SC atomicity: LR source store must precede successful SC");
    if (remote > source)
      return violation("LR/SC atomicity: another hart wrote between the LR source store and successful SC");
    if (remote > lr.read_time.rank)
      return violation("successful SC follows another hart's intervening write to its LR operand");
  }
  paired_lr = lr.id;
  reservations_.erase(found);
  return {};
}

} // namespace rvwmo
