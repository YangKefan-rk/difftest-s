#ifndef DIFFTEST_STORE_AUDIT_FIFO_H
#define DIFFTEST_STORE_AUDIT_FIFO_H

#include <queue>

namespace difftest_detail {

enum class StoreAuditAction { Consume, Wait, Error };

// Inspect only the FIFO front. A successful independent audit is the sole
// operation that removes an event; future or failed events remain available.
template <class Event, class Readiness, class Audit>
int drain_store_audit_fifo(std::queue<Event> &events, Readiness readiness, Audit audit) {
  while (!events.empty()) {
    const auto event = events.front();
    const auto ready = readiness(event);
    if (ready != StoreAuditAction::Consume)
      return ready == StoreAuditAction::Error ? 1 : 0;
    const auto checked = audit(event);
    if (checked != StoreAuditAction::Consume)
      return checked == StoreAuditAction::Error ? 1 : 0;
    events.pop();
  }
  return 0;
}

} // namespace difftest_detail

#endif

