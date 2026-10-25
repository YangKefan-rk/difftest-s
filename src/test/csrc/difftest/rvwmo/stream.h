#ifndef DIFFTEST_RVWMO_STREAM_H
#define DIFFTEST_RVWMO_STREAM_H

#include "event.h"
#include <map>
#include <set>

namespace rvwmo {

enum class SourceOrder { Before, Equal, After, Unordered };

SourceOrder compare_source_position(uint32_t lhs_producer, const SourcePosition &lhs, uint32_t rhs_producer,
                                    const SourcePosition &rhs);

// Stream acceptance/liveness only; Accepted never means an RVWMO verdict.
enum class EventValidationStatus { Accepted, Pending, Incomplete, Unsupported, Invalid };

struct ProducerRequirement {
  uint32_t producer_id = 0;
  std::vector<RuntimeEventKind> event_kinds;
};

struct StreamContract {
  uint32_t abi_version = 2;
  // Required observation producers, not an architectural hart roster.
  std::vector<ProducerRequirement> required_producers;
  // Bounds transport buffering if a required source stalls its watermark.
  size_t max_pending_events = 65536;
};

struct ProducerCapability {
  // Producer IDs identify lossless observation channels, not architectural harts.
  uint32_t producer_id = 0;
  bool lossless_events = false;
  bool provides_source_positions = false;
  bool provides_watermarks = false;
  std::vector<RuntimeEventKind> event_kinds;
};

struct StreamResult {
  EventValidationStatus status = EventValidationStatus::Accepted;
  std::string message;
  explicit operator bool() const { return status == EventValidationStatus::Accepted; }
};

struct DrainedEventBatch {
  EventValidationStatus status = EventValidationStatus::Accepted;
  std::string message;
  std::optional<uint64_t> closed_through_cycle;
  // Deterministic delivery order only; unordered events do not gain GMO order.
  std::vector<RuntimeEvent> events;
};

// Delivers events only after all registered producers close their source prefix.
// HartDone is transported as an event; this adapter does not prove all-hart
// completion or memory drain and is not a retirement/runtime verdict.
// Identity duplicate checks are batch-local; instruction/store lifecycle belongs
// to the semantic consumer. Buffered source events are explicitly capacity-limited.
class ObservationStream {
public:
  ObservationStream(StreamContract contract, std::vector<ProducerCapability> producers);

  const StreamResult &configuration() const { return configuration_; }
  StreamResult submit(const EventBatch &batch);
  DrainedEventBatch drain();
  std::optional<uint64_t> minimum_closed_cycle() const;
  size_t buffered_events() const { return pending_events_.size(); }

private:
  struct MemoryEffect {
    uint32_t producer_id = 0;
    SourcePosition source;
    uint64_t address = 0;
    std::vector<uint8_t> byte_mask;
    bool write = false;
  };

  std::map<uint32_t, ProducerCapability> producers_;
  StreamContract contract_;
  std::map<uint32_t, SourcePosition> watermarks_;
  std::map<uint32_t, uint64_t> closed_source_sequences_;
  std::vector<RuntimeEvent> pending_events_;
  StreamResult configuration_;

  static bool payload_matches_kind(const RuntimeEvent &event);
  static bool payload_has_valid_shape(const RuntimeEvent &event);
  static bool position_is_closed(uint32_t producer, const SourcePosition &position,
                                 const SourcePosition &watermark);
  static std::optional<MemoryEffect> memory_effect(const RuntimeEvent &event);
  static bool effects_overlap(const MemoryEffect &lhs, const MemoryEffect &rhs);
  static StreamResult validate_transaction(const ObservationStream &stream, const EventBatch &batch);
};

} // namespace rvwmo
#endif
