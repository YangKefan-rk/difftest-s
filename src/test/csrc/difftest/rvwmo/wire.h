#ifndef DIFFTEST_RVWMO_WIRE_H
#define DIFFTEST_RVWMO_WIRE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIFFTEST_S_WIRE_ABI_VERSION_1 1u
#define DIFFTEST_S_WIRE_MAX_BYTES 8u
#define DIFFTEST_S_WIRE_MAX_BATCH_EVENTS 65536u
#define DIFFTEST_S_WIRE_MAX_BATCH_WATERMARKS 4096u
#define DIFFTEST_S_WIRE_MESSAGE_BYTES 256u
#define DIFFTEST_S_WIRE_END_OF_CYCLE_PHASE UINT16_MAX

/* Numeric values belong to this C ABI, not the internal C++ variant indices. */
enum difftest_s_wire_event_kind {
  DIFFTEST_S_WIRE_ALLOCATE = 1,
  DIFFTEST_S_WIRE_CANCEL_ATTEMPT = 2,
  DIFFTEST_S_WIRE_SQUASH = 3,
  DIFFTEST_S_WIRE_LOCAL_STORE = 4,
  DIFFTEST_S_WIRE_LOAD_SAMPLE = 5,
  DIFFTEST_S_WIRE_STORE_PUBLISH = 6,
  DIFFTEST_S_WIRE_RETIRE = 7,
  DIFFTEST_S_WIRE_TRAP = 8,
  DIFFTEST_S_WIRE_HART_DONE = 9,
  DIFFTEST_S_WIRE_ATOMIC = 10
};

enum difftest_s_wire_memory_kind {
  DIFFTEST_S_WIRE_NO_MEMORY = 0,
  DIFFTEST_S_WIRE_LOAD = 1,
  DIFFTEST_S_WIRE_STORE = 2
};

enum difftest_s_wire_destination_kind {
  DIFFTEST_S_WIRE_NO_DESTINATION = 0,
  DIFFTEST_S_WIRE_INTEGER_DESTINATION = 1,
  DIFFTEST_S_WIRE_UNSUPPORTED_DESTINATION = 2
};

enum difftest_s_wire_check_status {
  DIFFTEST_S_WIRE_PASS = 0,
  DIFFTEST_S_WIRE_VIOLATION = 1,
  DIFFTEST_S_WIRE_PENDING = 2,
  DIFFTEST_S_WIRE_INCOMPLETE = 3,
  DIFFTEST_S_WIRE_UNSUPPORTED = 4,
  DIFFTEST_S_WIRE_INVALID = 5
};

enum difftest_s_wire_transport_status {
  DIFFTEST_S_WIRE_NOT_SUBMITTED = 0,
  DIFFTEST_S_WIRE_TRANSPORT_ACCEPTED = 1,
  DIFFTEST_S_WIRE_TRANSPORT_PENDING = 2,
  DIFFTEST_S_WIRE_TRANSPORT_INCOMPLETE = 3,
  DIFFTEST_S_WIRE_TRANSPORT_UNSUPPORTED = 4,
  DIFFTEST_S_WIRE_TRANSPORT_INVALID = 5
};

typedef struct difftest_s_wire_operation_v1 {
  uint32_t hart;
  uint32_t subaccess;
  uint64_t epoch;
  uint64_t uid;
} difftest_s_wire_operation_v1;

typedef struct difftest_s_wire_source_v1 {
  uint32_t producer_id;
  uint16_t qualified_phase;
  uint8_t order_qualified;
  uint8_t reserved;
  uint64_t cycle;
  uint64_t producer_sequence;
} difftest_s_wire_source_v1;

/* Zero-initialize records. Fields unused by an event kind must remain zero.
 * bytes[] are in increasing address order. Bit i of byte_mask selects byte i.
 * A known writer is diagnostic physical provenance for LoadSample; an unset
 * writer_known_mask bit remains unknown and never becomes a guessed writer.
 * A known all-zero writer ID denotes initialization, distinct from unknown.
 * StorePublish supports one member, identified by id, at the envelope source
 * position; every enabled byte needs that member's known writer identity.
 * Retire carries one ordinary scalar memory access or none, plus the captured
 * architectural integer write. Its byte payload is the actual load result.
 * Unsupported event kinds are declared so producers fail closed when seen.
 */
typedef struct difftest_s_wire_event_v1 {
  uint32_t struct_size;
  uint32_t kind;
  difftest_s_wire_source_v1 source;
  difftest_s_wire_operation_v1 id;
  uint32_t attempt;
  uint32_t flags;
  uint64_t pc;
  uint64_t address;
  uint64_t transaction_id;
  uint64_t integer_value;
  uint32_t instruction;
  uint8_t instruction_length;
  uint8_t width;
  uint8_t byte_mask;
  uint8_t writer_known_mask;
  uint8_t memory_kind;
  uint8_t destination_kind;
  uint8_t destination_register;
  uint8_t reserved;
  uint8_t bytes[DIFFTEST_S_WIRE_MAX_BYTES];
  difftest_s_wire_operation_v1 writers[DIFFTEST_S_WIRE_MAX_BYTES];
  uint64_t reserved_words[2];
} difftest_s_wire_event_v1;

typedef struct difftest_s_wire_watermark_v1 {
  uint32_t struct_size;
  uint32_t reserved;
  difftest_s_wire_source_v1 closed_through;
} difftest_s_wire_watermark_v1;

typedef struct difftest_s_wire_batch_v1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t event_count;
  uint32_t watermark_count;
  const difftest_s_wire_event_v1 *events;
  const difftest_s_wire_watermark_v1 *watermarks;
  uint64_t reserved;
} difftest_s_wire_batch_v1;

typedef struct difftest_s_wire_limits_v1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t max_events;
  uint32_t max_watermarks;
} difftest_s_wire_limits_v1;

typedef struct difftest_s_wire_result_v1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t check_status;
  uint32_t transport_status;
  uint32_t accepted;
  uint32_t rule;
  uint64_t pending_events;
  char message[DIFFTEST_S_WIRE_MESSAGE_BYTES];
} difftest_s_wire_result_v1;

typedef struct difftest_s_wire_ingress difftest_s_wire_ingress;

/* The opaque pointer must refer to a live rvwmo::ObservationSession configured
 * with the complete producer contract. The caller owns its lifetime; use one
 * ingress and one host writer per session. No Runtime, REF, producer registry,
 * watermark, or GMO rank is created here. Source positions describe occurrence
 * time and watermarks explicitly close fully delivered source prefixes.
 * Pointers are borrowed synchronously; these records are not a network format.
 * All v1 struct_size fields must equal sizeof(the corresponding v1 type).
 */
difftest_s_wire_ingress *difftest_s_wire_create_v1(void *borrowed_observation_session,
                                                  const difftest_s_wire_limits_v1 *limits,
                                                  difftest_s_wire_result_v1 *result);
void difftest_s_wire_destroy(difftest_s_wire_ingress *ingress);
int difftest_s_wire_submit_v1(difftest_s_wire_ingress *ingress, const difftest_s_wire_batch_v1 *batch,
                              difftest_s_wire_result_v1 *result);
int difftest_s_wire_poll_v1(difftest_s_wire_ingress *ingress, difftest_s_wire_result_v1 *result);
int difftest_s_wire_finalize_v1(difftest_s_wire_ingress *ingress, uint64_t completed_cycle,
                                difftest_s_wire_result_v1 *result);

/* Submit Pass means accepted/progress, never final RVWMO Pass. accepted=0 plus
 * Pending means retry the whole batch unchanged after progress. accepted=1
 * means never submit it again. Malformed/unsupported inputs and checker errors
 * latch on the ingress so ignoring them cannot later produce final Pass.
 */

#ifdef __cplusplus
}
#endif

#endif
