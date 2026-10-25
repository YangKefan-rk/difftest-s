#ifndef DIFFTEST_ROCKET_CACHE_TRACKER_H
#define DIFFTEST_ROCKET_CACHE_TRACKER_H

#include "event_emitter.h"

namespace rocket_difftest {

struct CacheConfiguration {
  uint32_t core_requestor = 0;
  uint32_t requestors = 1;
  size_t capacity = 65536;
};

struct RequestDetails {
  uint64_t address = 0;
  uint64_t tag = 0;
  uint8_t command = 0;
  uint8_t size = 0;
};

struct CoreRequest {
  uint64_t token = 0;
  uint32_t attempt = 0;
  RequestDetails request;
  rvwmo::SourcePosition source;
};

struct CacheRequest {
  uint64_t request_id = 0;
  RequestDetails request;
  rvwmo::SourcePosition source;
  bool array_read = false;
};

struct CacheLoadResult {
  uint64_t request_id = 0;
  uint64_t physical_address = 0;
  uint64_t data = 0; // Right-justified actual data consumed by LoadGen, not raw SRAM word.
};

struct CacheStoreValue {
  uint64_t request_id = 0;
  uint64_t physical_address = 0;
  uint64_t data = 0; // Word-lane layout from pstore, before ECC encoding.
  uint8_t mask = 0;
  rvwmo::SourcePosition source;
};

// Associates same-source-edge core/cache handshakes without treating rd/tag as
// a dynamic identity. Accept only native probe valid facts from the supported
// RV64 blocking cache. This is a private converter, not another transport ABI.
class CacheTracker {
public:
  explicit CacheTracker(CacheConfiguration configuration);
  rvwmo::CheckResult bind(const CoreRequest &core, const CacheRequest &cache);
  rvwmo::CheckResult load_sample(const CacheLoadResult &result, LoadObservation &load);
  rvwmo::CheckResult accept_store(const CacheStoreValue &store);
  rvwmo::CheckResult local_store(uint64_t token, rvwmo::SourcePosition commit, StoreObservation &store);
  rvwmo::CheckResult publication(const CacheStoreValue &value, StoreObservation &store);
  rvwmo::CheckResult observe_merge();
  rvwmo::CheckResult release(uint64_t request_id);
  void discard_instruction(uint64_t token);
  rvwmo::CheckResult finalize() const;
  size_t live_requests() const { return requests_.size(); }

private:
  struct Request {
    CoreRequest core;
    CacheRequest cache;
    std::optional<StoreObservation> accepted_store;
  };
  CacheConfiguration configuration_;
  std::map<uint64_t, Request> requests_;
  std::optional<uint64_t> last_request_;
  rvwmo::CheckResult failure_;

  rvwmo::CheckResult reject(rvwmo::CheckStatus status, const char *message);
  rvwmo::CheckResult store_bytes(const Request &request, const CacheStoreValue &value, StoreObservation &store);
};

} // namespace rocket_difftest
#endif
