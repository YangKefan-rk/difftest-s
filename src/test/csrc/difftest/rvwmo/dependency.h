#ifndef DIFFTEST_RVWMO_DEPENDENCY_H
#define DIFFTEST_RVWMO_DEPENDENCY_H
#include "event.h"
#include <map>
#include <optional>

namespace rvwmo {
enum class FloatingTransferKind { Load, Store, FromInteger, ToInteger };
struct FloatingTransfer {
  FloatingTransferKind kind;
  uint8_t integer_register = 0;
  uint8_t floating_register = 0;
  uint8_t bytes = 0;
};
// Only scalar floating data transfers are covered; arithmetic and vector
// memory encodings remain unsupported until their own semantics are supplied.
std::optional<FloatingTransfer> decode_floating_transfer(uint32_t instruction);

struct DependencySummary {
  bool valid = false;
  uint64_t rank = 0;
  OperationId source;
  void include(const DependencySummary &other);
};
class DependencyTracker {
public:
  DependencySummary read(const std::vector<unsigned> &registers) const;
  void write(const std::vector<unsigned> &registers, const DependencySummary &summary);
  CheckResult propagate(const DependencyMetadata &metadata, const DependencySummary &generated_read = {});

private:
  std::map<unsigned, DependencySummary> registers_;
};
// Compose memory-free instructions without reading or changing live dependencies.
// Output origins refer to register values at the start of the first segment.
bool compose_dependencies(const DependencyMetadata &first, const DependencyMetadata &second,
                          DependencyMetadata &composed);
CheckResult decode_dependencies(uint32_t instruction, DependencyMetadata &metadata);
} // namespace rvwmo
#endif
