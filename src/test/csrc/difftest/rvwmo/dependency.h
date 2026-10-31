#ifndef DIFFTEST_RVWMO_DEPENDENCY_H
#define DIFFTEST_RVWMO_DEPENDENCY_H
#include "event.h"
#include <map>

namespace rvwmo {
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
// Integer and FP register namespaces remain disjoint; f0 is a writable carrier.
constexpr unsigned floating_point_register_base = 32;
struct FloatingPointInstruction {
  bool recognized = false;
  bool load = false;
  bool store = false;
  bool writes_floating_point = false;
  bool writes_integer = false;
  bool reads_rounding_mode = false;
  bool updates_flags = false;
  uint8_t destination = 0;
};
// Decodes RV64 F/D architectural effects independently of DUT classification.
// Non-FP instructions return recognized=false; unknown FP encodings reject.
CheckResult decode_floating_point_instruction(uint32_t instruction, FloatingPointInstruction &decoded);
CheckResult decode_dependencies(uint32_t instruction, DependencyMetadata &metadata);
} // namespace rvwmo
#endif
