#ifndef DIFFTEST_ADAPTERS_BOOM_RETIREMENT_SNAPSHOT_H
#define DIFFTEST_ADAPTERS_BOOM_RETIREMENT_SNAPSHOT_H

#include "boom_event_adapter.h"
#include "../../rvwmo/session.h"

namespace rvwmo {
namespace boom {

// Converts the private adapter's captured result for the shared session. State
// requiring an FPR/fflags/CSR/system comparator returns Unsupported; it cannot
// be represented as a complete scalar integer snapshot. Failure preserves output.
CheckResult convert_retirement_snapshot(const CapturedRetirement &captured, ArchitecturalRetirement &snapshot);

// Preserves input order and validates the whole batch before replacing output.
CheckResult convert_retirement_snapshots(const std::vector<CapturedRetirement> &captured,
                                         std::vector<ArchitecturalRetirement> &snapshots);

} // namespace boom
} // namespace rvwmo
#endif
