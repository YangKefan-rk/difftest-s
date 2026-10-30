#ifndef DIFFTEST_ADAPTERS_BOOM_READONLY_HARTID_H
#define DIFFTEST_ADAPTERS_BOOM_READONLY_HARTID_H

#include <cstdint>

namespace rvwmo {
namespace boom {

// CSRRS rd,mhartid,x0 reads an immutable per-hart CSR without a CSR write.
// Requiring rd!=x0 makes the result observable through the existing independent
// REF-versus-DUT integer-write comparison; all other CSR operations need a
// dedicated architectural CSR-state comparator.
constexpr bool is_observable_readonly_hartid(uint32_t instruction) {
  constexpr uint32_t kCsrRdMask = 0xfffff07f;
  constexpr uint32_t kCsrRsHartid = 0xf1402073;
  return (instruction & kCsrRdMask) == kCsrRsHartid && ((instruction >> 7) & 31) != 0;
}

} // namespace boom
} // namespace rvwmo

#endif
