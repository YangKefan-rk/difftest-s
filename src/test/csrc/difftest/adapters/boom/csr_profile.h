#ifndef DIFFTEST_ADAPTERS_BOOM_CSR_PROFILE_H
#define DIFFTEST_ADAPTERS_BOOM_CSR_PROFILE_H

#include <cstdint>

namespace rvwmo::boom {

// Readback ports and the per-hart Spike peek API both implement this limited
// startup profile. Every other CSR retains its explicit Unsupported verdict.
inline bool certified_counter_address(uint32_t csr) {
  return csr == 0xb00 || csr == 0xb02; // mcycle or minstret
}

inline bool certified_counter_write(uint32_t instruction) {
  const auto function = (instruction >> 12) & 7;
  return (instruction & 0x7f) == 0x73 && (function == 1 || function == 5) &&
         ((instruction >> 7) & 31) == 0 && certified_counter_address(instruction >> 20);
}

// A counter read has a time-dependent old value; only a write without an
// architectural read result has a comparable post-write certificate.
inline bool certified_csr_instruction(uint32_t instruction) {
  if ((instruction & 0x7f) != 0x73 || ((instruction >> 12) & 7) == 0)
    return false;
  if (certified_counter_write(instruction))
    return true;
  switch (instruction >> 20) {
  case 0x003: // fcsr
  case 0x105: // stvec
  case 0x140: // sscratch
  case 0x142: // scause
  case 0x143: // stval
  case 0x300: // mstatus
  case 0x302: // medeleg
  case 0x303: // mideleg
  case 0x304: // mie
  case 0x305: // mtvec
  case 0x340: // mscratch
  case 0x342: // mcause
  case 0x343: // mtval
  case 0x3a0: // pmpcfg0
  case 0x3b0: // pmpaddr0
    return true;
  default:
    return false;
  }
}

} // namespace rvwmo::boom
#endif
