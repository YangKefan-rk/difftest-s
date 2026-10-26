#ifndef DIFFTEST_RVWMO_MEMORY_IMAGE_H
#define DIFFTEST_RVWMO_MEMORY_IMAGE_H

#include "../globalmem.h"
#include "event.h"
#include <string>

namespace rvwmo {

// Load an independently supplied RV64 little-endian executable into initialized
// reference RAM. Every PT_LOAD byte, including BSS, must fit the existing RAM;
// this function does not create implicit MMIO/boot-device mappings.
CheckResult load_reference_elf(GlobalMem &memory, const std::string &path, uint64_t &entry);

} // namespace rvwmo

#endif
