/***************************************************************************************
* Copyright (c) 2020-2023 Institute of Computing Technology, Chinese Academy of Sciences
* Copyright (c) 2020-2021 Peng Cheng Laboratory
*
* DiffTest is licensed under Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*          http://license.coscl.org.cn/MulanPSL2
*
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
* EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
* MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
*
* See the Mulan PSL v2 for more details.
***************************************************************************************/

#include "globalmem.h"
#include "common.h"
#include "elfloader.h"
#include "ram.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace {
GlobalMem memory;
uint64_t initialization_generation = 0;
#ifdef ENABLE_STORE_LOG
bool store_log_enabled = false;
struct StoreUndo {
  uint64_t address;
  uint8_t byte;
};
std::vector<StoreUndo> store_log;
#endif
} // namespace

GlobalMem &global_memory() {
  return memory;
}

void init_globalmem() {
  globalmem_finish();
  if (!memory.initialize(PMEM_BASE, simMemory->get_size()))
    panic("cannot allocate GlobalMem");
  if (dynamic_cast<FootprintsMemory *>(simMemory))
    memory.require_lazy_initialization();
  const uint64_t generation = initialization_generation;
  simMemory->clone_on_demand(
      [generation](uint64_t offset, void *source, size_t size) {
        // Footprint callbacks can outlive one fuzzing session, never its generation.
        if (generation == initialization_generation && !memory.write(PMEM_BASE + offset, source, size))
          panic("GlobalMem initialization range is invalid");
      },
      true);
  cloneElfSparseMemory([](uint64_t address, const void *source, size_t size) {
    const auto *bytes = static_cast<const uint8_t *>(source);
    while (size) {
      size_t chunk = size;
      if (address >= PMEM_BASE && address - PMEM_BASE < memory.size()) {
        // A sparse loader page can straddle a non-page-aligned main RAM edge.
        // Its padding must not overwrite bytes already cloned from main RAM.
        chunk = std::min<uint64_t>(size, memory.size() - (address - PMEM_BASE));
      } else {
        if (address < PMEM_BASE)
          chunk = std::min<uint64_t>(size, PMEM_BASE - address);
        if (!memory.add_region(address, bytes, chunk))
          panic("GlobalMem sparse ELF initialization failed");
      }
      size -= chunk;
      bytes += chunk;
      if (size)
        address += chunk;
    }
  });
  Info("GlobalMem: %lu main bytes, %lu sparse bytes; no dense byte flags\n", memory.size(), memory.sparse_bytes());
}

void globalmem_finish() {
  ++initialization_generation;
  memory.reset();
#ifdef ENABLE_STORE_LOG
  store_log.clear();
  store_log_enabled = false;
#endif
}

bool in_pmem(uint64_t address) {
  return memory.contains(address);
}

void read_globalmem(uint64_t address, void *destination, uint64_t size) {
  if (!memory.read(address, destination, size))
    panic("GlobalMem read outside initialized memory: address=%lx size=%lu", address, size);
}

void update_globalmem(uint64_t address, const void *source, uint64_t mask, int size) {
  if (size <= 0 || size > 64 || !memory.contains(address, size))
    panic("GlobalMem write outside initialized memory: address=%lx size=%d", address, size);
  const auto *bytes = static_cast<const uint8_t *>(source);
  for (int byte = 0; byte < size; ++byte) {
    if (!((mask >> byte) & 1))
      continue;
#ifdef ENABLE_STORE_LOG
    if (store_log_enabled) {
      uint8_t before;
      read_globalmem(address + byte, &before, 1);
      store_log.push_back({address + byte, before});
    }
#endif
    if (!memory.write(address + byte, bytes + byte, 1))
      panic("GlobalMem masked write failed");
  }
}

#ifdef ENABLE_STORE_LOG
void globalmem_set_store_log(bool enabled) {
  store_log_enabled = enabled;
}
void globalmem_store_log_reset() {
  store_log.clear();
}
void globalmem_store_log_restore() {
  for (auto it = store_log.rbegin(); it != store_log.rend(); ++it)
    if (!memory.write(it->address, &it->byte, 1))
      panic("GlobalMem undo range is invalid");
  store_log.clear();
}
#endif
