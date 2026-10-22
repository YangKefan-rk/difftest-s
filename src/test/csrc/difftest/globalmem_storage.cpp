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
#include <algorithm>
#include <cstring>
#include <limits>
#include <sys/mman.h>

GlobalMem::~GlobalMem() { reset(); }

bool GlobalMem::initialize(uint64_t base, size_t size) {
  if (!size || size - 1 > std::numeric_limits<uint64_t>::max() - base)
    return false;
  auto *bytes = static_cast<uint8_t *>(mmap(nullptr, size, PROT_READ | PROT_WRITE,
                                           MAP_ANON | MAP_PRIVATE | MAP_NORESERVE, -1, 0));
  if (bytes == MAP_FAILED)
    return false;
  reset();
  bytes_ = bytes;
  base_ = base;
  size_ = size;
  return true;
}

void GlobalMem::reset() {
  if (bytes_)
    munmap(bytes_, size_);
  bytes_ = nullptr;
  base_ = 0;
  size_ = 0;
  sparse_.clear();
  initialized_bytes_.clear();
  lazy_initialization_ = false;
}

bool GlobalMem::contiguous(uint64_t address) const {
  return bytes_ && address >= base_ && address - base_ < size_;
}

bool GlobalMem::contains(uint64_t address, size_t size) const {
  if (!bytes_ || !size || size - 1 > std::numeric_limits<uint64_t>::max() - address)
    return false;
  while (size) {
    size_t chunk;
    if (contiguous(address)) {
      chunk = std::min<uint64_t>(size, size_ - (address - base_));
    } else {
      if (!sparse_.count(address / page_size))
        return false;
      chunk = std::min(size, page_size - size_t(address % page_size));
      if (address < base_)
        chunk = std::min<uint64_t>(chunk, base_ - address);
    }
    size -= chunk;
    if (size)
      address += chunk;
  }
  return true;
}

bool GlobalMem::initialized(uint64_t address, size_t size) const {
  if (!lazy_initialization_)
    return true;
  for (size_t byte = 0; byte < size; ++byte) {
    const uint64_t at = address + byte;
    auto found = initialized_bytes_.find(at / 8);
    if (found == initialized_bytes_.end() || !(found->second & (1 << (at % 8))))
      return false;
  }
  return true;
}

bool GlobalMem::read(uint64_t address, void *destination, size_t size) const {
  if (!destination || !contains(address, size) || !initialized(address, size))
    return false;
  auto *out = static_cast<uint8_t *>(destination);
  while (size) {
    const bool main = contiguous(address);
    size_t chunk = main ? std::min<uint64_t>(size, size_ - (address - base_))
                        : std::min(size, page_size - size_t(address % page_size));
    if (!main && address < base_)
      chunk = std::min<uint64_t>(chunk, base_ - address);
    const auto *source = main ? bytes_ + (address - base_) : sparse_.at(address / page_size).data() + address % page_size;
    std::memcpy(out, source, chunk);
    size -= chunk;
    out += chunk;
    if (size)
      address += chunk;
  }
  return true;
}

bool GlobalMem::write(uint64_t address, const void *source, size_t size) {
  if (!source || !contains(address, size))
    return false;
  if (lazy_initialization_)
    for (size_t byte = 0; byte < size; ++byte)
      initialized_bytes_[(address + byte) / 8] |= 1 << ((address + byte) % 8);
  const auto *in = static_cast<const uint8_t *>(source);
  while (size) {
    const bool main = contiguous(address);
    size_t chunk = main ? std::min<uint64_t>(size, size_ - (address - base_))
                        : std::min(size, page_size - size_t(address % page_size));
    if (!main && address < base_)
      chunk = std::min<uint64_t>(chunk, base_ - address);
    auto *destination = main ? bytes_ + (address - base_) : sparse_.at(address / page_size).data() + address % page_size;
    std::memcpy(destination, in, chunk);
    size -= chunk;
    in += chunk;
    if (size)
      address += chunk;
  }
  return true;
}

bool GlobalMem::add_region(uint64_t address, const void *source, size_t size) {
  if (!bytes_ || !source || !size || size - 1 > std::numeric_limits<uint64_t>::max() - address)
    return false;
  uint64_t at = address;
  size_t remaining = size;
  while (remaining) {
    size_t chunk = std::min(remaining, page_size - size_t(at % page_size));
    if (contiguous(at)) {
      chunk = std::min<uint64_t>(chunk, size_ - (at - base_));
    } else {
      if (at < base_)
        chunk = std::min<uint64_t>(chunk, base_ - at);
      sparse_.try_emplace(at / page_size, std::array<uint8_t, page_size>{});
    }
    remaining -= chunk;
    if (remaining)
      at += chunk;
  }
  return write(address, source, size);
}
