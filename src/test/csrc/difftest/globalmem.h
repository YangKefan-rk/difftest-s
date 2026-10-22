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

#ifndef DIFFTEST_GLOBALMEM_H
#define DIFFTEST_GLOBALMEM_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

// Owns reference bytes independently of DUT memory and per-hart pending stores.
class GlobalMem {
public:
  GlobalMem() = default;
  ~GlobalMem();
  GlobalMem(const GlobalMem &) = delete;
  GlobalMem &operator=(const GlobalMem &) = delete;
  bool initialize(uint64_t base, size_t size);
  void reset();
  void require_lazy_initialization() { lazy_initialization_ = true; }
  bool contains(uint64_t address, size_t size = 1) const;
  bool read(uint64_t address, void *destination, size_t size) const;
  bool write(uint64_t address, const void *source, size_t size);
  bool add_region(uint64_t address, const void *source, size_t size);
  uint64_t size() const { return size_; }
  uint64_t sparse_bytes() const { return sparse_.size() * page_size; }

private:
  static constexpr size_t page_size = 4096;
  uint8_t *bytes_ = nullptr;
  uint64_t base_ = 0;
  size_t size_ = 0;
  std::unordered_map<uint64_t, std::array<uint8_t, page_size>> sparse_;
  bool lazy_initialization_ = false;
  std::unordered_map<uint64_t, uint8_t> initialized_bytes_;
  bool initialized(uint64_t address, size_t size) const;
  bool contiguous(uint64_t address) const;
};

GlobalMem &global_memory();
void init_globalmem();
void globalmem_finish();
void update_globalmem(uint64_t address, const void *source, uint64_t mask, int size);
void read_globalmem(uint64_t address, void *destination, uint64_t size);
bool in_pmem(uint64_t address);

#ifdef ENABLE_STORE_LOG
void globalmem_set_store_log(bool enabled);
void globalmem_store_log_reset();
void globalmem_store_log_restore();
#endif
#endif
