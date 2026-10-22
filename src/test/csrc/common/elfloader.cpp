/***************************************************************************************
* Copyright (c) 2024 Axelera AI
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

#include "elfloader.h"
#include <algorithm>
#include <array>
#include <limits>
#include <unordered_map>

namespace {

constexpr uint64_t SPARSE_PAGE_SIZE = 4096;
using SparsePage = std::array<uint8_t, SPARSE_PAGE_SIZE>;
std::unordered_map<uint64_t, SparsePage> sparse_elf_memory;

bool rangeContains(uint64_t base, uint64_t size, uint64_t address) {
  return address >= base && address - base < size;
}

void storeSparse(uint64_t paddr, const uint8_t *src, size_t len, bool zero) {
  while (len != 0) {
    const uint64_t page_number = paddr / SPARSE_PAGE_SIZE;
    const size_t page_offset = paddr % SPARSE_PAGE_SIZE;
    const size_t chunk = std::min<size_t>(len, SPARSE_PAGE_SIZE - page_offset);
    auto &page = sparse_elf_memory[page_number];
    if (zero)
      std::memset(page.data() + page_offset, 0, chunk);
    else
      std::memcpy(page.data() + page_offset, src, chunk);
    paddr += chunk;
    if (!zero)
      src += chunk;
    len -= chunk;
  }
}

bool loadRange(void *ptr, uint64_t buf_size, uint64_t paddr,
               const uint8_t *src, uint64_t len, bool zero, uint64_t &image_span) {
  auto *pmem = static_cast<uint8_t *>(ptr);
  while (len != 0) {
    if (rangeContains(PMEM_BASE, buf_size, paddr)) {
      const uint64_t offset = paddr - PMEM_BASE;
      const size_t chunk = static_cast<size_t>(
          std::min<uint64_t>(len, buf_size - offset));
      image_span = std::max(image_span, offset + chunk);
      if (zero)
        std::memset(pmem + offset, 0, chunk);
      else
        std::memcpy(pmem + offset, src, chunk);
      paddr += chunk;
      if (!zero)
        src += chunk;
      len -= chunk;
      continue;
    }

    uint64_t sparse_len = len;
    if (paddr < PMEM_BASE)
      sparse_len = std::min<uint64_t>(sparse_len, PMEM_BASE - paddr);
    storeSparse(paddr, src, static_cast<size_t>(sparse_len), zero);
    paddr += sparse_len;
    if (!zero)
      src += sparse_len;
    len -= sparse_len;
  }
  return true;
}

} // namespace

void clearElfSparseMemory() {
  sparse_elf_memory.clear();
}

void ElfBinary::load() {
  assert(size >= sizeof(Elf64_Ehdr));
  eh64 = (const Elf64_Ehdr *)raw;
  assert(IS_ELF32(*eh64) || IS_ELF64(*eh64));

  if (IS_ELF32(*eh64))
    parse(data32);
  else
    parse(data64);
}

template <typename ehdr_t, typename phdr_t, typename shdr_t, typename sym_t>
void ElfBinary::parse(ElfBinaryData<ehdr_t, phdr_t, shdr_t, sym_t> &data) {
  data.eh = (const ehdr_t *)raw;
  data.ph = (const phdr_t *)(raw + data.eh->e_phoff);
  entry = data.eh->e_entry;
  assert(size >= data.eh->e_phoff + data.eh->e_phnum * sizeof(*data.ph));
  for (unsigned i = 0; i < data.eh->e_phnum; i++) {
    if (data.ph[i].p_type == PT_LOAD && data.ph[i].p_memsz) {
      assert(data.ph[i].p_filesz <= data.ph[i].p_memsz);
      if (data.ph[i].p_filesz)
        assert(size >= data.ph[i].p_offset + data.ph[i].p_filesz);
      sections.push_back({
          .data_src = data.ph[i].p_filesz ? (const uint8_t *)raw + data.ph[i].p_offset : nullptr,
          .data_dst = data.ph[i].p_paddr,
          .data_len = data.ph[i].p_filesz,
          .zero_dst = data.ph[i].p_paddr + data.ph[i].p_filesz,
          .zero_len = data.ph[i].p_memsz - data.ph[i].p_filesz,
      });
    }
  }
  std::sort(sections.begin(), sections.end(),
            [](const ElfSection &a, const ElfSection &b) { return a.data_dst < b.data_dst; });
}

ElfBinaryFile::ElfBinaryFile(const char *filename) : filename(filename) {
  int fd = open(filename, O_RDONLY);
  struct stat s;
  assert(fd != -1);
  assert(fstat(fd, &s) >= 0);
  size = s.st_size;

  raw = (uint8_t *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  assert(raw != MAP_FAILED);
  close(fd);

  load();
}

ElfBinaryFile::~ElfBinaryFile() {
  if (raw)
    munmap((void *)raw, size);
}

bool isElfFile(const char *filename) {
  int fd = -1;

#ifdef NO_IMAGE_ELF
  return false;
#endif

  fd = open(filename, O_RDONLY);
  if (fd < 0)
    return false;

  uint8_t buf[4];

  size_t sz = read(fd, buf, 4);
  if (sz != sizeof(buf) || std::memcmp(buf, "\177ELF", sizeof(buf)) != 0) {
    close(fd);
    return false;
  }

  close(fd);
  return true;
}

long readFromElf(void *ptr, const char *file_name, long buf_size) {
  clearElfSparseMemory();
  if (ptr == nullptr || buf_size < 0) {
    printf("Invalid destination buffer for ELF '%s'\n", file_name);
    return -1;
  }

  auto elf_file = ElfBinaryFile(file_name);

  if (elf_file.sections.size() < 1) {
    printf("The requested elf '%s' contains zero sections\n", file_name);
    return -1;
  }

  uint64_t image_span = 0;
  size_t total_len = 0;
  size_t total_sections = 0;
  for (const auto &section: elf_file.sections) {
    if (section.data_len != 0)
      loadRange(ptr, static_cast<uint64_t>(buf_size), section.data_dst,
                section.data_src, section.data_len, false, image_span);
    if (section.zero_len != 0)
      loadRange(ptr, static_cast<uint64_t>(buf_size), section.zero_dst,
                nullptr, section.zero_len, true, image_span);
    total_len += section.data_len + section.zero_len;
    total_sections++;
  }
  printf("Loaded %ld bytes across %ld sections (%ld sparse pages).\n",
         total_len, total_sections, sparse_elf_memory.size());
  // MmapMemory::clone uses this as a contiguous prefix length.
  return static_cast<long>(image_span);
}

bool readFromElfSparseMemory(uint64_t paddr, void *dst, size_t len) {
  auto *out = static_cast<uint8_t *>(dst);
  while (len != 0) {
    const uint64_t page_number = paddr / SPARSE_PAGE_SIZE;
    const size_t page_offset = paddr % SPARSE_PAGE_SIZE;
    const size_t chunk = std::min<size_t>(len, SPARSE_PAGE_SIZE - page_offset);
    auto page = sparse_elf_memory.find(page_number);
    if (page == sparse_elf_memory.end())
      return false;
    std::memcpy(out, page->second.data() + page_offset, chunk);
    out += chunk;
    paddr += chunk;
    len -= chunk;
  }
  return true;
}

bool writeToElfSparseMemory(uint64_t paddr, const void *src, size_t len) {
  const auto *in = static_cast<const uint8_t *>(src);
  uint64_t current = paddr;
  size_t remaining = len;
  while (remaining != 0) {
    const uint64_t page_number = current / SPARSE_PAGE_SIZE;
    const size_t page_offset = current % SPARSE_PAGE_SIZE;
    const size_t chunk = std::min<size_t>(remaining, SPARSE_PAGE_SIZE - page_offset);
    auto page = sparse_elf_memory.find(page_number);
    if (page == sparse_elf_memory.end())
      return false;
    current += chunk;
    remaining -= chunk;
  }
  storeSparse(paddr, in, len, false);
  return true;
}

void cloneElfSparseMemory(const std::function<void(uint64_t, const void *, size_t)> &copy) {
  for (const auto &page : sparse_elf_memory)
    copy(page.first * SPARSE_PAGE_SIZE, page.second.data(), page.second.size());
}
