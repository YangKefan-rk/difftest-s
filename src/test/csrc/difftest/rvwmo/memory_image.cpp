#include "memory_image.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <limits>
#include <vector>

namespace rvwmo {
namespace {
constexpr size_t maximum_file_size = 64 * 1024 * 1024;
constexpr size_t maximum_program_headers = 4096;

CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
bool covers(size_t file_size, uint64_t offset, uint64_t size) {
  return offset <= file_size && size <= file_size - offset;
}

struct Segment {
  uint64_t address;
  uint64_t memory_size;
  uint64_t offset;
  uint64_t file_size;
};
} // namespace

CheckResult load_reference_elf(GlobalMem &memory, const std::string &path, uint64_t &entry) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input)
    return {CheckStatus::Incomplete, 0, "cannot open independent reference ELF: " + path};
  const auto length = input.tellg();
  if (length < static_cast<std::streamoff>(sizeof(Elf64_Ehdr)) ||
      length > static_cast<std::streamoff>(maximum_file_size))
    return invalid("reference ELF file size is outside the supported bounds");
  std::vector<uint8_t> contents(static_cast<size_t>(length));
  input.seekg(0);
  if (!input.read(reinterpret_cast<char *>(contents.data()), static_cast<std::streamsize>(contents.size())))
    return {CheckStatus::Incomplete, 0, "independent reference ELF read was incomplete"};

  Elf64_Ehdr header{};
  std::memcpy(&header, contents.data(), sizeof(header));
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 || header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_machine != EM_RISCV || header.e_version != EV_CURRENT || header.e_type != ET_EXEC)
    return {CheckStatus::Unsupported, 0, "reference image must be a little-endian RV64 RISC-V executable"};
  if (header.e_ehsize != sizeof(header) || header.e_phentsize != sizeof(Elf64_Phdr) ||
      !header.e_phnum || header.e_phnum > maximum_program_headers || header.e_entry % 2 ||
      !covers(contents.size(), header.e_phoff, uint64_t(header.e_phnum) * sizeof(Elf64_Phdr)))
    return invalid("reference ELF header or program table is malformed");

  std::vector<Segment> segments;
  uint64_t initialized_bytes = 0;
  bool executable_entry = false;
  for (uint16_t index = 0; index < header.e_phnum; ++index) {
    Elf64_Phdr program{};
    std::memcpy(&program, contents.data() + header.e_phoff + index * sizeof(program), sizeof(program));
    if (program.p_type != PT_LOAD || !program.p_memsz)
      continue;
    if (program.p_filesz > program.p_memsz || !covers(contents.size(), program.p_offset, program.p_filesz) ||
        program.p_memsz > std::numeric_limits<size_t>::max() ||
        !memory.contains(program.p_paddr, static_cast<size_t>(program.p_memsz)))
      return invalid("reference ELF segment bytes exceed the file or initialized physical memory");
    if (program.p_memsz > memory.size() - initialized_bytes)
      return invalid("reference ELF total segment bytes exceed configured reference RAM");
    initialized_bytes += program.p_memsz;
    if ((program.p_flags & PF_X) && header.e_entry >= program.p_paddr &&
        header.e_entry - program.p_paddr < program.p_memsz)
      executable_entry = true;
    segments.push_back({program.p_paddr, program.p_memsz, program.p_offset, program.p_filesz});
  }
  if (!executable_entry || segments.empty())
    return invalid("reference ELF entry is not inside an executable physical load segment");
  std::sort(segments.begin(), segments.end(), [](const auto &lhs, const auto &rhs) {
    return lhs.address < rhs.address;
  });
  for (size_t index = 1; index < segments.size(); ++index)
    if (segments[index].address - segments[index - 1].address < segments[index - 1].memory_size)
      return {CheckStatus::Unsupported, 0, "overlapping reference ELF physical load segments are not supported"};

  // All ranges are validated before any reference byte changes.
  const std::array<uint8_t, 4096> zeros{};
  for (const auto &segment : segments) {
    if (segment.file_size && !memory.write(segment.address, contents.data() + segment.offset, segment.file_size))
      return {CheckStatus::Incomplete, 0, "reference ELF data initialization failed"};
    uint64_t offset = segment.file_size;
    while (offset < segment.memory_size) {
      const size_t chunk = static_cast<size_t>(std::min<uint64_t>(zeros.size(), segment.memory_size - offset));
      if (!memory.write(segment.address + offset, zeros.data(), chunk))
        return {CheckStatus::Incomplete, 0, "reference ELF BSS initialization failed"};
      offset += chunk;
    }
  }
  entry = header.e_entry;
  return {};
}

} // namespace rvwmo
