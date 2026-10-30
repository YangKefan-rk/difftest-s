#include "dependency.h"
#include <set>

namespace rvwmo {
void DependencySummary::include(const DependencySummary &other) {
  if (other.valid && (!valid || other.rank > rank))
    *this = other;
}
DependencySummary DependencyTracker::read(const std::vector<unsigned> &registers) const {
  DependencySummary result;
  for (auto reg: registers) {
    auto found = registers_.find(reg);
    if (reg && found != registers_.end())
      result.include(found->second);
  }
  return result;
}
void DependencyTracker::write(const std::vector<unsigned> &registers, const DependencySummary &summary) {
  for (auto reg: registers)
    if (reg)
      registers_[reg] = summary;
}

CheckResult DependencyTracker::propagate(const DependencyMetadata &metadata, const DependencySummary &generated_read) {
  if (!metadata.destination_sources.empty() && metadata.destination_sources.size() != metadata.destinations.size())
    return {CheckStatus::Invalid, 0, "dependency destination carrier count mismatch"};
  std::vector<DependencySummary> replacements;
  for (size_t destination = 0; destination < metadata.destinations.size(); ++destination) {
    DependencySummary summary = generated_read;
    if (!metadata.destination_sources.empty())
      summary.include(read(metadata.destination_sources[destination]));
    else if (metadata.carries_to_destination)
      summary.include(read(metadata.sources));
    replacements.push_back(summary);
  }
  // In particular, CSRRW rd=rs1 reads both old values before either is replaced.
  for (size_t destination = 0; destination < metadata.destinations.size(); ++destination)
    write({metadata.destinations[destination]}, replacements[destination]);
  return {};
}

bool compose_dependencies(const DependencyMetadata &first, const DependencyMetadata &second,
                          DependencyMetadata &composed) {
  using Origins = std::set<unsigned>;
  std::map<unsigned, Origins> bindings;
  Origins control;
  for (const auto *metadata: {&first, &second}) {
    if (!metadata->provided || !metadata->complete || metadata->fence || !metadata->address_sources.empty() ||
        !metadata->data_sources.empty() ||
        (!metadata->destination_sources.empty() &&
         metadata->destination_sources.size() != metadata->destinations.size()))
      return false;
    auto expand = [&](const std::vector<unsigned> &sources) {
      Origins origins;
      for (auto reg: sources) {
        if (!reg)
          continue;
        auto binding = bindings.find(reg);
        if (binding == bindings.end())
          origins.insert(reg);
        else
          origins.insert(binding->second.begin(), binding->second.end());
      }
      return origins;
    };
    if (metadata->control_transfer) {
      auto origins = expand(metadata->sources);
      control.insert(origins.begin(), origins.end());
    }
    // All sources see the old bindings, including CSRRW's parallel assignments.
    std::vector<Origins> replacements;
    for (size_t destination = 0; destination < metadata->destinations.size(); ++destination) {
      Origins origins;
      if (!metadata->destination_sources.empty())
        origins = expand(metadata->destination_sources[destination]);
      else if (metadata->carries_to_destination)
        origins = expand(metadata->sources);
      replacements.push_back(std::move(origins));
    }
    for (size_t destination = 0; destination < metadata->destinations.size(); ++destination)
      if (metadata->destinations[destination])
        bindings[metadata->destinations[destination]] = std::move(replacements[destination]);
  }
  DependencyMetadata result;
  result.provided = true;
  result.carries_to_destination = false;
  result.control_transfer = first.control_transfer || second.control_transfer;
  result.sources.assign(control.begin(), control.end());
  for (const auto &binding: bindings) {
    result.destinations.push_back(binding.first);
    result.destination_sources.emplace_back(binding.second.begin(), binding.second.end());
  }
  composed = std::move(result);
  return true;
}

namespace {
constexpr unsigned csr_fflags = 0x001;
constexpr unsigned csr_frm = 0x002;
constexpr unsigned csr_fcsr = 0x003;
constexpr unsigned csr_sstatus = 0x100;
constexpr unsigned csr_sie = 0x104;
constexpr unsigned csr_sip = 0x144;
constexpr unsigned csr_mstatush = 0x310;
constexpr unsigned fflags_dependency_base = 0x10000;
constexpr unsigned frm_dependency = fflags_dependency_base + 5;

const std::vector<unsigned> &fflags_dependency_units() {
  static const std::vector<unsigned> units{fflags_dependency_base, fflags_dependency_base + 1,
                                           fflags_dependency_base + 2, fflags_dependency_base + 3,
                                           fflags_dependency_base + 4};
  return units;
}

std::vector<unsigned> csr_dependency_units(unsigned csr) {
  switch (csr) {
    case csr_fflags: return fflags_dependency_units();
    case csr_frm: return {frm_dependency};
    case csr_fcsr: {
      auto units = fflags_dependency_units();
      units.push_back(frm_dependency);
      return units;
    }
    default: return {64 + csr};
  }
}

CheckResult decode_system(uint32_t instruction, DependencyMetadata &metadata) {
  const unsigned funct = (instruction >> 12) & 7;
  if (!funct) {
    switch (instruction) {
      case 0x00000073: // ECALL
      case 0x00100073: // EBREAK
      case 0x10200073: // SRET
      case 0x30200073: // MRET
      case 0x10500073: // WFI
        return {};
      default: return {CheckStatus::Unsupported, 0, "system ordering instruction requires explicit adapter metadata"};
    }
  }
  if (funct == 4)
    return {CheckStatus::Unsupported, 0, "reserved system instruction"};
  const unsigned csr = instruction >> 20;
  if (csr == csr_sstatus || csr == csr_sie || csr == csr_sip || csr == csr_mstatush)
    return {CheckStatus::Unsupported, 0, "CSR alias or field dependency tracking requires explicit adapter metadata"};
  const unsigned rd = (instruction >> 7) & 31, rs1 = (instruction >> 15) & 31;
  const auto csr_units = csr_dependency_units(csr);
  const bool immediate = funct & 4;
  const bool exchange = (funct & 3) == 1;
  const bool reads_csr = !exchange || rd != 0;
  const bool writes_csr = exchange || rs1 != 0;
  // Read-only CSRs do not participate in syntactic dependency tracking.
  const bool read_only = (csr >> 10) == 3;
  if (!immediate && rs1)
    metadata.sources.push_back(rs1);
  if (reads_csr && !read_only)
    metadata.sources.insert(metadata.sources.end(), csr_units.begin(), csr_units.end());
  if (rd) {
    metadata.destinations.push_back(rd);
    metadata.destination_sources.push_back(reads_csr && !read_only ? csr_units : std::vector<unsigned>{});
  }
  if (writes_csr) {
    for (auto unit: csr_units) {
      metadata.destinations.push_back(unit);
      std::vector<unsigned> carriers;
      if (!exchange && !read_only)
        carriers.push_back(unit);
      if (!immediate && rs1)
        carriers.push_back(rs1);
      metadata.destination_sources.push_back(std::move(carriers));
    }
  }
  return {};
}

bool valid_rounding(unsigned mode) { return mode <= 4 || mode == 7; }

unsigned floating_point_flag_mask(uint32_t instruction) {
  const unsigned opcode = instruction & 127;
  if (opcode == 0x43 || opcode == 0x47 || opcode == 0x4b || opcode == 0x4f)
    return 0x17; // NV, OF, UF, NX; fused arithmetic cannot divide by zero.
  if (opcode != 0x53)
    return 0;
  const unsigned operation = instruction >> 27;
  switch (operation) {
    case 0: case 1: case 2: return 0x17;
    case 3: return 0x1f;
    case 5: case 20: return 0x10;
    case 8: return ((instruction >> 25) & 3) == 1 ? 0x10 : 0x17;
    case 11: case 24: return 0x11;
    case 26: return 1; // W/L conversions can round or raise inexact.
    default: return 0;
  }
}

void floating_point_dependencies(uint32_t instruction, const FloatingPointInstruction &decoded,
                                 DependencyMetadata &metadata) {
  const bool compressed = (instruction & 3) != 3;
  const unsigned rs1 = (instruction >> 15) & 31;
  const unsigned rs2 = (instruction >> 20) & 31;
  const unsigned opcode = instruction & 127;
  if (decoded.load || decoded.store) {
    const unsigned address = compressed
        ? ((instruction & 3) == 0 ? 8 + ((instruction >> 7) & 7) : 2) : rs1;
    metadata.sources = metadata.address_sources = {address};
    if (decoded.load) {
      metadata.destinations = {floating_point_register_base + decoded.destination};
      metadata.carries_to_destination = false;
    } else {
      const unsigned data = compressed
          ? ((instruction & 3) == 0 ? 8 + ((instruction >> 2) & 7) : (instruction >> 2) & 31) : rs2;
      metadata.data_sources = {floating_point_register_base + data};
      metadata.sources.push_back(floating_point_register_base + data);
    }
    return;
  }

  const unsigned operation = instruction >> 27;
  std::vector<unsigned> inputs;
  if (opcode == 0x53 && (operation == 26 || operation == 30)) {
    inputs = {rs1};
  } else {
    inputs = {floating_point_register_base + rs1};
    if (opcode != 0x53 || operation <= 5 || operation == 20)
      inputs.push_back(floating_point_register_base + rs2);
    if (opcode != 0x53)
      inputs.push_back(floating_point_register_base + ((instruction >> 27) & 31));
  }
  if (decoded.reads_rounding_mode)
    inputs.push_back(frm_dependency);
  metadata.sources = inputs;
  if (decoded.writes_floating_point || decoded.writes_integer) {
    metadata.destinations.push_back(decoded.writes_floating_point
        ? floating_point_register_base + decoded.destination : decoded.destination);
    metadata.destination_sources.push_back(inputs);
  }
  const unsigned flag_mask = floating_point_flag_mask(instruction);
  for (unsigned bit = 0; bit < 5; ++bit) {
    if (!(flag_mask & (1U << bit)))
      continue;
    const auto unit = fflags_dependency_base + bit;
    metadata.sources.push_back(unit);
    metadata.destinations.push_back(unit);
    auto carriers = inputs;
    carriers.push_back(unit); // Accrual preserves the previous flag value.
    metadata.destination_sources.push_back(std::move(carriers));
  }
}
} // namespace

CheckResult decode_floating_point_instruction(uint32_t instruction, FloatingPointInstruction &decoded) {
  decoded = {};
  const unsigned rd = (instruction >> 7) & 31;
  const unsigned rs2 = (instruction >> 20) & 31;
  const unsigned rounding = (instruction >> 12) & 7;
  if ((instruction & 3) != 3) {
    const unsigned quadrant = instruction & 3;
    const unsigned function = (instruction >> 13) & 7;
    if (quadrant == 0 || quadrant == 2) {
      if (function == 1) {
        decoded.recognized = decoded.load = decoded.writes_floating_point = true;
        decoded.destination = quadrant == 0 ? 8 + ((instruction >> 2) & 7) : rd;
      } else if (function == 5) {
        decoded.recognized = decoded.store = true;
      } else if (function == 3 || function == 7) {
        // In RV64 these encodings are C.LD/C.SD, not floating-point C.FLW/C.FSW.
        return {};
      }
    }
    return {};
  }
  const unsigned opcode = instruction & 127;
  const bool fused = opcode == 0x43 || opcode == 0x47 || opcode == 0x4b || opcode == 0x4f;
  if (opcode != 0x07 && opcode != 0x27 && opcode != 0x53 && !fused)
    return {};
  decoded.recognized = true;
  decoded.destination = rd;
  auto unsupported_encoding = [] {
    return CheckResult{CheckStatus::Unsupported, 0, "floating-point encoding is outside RV64 F/D support"};
  };
  if (opcode == 0x07 || opcode == 0x27) {
    if (rounding != 2 && rounding != 3)
      return unsupported_encoding();
    decoded.load = decoded.writes_floating_point = opcode == 0x07;
    decoded.store = opcode == 0x27;
    return {};
  }
  const unsigned format = (instruction >> 25) & 3;
  if (format > 1)
    return unsupported_encoding();
  bool needs_rounding = fused;
  decoded.writes_floating_point = true;
  if (!fused) {
    switch (instruction >> 27) {
      case 0: case 1: case 2: case 3:
        needs_rounding = true;
        break;
      case 4: // FSGNJ[N/X].S/D
        if (rounding > 2)
          return unsupported_encoding();
        break;
      case 5: // FMIN/FMAX.S/D
        if (rounding > 1)
          return unsupported_encoding();
        break;
      case 8: // FCVT.S.D / FCVT.D.S
        if (rs2 > 1 || rs2 == format)
          return unsupported_encoding();
        needs_rounding = true;
        break;
      case 11: // FSQRT.S/D
        if (rs2)
          return unsupported_encoding();
        needs_rounding = true;
        break;
      case 20: // FLE/FLT/FEQ.S/D
        if (rounding > 2)
          return unsupported_encoding();
        decoded.writes_floating_point = false;
        decoded.writes_integer = rd != 0;
        break;
      case 24: // FCVT.[W/WU/L/LU].S/D
        if (rs2 > 3)
          return unsupported_encoding();
        decoded.writes_floating_point = false;
        decoded.writes_integer = rd != 0;
        needs_rounding = true;
        break;
      case 26: // FCVT.S/D.[W/WU/L/LU]
        if (rs2 > 3)
          return unsupported_encoding();
        needs_rounding = true;
        break;
      case 28: // FMV.X.W/D and FCLASS.S/D
        if (rs2 || rounding > 1)
          return unsupported_encoding();
        decoded.writes_floating_point = false;
        decoded.writes_integer = rd != 0;
        break;
      case 30: // FMV.W/D.X
        if (rs2 || rounding)
          return unsupported_encoding();
        break;
      default: return unsupported_encoding();
    }
  }
  if (needs_rounding && !valid_rounding(rounding))
    return unsupported_encoding();
  decoded.reads_rounding_mode = needs_rounding && rounding == 7;
  decoded.updates_flags = floating_point_flag_mask(instruction) != 0;
  return {};
}

CheckResult decode_dependencies(uint32_t inst, DependencyMetadata &m) {
  m = {};
  m.provided = true;
  const unsigned rd = (inst >> 7) & 31, rs1 = (inst >> 15) & 31, rs2 = (inst >> 20) & 31;
  FloatingPointInstruction floating;
  auto fp_decoded = decode_floating_point_instruction(inst, floating);
  if (!fp_decoded)
    return fp_decoded;
  if (floating.recognized) {
    floating_point_dependencies(inst, floating, m);
    return {};
  }
  if ((inst & 3) != 3) {
    const unsigned quadrant = inst & 3, funct = (inst >> 13) & 7;
    const unsigned compact1 = 8 + ((inst >> 7) & 7), compact2 = 8 + ((inst >> 2) & 7);
    if (quadrant == 0 && funct == 0) {
      m.sources = {2};
      m.destinations = {compact2};
    } else if (quadrant == 0 && (funct == 2 || funct == 3)) {
      m.sources = m.address_sources = {compact1};
      m.destinations = {compact2};
      m.carries_to_destination = false;
    } else if (quadrant == 0 && (funct == 6 || funct == 7)) {
      m.address_sources = {compact1};
      m.data_sources = {compact2};
      m.sources = {compact1, compact2};
    } else if (quadrant == 1 && (funct == 0 || funct == 1 || funct == 3)) {
      m.sources = {rd};
      m.destinations = {rd};
      if (funct == 3 && rd != 2)
        m.sources.clear();
    } else if (quadrant == 1 && funct == 2) {
      m.destinations = {rd};
    } else if (quadrant == 1 && funct == 4) {
      m.sources = {compact1};
      m.destinations = {compact1};
      if (((inst >> 10) & 3) == 3)
        m.sources.push_back(compact2);
    } else if (quadrant == 1 && funct == 5) { /* C.J */
    } else if (quadrant == 1 && (funct == 6 || funct == 7)) {
      m.sources = {compact1};
      m.control_transfer = true;
    } else if (quadrant == 2 && funct == 0) {
      m.sources = {rd};
      m.destinations = {rd};
    } else if (quadrant == 2 && (funct == 2 || funct == 3)) {
      m.sources = m.address_sources = {2};
      m.destinations = {rd};
      m.carries_to_destination = false;
    } else if (quadrant == 2 && (funct == 6 || funct == 7)) {
      m.address_sources = {2};
      m.data_sources = {(inst >> 2) & 31};
      m.sources = {2, (inst >> 2) & 31};
    } else if (quadrant == 2 && funct == 4) {
      const unsigned src = (inst >> 2) & 31;
      if (src) {
        m.sources = {src};
        if (inst & 0x1000)
          m.sources.push_back(rd);
        m.destinations = {rd};
      } else if (rd) {
        m.sources = {rd};
        m.control_transfer = true;
        m.carries_to_destination = false;
        if (inst & 0x1000)
          m.destinations = {1};
      }
    } else
      return {CheckStatus::Unsupported, 0, "compressed opcode requires dependency metadata"};
    return {};
  }
  switch (inst & 127) {
    case 0x73: return decode_system(inst, m);
    case 0x03:
      m.sources = m.address_sources = {rs1};
      m.destinations = {rd};
      m.carries_to_destination = false;
      break;
    case 0x23:
      m.sources = {rs1, rs2};
      m.address_sources = {rs1};
      m.data_sources = {rs2};
      break;
    case 0x13:
    case 0x1b:
      m.sources = {rs1};
      m.destinations = {rd};
      break;
    case 0x33:
    case 0x3b:
      m.sources = {rs1, rs2};
      m.destinations = {rd};
      break;
    case 0x37:
    case 0x17:
    case 0x6f: m.destinations = {rd}; break;
    case 0x67:
      m.sources = {rs1};
      m.destinations = {rd};
      m.control_transfer = true;
      m.carries_to_destination = false;
      break;
    case 0x63:
      m.sources = {rs1, rs2};
      m.control_transfer = true;
      break;
    case 0x0f:
      // Rocket ignores FENCE.I's reserved immediate/register fields. It orders
      // instruction fetch, not data memory, even when those fields are nonzero.
      if (((inst >> 12) & 7) == 1)
        break;
      if (((inst >> 12) & 7) != 0)
        return {CheckStatus::Unsupported, 0, "non-data fence requires adapter metadata"};
      if ((inst >> 28) != 0)
        return {CheckStatus::Unsupported, 0, "non-base fence requires adapter metadata"};
      m.fence = true;
      m.fence_predecessor = (inst >> 24) & 15;
      m.fence_successor = (inst >> 20) & 15;
      break;
    case 0x2f: {
      unsigned funct = inst >> 27;
      m.address_sources = {rs1};
      m.sources = {rs1};
      m.destinations = {rd};
      if (funct != 2) {
        m.data_sources = {rs2};
        m.sources.push_back(rs2);
      }
      m.carries_to_destination = false;
      break;
    }
    default: return {CheckStatus::Unsupported, 0, "opcode requires explicit complete dependency metadata"};
  }
  return {};
}
} // namespace rvwmo
