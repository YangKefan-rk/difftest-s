#include "host_session_adapter.h"
#include "native_bridge.h"
#include "rvwmo/host_session.h"
#include "rvwmo/memory_image.h"
#include "rvwmo/producer_ids.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace blackparrot {
namespace {
constexpr uint32_t hart_count = 4;
constexpr uint64_t ram_base = UINT64_C(0x80000000);
constexpr size_t ram_size = size_t{2} * 1024 * 1024 * 1024;
constexpr uint64_t reset_mstatus = UINT64_C(0xa00000000);
constexpr uint64_t reset_sstatus = UINT64_C(0x200000000);
constexpr uint64_t pending_machine_timer = UINT64_C(0x80);

rvwmo::HostSessionConfiguration host_configuration(uint64_t entry) {
  rvwmo::HostSessionConfiguration configuration;
  configuration.platform = "blackparrot";
  configuration.reference_profile = DIFFTEST_REF_PROFILE_ID_BLACKPARROT;
  const std::vector<rvwmo::RuntimeEventKind> hart_kinds = {
      rvwmo::RuntimeEventKind::InstructionAllocate, rvwmo::RuntimeEventKind::InstructionCancelAttempt,
      rvwmo::RuntimeEventKind::InstructionSquash, rvwmo::RuntimeEventKind::LocalStore,
      rvwmo::RuntimeEventKind::LoadSample, rvwmo::RuntimeEventKind::InstructionRetire};
  const std::vector<rvwmo::RuntimeEventKind> publication = {rvwmo::RuntimeEventKind::StorePublish};
  for (uint32_t hart = 0; hart < hart_count; ++hart) {
    const auto producer = rvwmo::hart_producer_id(hart);
    configuration.stream.required_producers.push_back({producer, hart_kinds});
    configuration.producers.push_back({producer, true, true, true, hart_kinds});
    const auto fabric = rvwmo::memory_fabric_producer_id(hart);
    configuration.stream.required_producers.push_back({fabric, publication});
    configuration.producers.push_back({fabric, true, true, true, publication});

    difftest_ref_state_v1 initial{};
    initial.abi_version = DIFFTEST_REF_STATE_ABI_VERSION_1;
    initial.struct_size = sizeof(initial);
    initial.pc = entry;
    initial.privilege = 3;
    initial.mstatus = reset_mstatus;
    initial.sstatus = reset_sstatus;
    initial.mip = pending_machine_timer;
    configuration.initial_harts.push_back(initial);
  }
  return configuration;
}

Configuration native_configuration() {
  Configuration configuration;
  for (uint32_t hart = 0; hart < hart_count; ++hart) {
    const auto producer = rvwmo::hart_producer_id(hart);
    configuration.harts.push_back({hart, producer, producer, producer});
    configuration.publication_producers.push_back(rvwmo::memory_fabric_producer_id(hart));
  }
  return configuration;
}

void validate_initial_registers(const GlobalMem &memory, uint64_t entry) {
  // This platform's GPR SRAM has no reset. All harts must overwrite x1..x31
  // before reading them; independent REF zeros cannot stand in for DUT state.
  for (uint32_t reg = 1; reg < 32; ++reg) {
    std::array<uint8_t, 4> bytes{};
    if (!memory.read(entry + 4 * (reg - 1), bytes.data(), bytes.size()))
      throw std::invalid_argument("BlackParrot register initialization lies outside reference RAM");
    uint32_t instruction = 0;
    for (size_t index = 0; index < bytes.size(); ++index)
      instruction |= uint32_t{bytes[index]} << (8 * index);
    if (instruction != (0x13u | (reg << 7)))
      throw std::invalid_argument("BlackParrot ELF must initialize x1..x31 with addi rd,x0,0 before any read");
  }
}

class NativeSession {
public:
  explicit NativeSession(const std::string &elf_path) {
    if (!memory_.initialize(ram_base, ram_size))
      throw std::runtime_error("BlackParrot reference RAM initialization failed");
    uint64_t entry = 0;
    const auto loaded = rvwmo::load_reference_elf(memory_, elf_path, entry);
    if (!loaded)
      throw std::invalid_argument(loaded.message);
    if (entry != ram_base)
      throw std::invalid_argument("BlackParrot ELF entry must match native boot address 0x80000000");
    validate_initial_registers(memory_, entry);
    host_ = std::make_unique<rvwmo::HostSession>(memory_, host_configuration(entry));
    if (!host_->configuration() || !host_->session())
      throw std::runtime_error("BlackParrot HostSession configuration failed: " + host_->configuration().message);
    adapter_ = std::make_unique<HostSessionAdapter>(*host_);
    const auto installed = install_native_online_verifier(native_configuration(),
        [this](const ConvertedOutput &observed) { return consume(observed); },
        [this](const NativeCapture &capture) { return finish(capture); },
        [this](const rvwmo::CheckResult &failure) { adapter_->report_source_failure(failure); });
    if (!installed)
      throw std::runtime_error("BlackParrot online session installation failed: " + installed.message);
  }

private:
  GlobalMem memory_;
  std::unique_ptr<rvwmo::HostSession> host_;
  std::unique_ptr<HostSessionAdapter> adapter_;
  bool statistics_written_ = false;
  size_t progress_reports_ = 0;

  rvwmo::SessionSubmitResult consume(const ConvertedOutput &observed) {
    std::vector<rvwmo::ArchitecturalRetirement> snapshots;
    const auto converted = capture_architectural_retirements(observed, snapshots);
    if (!converted) {
      rvwmo::SessionSubmitResult rejected;
      rejected.check = adapter_->report_source_failure(converted);
      write_statistics(last_native_capture());
      return rejected;
    }
    auto result = adapter_->submit_closed(observed.batch, snapshots);
    if (result.check.status != rvwmo::CheckStatus::Pass && result.check.status != rvwmo::CheckStatus::Pending)
      write_statistics(last_native_capture());
    if (result.accepted && ++progress_reports_ % 4096 == 0 && !observed.batch.watermarks.empty()) {
      std::cout << "[BP-ONLINE-CHECKPOINT] through="
                << observed.batch.watermarks.front().closed_through.cycle << " ref_steps=";
      for (const auto &hart : host_->session()->hart_statistics())
        std::cout << hart.first << ':' << hart.second.reference_steps << ',';
      std::cout << " finalized=" << host_->finalized() << '\n';
    }
    return result;
  }

  NativeVerification finish(const NativeCapture &capture) {
    auto result = capture.summary.gaps.empty() ? adapter_->finalize(capture.completion)
        : adapter_->report_source_failure({rvwmo::CheckStatus::Incomplete, 0, capture.summary.gaps.front()});
    write_statistics(capture);
    return {result, adapter_->finalized()};
  }

  void write_statistics(const NativeCapture &capture) {
    if (statistics_written_)
      return;
    statistics_written_ = true;
    const auto &statistics = host_->session()->hart_statistics();
    for (uint32_t hart = 0; hart < hart_count; ++hart) {
      const auto found = statistics.find(hart);
      const rvwmo::SessionHartStatistics empty;
      const auto &counts = found == statistics.end() ? empty : found->second;
      const auto terminal = std::count_if(capture.completion.harts.begin(), capture.completion.harts.end(),
          [hart](const auto &completion) { return completion.hart == hart; });
      std::cout << "[BP-REF] hart=" << hart
                << " owner=HostSession platform=blackparrot reference_profile=7 configured_harts=4"
                << " reference_steps=" << counts.reference_steps
                << " architecture_compared=" << counts.architecture_compared
                << " retired_instructions=" << counts.retired_instructions
                << " retired_load_operations=" << counts.retired_load_operations
                << " retired_store_operations=" << counts.retired_store_operations
                << " captured_terminal_wfi=" << terminal
                << " host_finalized=" << host_->finalized() << '\n';
    }
    std::cout << "[BP-HOST] finalized=" << host_->finalized()
              << " platform=blackparrot reference_profile=7 configured_harts=4\n";
    const auto &summary = capture.summary;
    std::cout << "[BP-ONLINE] prefixes=" << summary.online_prefixes
              << " peak_live=" << summary.peak_live_instructions
              << " live=" << summary.live_instructions
              << " converted=" << summary.converted_events << '\n';
    std::cout << "[BP-FINAL] " << host_->final_report() << std::endl;
  }
};

std::unique_ptr<NativeSession> native_session;
} // namespace
} // namespace blackparrot

extern "C" int bp_difftest_s_session_start(const char *elf, uint32_t harts) {
  try {
    if (blackparrot::native_session || !elf || !*elf || harts != blackparrot::hart_count)
      throw std::invalid_argument("BlackParrot session startup requires one ELF and four harts");
    blackparrot::native_session = std::make_unique<blackparrot::NativeSession>(elf);
    std::printf("[BP-REF] initialized public HostSession: harts=4 profile=7 independent_elf=%s online=1\n", elf);
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "[BP-REF] session startup failed: %s\n", error.what());
    return 1;
  }
}
