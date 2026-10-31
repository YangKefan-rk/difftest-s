#include "retirement_snapshot.h"
#include "csr_profile.h"
#include "readonly_hartid.h"
#include <set>
#include <utility>

namespace rvwmo {
namespace boom {
namespace {
CheckResult invalid(const char *message) { return {CheckStatus::Invalid, 0, message}; }
CheckResult unsupported(const char *message) { return {CheckStatus::Unsupported, 0, message}; }

CheckResult validate_coverage(RetirementResultCoverage coverage) {
  switch (coverage) {
  case RetirementResultCoverage::Complete:
    return {};
  case RetirementResultCoverage::FloatingRegisterAndFflagsNeedComparator:
    return unsupported("BOOM retirement needs floating-register and fflags comparison");
  case RetirementResultCoverage::FloatingFlagsNeedComparator:
    return unsupported("BOOM retirement needs fflags comparison");
  case RetirementResultCoverage::CsrStateNeedsComparator:
    return unsupported("BOOM retirement needs CSR-state comparison");
  case RetirementResultCoverage::SystemStateNeedsComparator:
    return unsupported("BOOM retirement needs architectural system-state comparison");
  }
  return invalid("BOOM retirement has an unknown result-coverage kind");
}

CheckResult validate_destination(const CapturedRetirement &captured) {
  switch (captured.destination_type) {
  case IntegerDestinationType::Integer:
  case IntegerDestinationType::Floating:
    if (!captured.destination_register || !captured.destination_value || *captured.destination_register > 31)
      return invalid("BOOM register retirement lacks a valid destination register or value");
    return {};
  case IntegerDestinationType::None:
  case IntegerDestinationType::Zero:
    if (captured.destination_register || captured.destination_value)
      return invalid("BOOM non-writing retirement carries a register result");
    return {};
  }
  return invalid("BOOM retirement has an unknown destination kind");
}
} // namespace

CheckResult convert_retirement_snapshot(const CapturedRetirement &captured, ArchitecturalRetirement &snapshot) {
  if (!captured.id.uid || captured.id.subaccess || captured.pc % 2)
    return invalid("BOOM scalar retirement snapshot has an invalid instruction identity or PC");
  auto result = validate_destination(captured);
  if (!result)
    return result;
  const bool checked_csr = captured.csr_post.has_value() &&
      (captured.instruction & 0x7f) == 0x73 && ((captured.instruction >> 12) & 7) != 0 &&
      certified_csr_instruction(captured.instruction) &&
      captured.csr_post->first == (captured.instruction >> 20);
  if (captured.csr_post && !checked_csr)
    return invalid("BOOM CSR post-state is not the retired instruction's physical CSR address");
  result = checked_csr && captured.coverage == RetirementResultCoverage::CsrStateNeedsComparator
      ? CheckResult{} : validate_coverage(captured.coverage);
  if (!result)
    return result;
  if ((captured.instruction & 0x7f) == 0x73 && ((captured.instruction >> 12) & 7) != 0) {
    if (!is_observable_readonly_hartid(captured.instruction) && !checked_csr)
      return unsupported("BOOM CSR instruction requires architectural CSR-state comparison");
    if (!checked_csr &&
        (captured.destination_type != IntegerDestinationType::Integer || !captured.destination_register ||
         *captured.destination_register != ((captured.instruction >> 7) & 31)))
      return invalid("BOOM read-only mhartid retirement omits its decoded integer destination");
  }
  if (captured.destination_type == IntegerDestinationType::Floating)
    return unsupported("BOOM floating destination is outside the scalar integer session");

  ArchitecturalRetirement converted;
  converted.id = captured.id;
  converted.pc = captured.pc;
  converted.instruction = captured.instruction;
  if (checked_csr)
    converted.csr_post = captured.csr_post;
  if (captured.destination_type == IntegerDestinationType::Integer && *captured.destination_register != 0) {
    converted.destination = ArchitecturalDestination::Integer;
    converted.destination_register = *captured.destination_register;
    converted.destination_value = *captured.destination_value;
  }
  snapshot = converted;
  return {};
}

CheckResult convert_retirement_snapshots(const std::vector<CapturedRetirement> &captured,
                                         std::vector<ArchitecturalRetirement> &snapshots) {
  std::vector<ArchitecturalRetirement> converted;
  converted.reserve(captured.size());
  std::set<OperationId> identities;
  for (const auto &retirement : captured) {
    if (!identities.insert(retirement.id).second)
      return invalid("BOOM retirement snapshot batch repeats an instruction identity");
    ArchitecturalRetirement snapshot;
    auto result = convert_retirement_snapshot(retirement, snapshot);
    if (!result)
      return result;
    converted.push_back(snapshot);
  }
  snapshots = std::move(converted);
  return {};
}

} // namespace boom
} // namespace rvwmo
