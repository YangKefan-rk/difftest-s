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

#include "difftest.h"
#include "difftrace.h"
#include "dut.h"
#include "flash.h"
#include "globalmem.h"
#include "ram.h"
#include "spikedasm.h"
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#if NUM_CORES > 1
#include "rvwmo/runtime.h"
#include "rvwmo/source_boundary.h"
#endif
#if defined(CONFIG_DIFFTEST_SQUASH) && !defined(CONFIG_PLATFORM_FPGA)
#include "svdpi.h"
#endif // CONFIG_DIFFTEST_SQUASH && !CONFIG_PLATFORM_FPGA
#ifdef CONFIG_DIFFTEST_PERFCNT
#include "perf.h"
#endif // CONFIG_DIFFTEST_PERFCNT
#ifdef CONFIG_DIFFTEST_QUERY
#include "query.h"
#endif // CONFIG_DIFFTEST_QUERY

Difftest **difftest = NULL;
#if NUM_CORES > 1
static std::unique_ptr<rvwmo::Runtime> multicore_session;
static std::vector<int> native_exit_codes;
static rvwmo::Runtime &multicore_runtime() {
  assert(multicore_session);
  return *multicore_session;
}
static int runtime_error(const rvwmo::CheckResult &result, const char *phase) {
  if (result) return 0;
  const char *kind = result.status == rvwmo::CheckStatus::Violation ? "VIOLATION" :
    result.status == rvwmo::CheckStatus::Unsupported ? "UNSUPPORTED" :
    result.status == rvwmo::CheckStatus::Pending ? "INCOMPLETE" : "EVENT_ERROR";
  Info("RVWMO %s during %s: %s\n", kind, phase, result.message.c_str());
  return 1;
}
#endif

bool difftest_read_reference_memory(unsigned hart, uint64_t address, size_t size, uint8_t *bytes) {
#if NUM_CORES > 1
  if (multicore_session)
    return multicore_runtime().read_reference_memory(hart, address, size, bytes);
#endif
  return global_memory().read(address, bytes, size);
}

static bool external_fetch_af_config = false;
static ExternalAfTracker external_af_trackers[NUM_CORES];

extern "C" void difftest_external_af_reset(int coreid) {
  if (coreid < 0 || coreid >= NUM_CORES) std::abort();
  external_af_trackers[coreid].reset();
}

extern "C" void difftest_external_af_trap(int coreid, uint64_t pc, int exception,
                                         int interrupt, int source, uint64_t paddr, uint64_t vaddr) {
  if (!external_fetch_af_config) return;
  if (coreid < 0 || coreid >= NUM_CORES ||
      !external_af_trackers[coreid].push({pc, paddr, vaddr, uint32_t(exception), uint32_t(interrupt), uint32_t(source)})) {
    fprintf(stderr, "External AF trap monitor overflow or invalid core: %d\n", coreid);
    std::abort();
  }
}

void difftest_set_external_fetch_af(bool enable) {
  if (difftest != NULL) {
    fprintf(stderr, "external fetch AF must be configured before difftest_init\n");
    std::abort();
  }
  external_fetch_af_config = enable;
}

#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
namespace {

constexpr uint64_t irq_bit(unsigned cause) {
  return 1ULL << cause;
}

constexpr uint64_t kMsi = irq_bit(3);
constexpr uint64_t kSti = irq_bit(5);
constexpr uint64_t kVsti = irq_bit(6);
constexpr uint64_t kMti = irq_bit(7);
constexpr uint64_t kSei = irq_bit(9);
constexpr uint64_t kVsei = irq_bit(10);
constexpr uint64_t kMei = irq_bit(11);
constexpr uint64_t kLcofi = irq_bit(13);
constexpr uint64_t kNonRegInterruptSnapshotMask = kMsi | kSti | kVsti | kMti | kSei | kVsei | kMei | kLcofi;

NonRegInterruptPending make_pending_update(uint64_t valid_mask, uint64_t pending) {
  NonRegInterruptPending ip = {};
  ip.platformIRPMeipValid = (valid_mask & kMei) != 0;
  ip.platformIRPMeip = (pending & kMei) != 0;
  ip.platformIRPMtipValid = (valid_mask & kMti) != 0;
  ip.platformIRPMtip = (pending & kMti) != 0;
  ip.platformIRPMsipValid = (valid_mask & kMsi) != 0;
  ip.platformIRPMsip = (pending & kMsi) != 0;
  ip.platformIRPSeipValid = (valid_mask & kSei) != 0;
  ip.platformIRPSeip = (pending & kSei) != 0;
  ip.platformIRPStipValid = (valid_mask & kSti) != 0;
  ip.platformIRPStip = (pending & kSti) != 0;
  ip.platformIRPVseipValid = (valid_mask & kVsei) != 0;
  ip.platformIRPVseip = (pending & kVsei) != 0;
  ip.platformIRPVstipValid = (valid_mask & kVsti) != 0;
  ip.platformIRPVstip = (pending & kVsti) != 0;
  ip.localCounterOverflowInterruptReqValid = (valid_mask & kLcofi) != 0;
  ip.localCounterOverflowInterruptReq = (pending & kLcofi) != 0;
  return ip;
}

constexpr uint32_t kCsrOpcode = 0x73;
constexpr uint32_t kCsrMip = 0x344;
constexpr uint32_t kCsrSip = 0x144;
constexpr uint32_t kCsrMvip = 0x309;
constexpr uint32_t kCsrHip = 0x644;
constexpr uint32_t kCsrVsip = 0x244;

bool is_pending_csr_address(uint32_t address) {
  return address == kCsrMip || address == kCsrSip || address == kCsrMvip ||
         address == kCsrHip || address == kCsrVsip;
}

bool is_pending_csr_read(uint32_t instruction) {
  if ((instruction & 0x7f) != kCsrOpcode || !is_pending_csr_address((instruction >> 20) & 0xfff)) {
    return false;
  }

  const uint32_t funct3 = (instruction >> 12) & 0x7;
  switch (funct3) {
  case 0x1: // CSRRW: rd=x0 suppresses the read
  case 0x5: // CSRRWI: rd=x0 suppresses the read
    return ((instruction >> 7) & 0x1f) != 0;
  case 0x2: // CSRRS
  case 0x3: // CSRRC
  case 0x6: // CSRRSI
  case 0x7: // CSRRCI
    return true;
  default:
    return false;
  }
}

bool is_pending_csr_write(uint32_t instruction) {
  if ((instruction & 0x7f) != kCsrOpcode || !is_pending_csr_address((instruction >> 20) & 0xfff)) {
    return false;
  }

  const uint32_t funct3 = (instruction >> 12) & 0x7;
  if (funct3 == 0x1 || funct3 == 0x5) { // CSRRW/CSRRWI always write
    return true;
  }
  if (funct3 == 0x2 || funct3 == 0x3 || funct3 == 0x6 || funct3 == 0x7) {
    return ((instruction >> 15) & 0x1f) != 0;
  }
  return false;
}

} // namespace
#endif

int difftest_init() {
  assert(difftest == nullptr);
#if NUM_CORES > 1
  // A fuzzing process may initialize several independent DUT runs.
  multicore_session = std::make_unique<rvwmo::Runtime>(NUM_CORES);
  native_exit_codes.assign(NUM_CORES, STATE_RUNNING);
#ifdef CONFIG_DIFFTEST_SOURCEPREFIXEVENT
  rvwmo::source_boundary().reset(NUM_CORES, CONFIG_DIFF_SOURCE_PREFIX_WIDTH);
#else
  rvwmo::source_boundary().reset(NUM_CORES, 0);
#endif
#endif
#ifdef CONFIG_DIFFTEST_PERFCNT
  difftest_perfcnt_init();
#endif // CONFIG_DIFFTEST_PERFCNT
#ifdef CONFIG_DIFFTEST_IOTRACE
  difftest_iotrace_init();
#endif // CONFIG_DIFFTEST_IOTRACE
#ifdef CONFIG_DIFFTEST_QUERY
  difftest_query_init();
#endif // CONFIG_DIFFTEST_QUERY
  diffstate_buffer_init();
  difftest = new Difftest *[NUM_CORES];
  for (int i = 0; i < NUM_CORES; i++) {
    difftest[i] = new Difftest(i);
    difftest[i]->dut = diffstate_buffer[i]->get(0, 0);
  }
  return 0;
}

int init_nemuproxy(size_t ramsize = 0) {
  for (int i = 0; i < NUM_CORES; i++) {
    difftest[i]->update_nemuproxy(i, ramsize);
  }
  return 0;
}

int difftest_state() {
  for (int i = 0; i < NUM_CORES; i++) {
    if (difftest[i]->get_trap_valid()) {
      const int code = difftest[i]->get_trap_code();
#if NUM_CORES > 1
      if (code != STATE_GOODTRAP && code != STATE_SIM_EXIT) return code;
      if (runtime_error(multicore_runtime().note_done(i, code), "hart completion")) return STATE_ABORT;
#else
      return code;
#endif
    }
    if (difftest[i]->proxy && difftest[i]->proxy->get_status()) {
      return difftest[i]->proxy->get_status();
    }
  }
#if NUM_CORES > 1
  if (multicore_runtime().all_done()) {
    const auto result = multicore_runtime().finish();
    if (result.status == rvwmo::CheckStatus::Pending) return -1;
    if (runtime_error(result, "all-hart finalization")) return STATE_ABORT;
    if (multicore_runtime().print_final_statistics())
      Info("RVWMO scalar PPO/read-value checks passed for all participating harts\n");
    return STATE_GOODTRAP;
  }
#endif
  return -1;
}

#if NUM_CORES > 1
// Native tracing runs without REF execution or memory/PPO certification.
// Its termination still requires a successful trap from every active hart.
static int native_difftest_state() {
  for (int hart = 0; hart < NUM_CORES; ++hart) {
    if (!difftest[hart]->get_trap_valid())
      continue;
    const int code = difftest[hart]->get_trap_code();
    if (code != STATE_GOODTRAP && code != STATE_SIM_EXIT)
      return code;
    if (native_exit_codes[hart] != STATE_RUNNING && native_exit_codes[hart] != code)
      return STATE_ABORT;
    native_exit_codes[hart] = code;
  }
  for (int code : native_exit_codes)
    if (code == STATE_RUNNING)
      return STATE_RUNNING;
  return STATE_GOODTRAP;
}
#endif

int difftest_nstep(int step, bool enable_diff) {
#if CONFIG_DIFFTEST_ZONESIZE > 1
  difftest_switch_zone();
#endif // CONFIG_DIFFTEST_ZONESIZE
  for (int i = 0; i < step; i++) {
    if (enable_diff) {
      if (difftest_step())
        return STATE_ABORT;
    } else {
      difftest_set_dut();
#if NUM_CORES > 1
      const int status = native_difftest_state();
      if (status != STATE_RUNNING)
        return status;
      continue;
#else
      if(difftest_check_trap())
        return STATE_GOODTRAP;
#endif
    }
    int status = difftest_state();
    if (status != STATE_RUNNING)
      return status;
  }
  return STATE_RUNNING;
}

void difftest_switch_zone() {
  for (int i = 0; i < NUM_CORES; i++) {
    diffstate_buffer[i]->switch_zone();
  }
}
void difftest_set_dut() {
  for (int i = 0; i < NUM_CORES; i++) {
    difftest[i]->dut = diffstate_buffer[i]->next();
  }
}
int difftest_step() {
  difftest_set_dut();
#if defined(CONFIG_DIFFTEST_QUERY) && !defined(CONFIG_DIFFTEST_BATCH)
  difftest_query_step();
#endif // CONFIG_DIFFTEST_QUERY
#if NUM_CORES > 1
  std::vector<DiffTestState *> states;
  for (int i = 0; i < NUM_CORES; ++i) states.push_back(difftest[i]->get_dut());
  if (runtime_error(multicore_runtime().capture(states), "event acquisition")) return 1;
#endif
  for (int i = 0; i < NUM_CORES; i++) {
#if NUM_CORES > 1
    if (multicore_runtime().done(i)) {
      if (difftest[i]->drain_store_checks()) return 1;
      continue;
    }
#endif
    int ret = difftest[i]->step();
    if (ret) {
      return ret;
    }
  }
  return 0;
}

int difftest_check_trap() {
  for (int i = 0; i < NUM_CORES; i++) {
    if(difftest[i]->dut->event.valid && (difftest[i]->dut->event.exceptionInst & 0xffff) == 0x6b) {
      return 1;
    }
  }
  return 0;
}

void difftest_trace_read() {
  for (int i = 0; i < NUM_CORES; i++) {
    difftest[i]->trace_read();
  }
}

void difftest_trace_write(int step) {
  for (int i = 0; i < NUM_CORES; i++) {
    difftest[i]->trace_write(step);
  }
}

void difftest_finish() {
#ifdef CONFIG_DIFFTEST_PERFCNT
  uint64_t cycleCnt = difftest[0]->get_trap_event()->cycleCnt;
  difftest_perfcnt_finish(cycleCnt);
#endif // CONFIG_DIFFTEST_PERFCNT
#ifdef CONFIG_DIFFTEST_IOTRACE
  difftest_iotrace_free();
#endif // CONFIG_DIFFTEST_IOTRACE
#ifdef CONFIG_DIFFTEST_QUERY
  difftest_query_finish();
#endif // CONFIG_DIFFTEST_QUERY
  diffstate_buffer_free();
  for (int i = 0; i < NUM_CORES; i++) {
    delete difftest[i];
  }
  delete[] difftest;
  difftest = NULL;
#if NUM_CORES > 1
  multicore_session.reset();
#endif
}

#if defined(CONFIG_DIFFTEST_SQUASH) && !defined(CONFIG_PLATFORM_FPGA)
svScope squashScope;
void set_squash_scope() {
  squashScope = svGetScope();
}

extern "C" void set_squash_enable(int enable);
void difftest_squash_enable(int enable) {
  if (squashScope == NULL) {
    printf("Error: Could not retrieve squash scope, set first\n");
    assert(squashScope);
  }
  svSetScope(squashScope);
  set_squash_enable(enable);
}
#endif // CONFIG_DIFFTEST_SQUASH && !CONFIG_PLATFORM_FPGA

#ifdef CONFIG_DIFFTEST_REPLAY
svScope replayScope;
void set_replay_scope() {
  replayScope = svGetScope();
}

extern "C" void set_replay_head(int head);
void difftest_replay_head(int head) {
  if (replayScope == NULL) {
    printf("Error: Could not retrieve replay scope, set first\n");
    assert(replayScope);
  }
  svSetScope(replayScope);
  set_replay_head(head);
}
#endif // CONFIG_DIFFTEST_REPLAY

Difftest::Difftest(int coreid) : id(coreid) {
  external_fetch_af_enabled = external_fetch_af_config;
  if (external_fetch_af_enabled) {
    Info("Core %d external AF matching enabled: only injection-tagged traps are synchronized "
         "(+DIFFTEST_EXTERNAL_FETCH_AF=1); untagged AFs remain strict\n", id);
  }
  state = new DiffState();
#ifdef CONFIG_DIFFTEST_REPLAY
  state_ss = (DiffState *)malloc(sizeof(DiffState));
#endif // CONFIG_DIFFTEST_REPLAY
}

Difftest::~Difftest() {
  delete state;
  delete difftrace;
  if (proxy) {
    delete proxy;
  }
#ifdef CONFIG_DIFFTEST_REPLAY
  free(state_ss);
  if (proxy_reg_ss) {
    free(proxy_reg_ss);
  }
#endif // CONFIG_DIFFTEST_REPLAY
}


void Difftest::update_nemuproxy(int coreid, size_t ram_size = 0) {
  proxy = new REF_PROXY(coreid, ram_size);
#ifdef CONFIG_DIFFTEST_REPLAY
  proxy_reg_size = proxy->get_reg_size();
  proxy_reg_ss = (uint8_t *)malloc(proxy_reg_size);
#endif // CONFIG_DIFFTEST_REPLAY
}

#ifdef CONFIG_DIFFTEST_REPLAY
bool Difftest::can_replay() {
  auto info = dut->trace_info;
  return info.valid && !info.in_replay && info.trace_size > 1;
}

bool Difftest::in_replay_range() {
  auto info = dut->trace_info;
  if (!info.valid || !info.in_replay || info.trace_size > 1)
    return false;
  int pos = info.trace_head;
  int head = replay_status.trace_head;
  int tail = (head + replay_status.trace_size - 1) % CONFIG_DIFFTEST_REPLAY_SIZE;
  if (tail < head) { // consider ring queue
    return (pos <= tail) || (pos >= head);
  } else {
    return (pos >= head) && (pos <= tail);
  }
}

void Difftest::replay_snapshot() {
  memcpy(state_ss, state, sizeof(DiffState));
  memcpy(proxy_reg_ss, &proxy->regs_int, proxy_reg_size);
  proxy->ref_csrcpy(squash_csr_buf, REF_TO_DUT);
  proxy->ref_store_log_reset();
  proxy->set_store_log(true);
  globalmem_store_log_reset();
  globalmem_set_store_log(true);
}

void Difftest::do_replay() {
  auto info = dut->trace_info;
  replay_status.in_replay = true;
  replay_status.trace_head = info.trace_head;
  replay_status.trace_size = info.trace_size;
  memcpy(state, state_ss, sizeof(DiffState));
  memcpy(&proxy->regs_int, proxy_reg_ss, proxy_reg_size);
  proxy->ref_regcpy(&proxy->regs_int, DUT_TO_REF, false);
  proxy->ref_csrcpy(squash_csr_buf, DUT_TO_REF);
  proxy->ref_store_log_restore();
  globalmem_store_log_restore();
  difftest_replay_head(info.trace_head);
  // clear buffered queue
#ifdef CONFIG_DIFFTEST_STOREEVENT
  while (!store_event_queue.empty())
    store_event_queue.pop();
#endif // CONFIG_DIFFTEST_STOREEVENT
#if defined(CONFIG_DIFFTEST_LOADEVENT) && defined(CONFIG_DIFFTEST_SQUASH)
  while (!load_event_queue.empty())
    load_event_queue.pop();
#endif
}
#endif // CONFIG_DIFFTEST_REPLAY

int Difftest::step() {
#ifdef CONFIG_DIFFTEST_REPLAY
  static int replay_step = 0;
  if (replay_status.in_replay) {
    if (!in_replay_range()) {
      return 0;
    } else {
      replay_step++;
      if (replay_step > replay_status.trace_size) {
        Info("*** DUT run out of replay range, failed to get error location ***\n");
        return 1;
      }
    }
  }
  bool canReplay = can_replay();
  if (canReplay) {
    replay_snapshot();
  } else {
    proxy->set_store_log(false);
    globalmem_set_store_log(false);
  }
  int ret = check_all();
  if (ret && canReplay) {
    Info("\n**** Start replay for more accurate error location ****\n");
    do_replay();
    return 0;
  } else {
    return ret;
  }
#else
  return check_all();
#endif // CONFIG_DIFFTEST_REPLAY
}

inline int Difftest::check_all() {
  progress = false;
  load_mismatch = false;
  access_fault_skipped = false;
  external_af_matched = false;

  if (check_timeout()) {
    return 1;
  }
  do_first_instr_commit();

  // Each cycle is checked for an store event, and recorded in queue.
  // It is checked every time an instruction is committed and queue has content.
#ifdef CONFIG_DIFFTEST_STOREEVENT
  store_event_record();
#endif

#ifdef CONFIG_DIFFTEST_SQUASH
#ifdef CONFIG_DIFFTEST_LOADEVENT
  load_event_record();
#endif // CONFIG_DIFFTEST_LOADEVENT
#endif // CONFIG_DIFFTEST_SQUASH

#ifdef DEBUG_GLOBALMEM
  if (do_global_memory_update()) {
    return 1;
  }
#endif

#ifdef CONFIG_DIFFTEST_CMOINVALEVENT
  if (cmo_inval_event_record()) return 1;
#endif // CONFIG_DIFFTEST_CMOINVALEVENT

#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
  tlb_event_record();
#endif

  if (dut->event.valid && external_fetch_af_enabled) {
    external_af_matched = external_af_trackers[id].consume(
        dut->event.exceptionPC, dut->event.exception, dut->event.interrupt, external_af_trap);
    if (external_af_trackers[id].broken()) {
      Info("Core %d external AF trap stream mismatch at pc=0x%lx; refusing waiver\n", id, dut->event.exceptionPC);
      return 1;
    }
  }
  if (!has_commit) {
    // Bootstrap traps still consume monitor records, before REF starts checking.
    if (external_fetch_af_enabled) dut->event.valid = 0;
    return 0;
  }

#ifdef DEBUG_REFILL
  if (do_irefill_check() || do_drefill_check() || do_ptwrefill_check()) {
    return 1;
  }
#endif

#ifdef DEBUG_L2TLB
  if (do_l2tlb_check()) {
    return 1;
  }
#endif

#if defined(DEBUG_L1TLB) && !(NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH))
  if (do_l1tlb_check()) {
    return 1;
  }
#endif

#ifdef DEBUG_MODE_DIFF
  // skip load & store insts in debug mode
  // for other insts copy inst content to ref's dummy debug module
  for (int i = 0; i < DIFFTEST_COMMIT_WIDTH; i++) {
    if (DEBUG_MEM_REGION(dut->commit[i].valid, dut->commit[i].pc))
      debug_mode_copy(dut->commit[i].pc, dut->commit[i].isRVC ? 2 : 4, dut->commit[i].inst);
  }

#endif

#ifdef CONFIG_DIFFTEST_LRSCEVENT
  // sync lr/sc reg microarchitectural status to the REF
  if (dut->lrsc.valid) {
    dut->lrsc.valid = 0;
    struct SyncState sync;
    sync.sc_fail = !dut->lrsc.success;
    proxy->uarchstatus_sync((uint64_t *)&sync);
  }
#endif

#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  do_non_reg_interrupt_pending();
  if (csr_snapshot_mismatch) {
    return 1;
  }
#endif

#ifdef CONFIG_DIFFTEST_MHPMEVENTOVERFLOWEVENT
  do_mhpmevent_overflow();
#endif
#ifdef CONFIG_DIFFTEST_CRITICALERROREVENT
  do_raise_critical_error();
#endif
#ifdef CONFIG_DIFFTEST_SYNCAIAEVENT
  do_sync_aia();
#endif
#ifdef CONFIG_DIFFTEST_SYNCCUSTOMMFLUSHPWREVENT
  do_sync_custom_mflushpwr();
#endif

  num_commit = 0; // reset num_commit this cycle to 0
  if (dut->event.valid) {
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
    csr_read_snapshot.valid = false;
#endif
    // interrupt has a higher priority than exception
    dut->event.interrupt ? do_interrupt() : do_exception();
    dut->event.valid = 0;
    dut->commit[0].valid = 0;
  } else {
#if !defined(BASIC_DIFFTEST_ONLY) && !defined(CONFIG_DIFFTEST_SQUASH)
    if (dut->commit[0].valid) {
      dut_commit_first_pc = dut->commit[0].pc;
      ref_commit_first_pc = proxy->pc;
      if (dut_commit_first_pc != ref_commit_first_pc) {
        pc_mismatch = true;
      }
    }
#endif
    for (int i = 0; i < CONFIG_DIFF_COMMIT_WIDTH; i++) {
      if (dut->commit[i].valid) {
        if (do_instr_commit(i)) {
          return 1;
        }
#ifdef CONFIG_DIFFTEST_VECFOFSYNCEVENT
        // only fof loads (opcode=0x07, mop=00, lumop=10000) should trigger sync
        if ((dut->commit[i].instr & 0x1f0007f) == 0x1000007) do_vec_fof_sync();
#endif
#ifndef CONFIG_DIFFTEST_SQUASH
        load_mismatch |= do_load_check(i);
        if (do_store_check()) {
          return 1;
        }
#endif // CONFIG_DIFFTEST_SQUASH
        dut->commit[i].valid = 0;
        num_commit += 1 + dut->commit[i].nFused;
      }
    }
  }

  if (update_delayed_writeback()) {
    return 1;
  }

  if (!progress && !load_mismatch) {
    return 0;
  }

  proxy->sync();

  if (num_commit > 0) {
    state->record_group(dut->commit[0].pc, num_commit);
  }

  if (apply_delayed_writeback()) {
    return 1;
  }

  const bool arch_compared = !access_fault_skipped;
  const bool arch_mismatch = arch_compared && proxy->compare(dut);
#if NUM_CORES > 1
  if (arch_compared && !arch_mismatch && num_commit &&
      runtime_error(multicore_runtime().note_arch_compare(id, num_commit), "independent architecture comparison"))
    return 1;
#endif
  if (arch_mismatch || pc_mismatch || load_mismatch
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
      || interrupt_mismatch || csr_snapshot_mismatch
#endif
  ) {
#ifdef FUZZING
    if (!load_mismatch && in_disambiguation_state()) {
      Info("Mismatch detected with a disambiguation state at pc = 0x%lx.\n", dut->trap.pc);
      return 0;
    }
#endif
    display();
    proxy->display(dut);
#ifdef FUZZER_LIB
    stats.exit_code = SimExitCode::difftest;
#endif // FUZZER_LIB
    return 1;
  }

  return 0;
}

void Difftest::do_interrupt() {
  state->record_interrupt(dut->event.exceptionPC, dut->event.exceptionInst, dut->event.interrupt);
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  uint64_t restore_mask = 0;
  const uint64_t latest_pending = latest_non_reg_interrupt_pending;
  if (dut->event.interruptSnapshotValid) {
    const uint64_t cause = dut->event.interrupt;
    if (cause >= 64 || !(dut->event.interruptCandidates & irq_bit(cause))) {
      Info("Core %d interrupt candidate mismatch: cause=%lu candidates=0x%016lx\n", this->id, cause,
           dut->event.interruptCandidates);
      interrupt_mismatch = true;
    }

    const uint64_t accepted_pending = dut->event.nonRegInterruptPending;
    const uint64_t snapshot_mask = dut->event.nonRegInterruptPendingMask & kNonRegInterruptSnapshotMask;
    const uint64_t latest_mask = latest_non_reg_interrupt_pending_mask & kNonRegInterruptSnapshotMask;
    const uint64_t rewind_domain = snapshot_mask | latest_mask;
    restore_mask = (accepted_pending ^ latest_pending) & rewind_domain;
    if (restore_mask) {
      auto accepted = make_pending_update(restore_mask, accepted_pending);
      proxy->non_reg_interrupt_pending(accepted);
    }
  }
#endif
  if (dut->event.hasNMI) {
    proxy->trigger_nmi(dut->event.hasNMI, dut->event.interrupt);
  } else if (dut->event.virtualInterruptIsHvictlInject) {
    proxy->virtual_interrupt_is_hvictl_inject(dut->event.virtualInterruptIsHvictlInject);
  }
  struct InterruptDelegate intrDeleg;
  intrDeleg.irToHS = dut->event.irToHS;
  intrDeleg.irToVS = dut->event.irToVS;
  proxy->intr_delegate(intrDeleg);
  proxy->raise_intr(dut->event.interrupt | (1ULL << 63));
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  if (restore_mask) {
    auto latest = make_pending_update(restore_mask, latest_pending);
    proxy->non_reg_interrupt_pending(latest);
  }
#endif
  progress = true;
}

void Difftest::do_exception() {
  state->record_exception(dut->event.exceptionPC, dut->event.exceptionInst, dut->event.exception);
  uint64_t fault_vaddr = dut->csr.privilegeMode == 3 ? dut->csr.mtval : dut->csr.stval;
#ifdef CONFIG_DIFFTEST_HCSRSTATE
  if (dut->csr.privilegeMode != 3 && dut->hcsr.virtMode) fault_vaddr = dut->hcsr.vstval;
#endif
  // Nanhu transports a 50-bit VA internally; CSR sign extension depends on the
  // pre-trap translation mode. Keep PA matching in the RTL request tracker.
  const uint64_t vaddr_mask = (uint64_t(1) << 50) - 1;
  const bool fault_address_matches = (fault_vaddr & vaddr_mask) == (external_af_trap.vaddr & vaddr_mask);
  if (external_fetch_af_enabled && external_af_matched && fault_address_matches &&
      ExternalAfTracker::permits(external_af_trap)) {
    // The monitor follows an injected response through FTQ/ROB to this trap.
    // Never execute the faulting instruction in REF (it could store or do MMIO).
    // CSR snapshots contain the destination privilege. Synchronous exceptions
    // use xTVEC.BASE even when xTVEC.MODE is vectored.
    uint64_t trap_pc = dut->csr.privilegeMode == 3 ? dut->csr.mtvec : dut->csr.stvec;
#ifdef CONFIG_DIFFTEST_HCSRSTATE
    if (dut->csr.privilegeMode != 3 && dut->hcsr.virtMode) {
      trap_pc = dut->hcsr.vstvec;
    }
#endif
    trap_pc &= ~uint64_t(3);
    const uint64_t commit_pc = dut->commit[0].pc;
    dut->commit[0].pc = trap_pc;
    regcpy_dut_to_ref();
    dut->commit[0].pc = commit_pc;
    access_fault_skipped = true;
    Info("Core %d external AF comparison skipped: cause=%lu pc=0x%lx paddr=0x%lx source=0x%x handler=0x%lx\n",
         id, dut->event.exception, dut->event.exceptionPC, external_af_trap.paddr, external_af_trap.source, trap_pc);
  } else if (dut->event.exception == EX_IPF || dut->event.exception == EX_LPF || dut->event.exception == EX_SPF ||
      dut->event.exception == EX_IGPF || dut->event.exception == EX_LGPF || dut->event.exception == EX_SGPF) {
    struct ExecutionGuide guide;
    guide.force_raise_exception = true;
    guide.exception_num = dut->event.exception;
    guide.mtval = dut->csr.mtval;
    guide.stval = dut->csr.stval;
#ifdef CONFIG_DIFFTEST_HCSRSTATE
    guide.mtval2 = dut->hcsr.mtval2;
    guide.htval = dut->hcsr.htval;
    guide.vstval = dut->hcsr.vstval;
#endif // CONFIG_DIFFTEST_HCSRSTATE
    guide.force_set_jump_target = false;
    proxy->guided_exec(guide);
  } else if (dut->event.exception == EX_HWE) {
    proxy->raise_intr(dut->event.exception);
  } else {
#ifdef DEBUG_MODE_DIFF
    if (DEBUG_MEM_REGION(true, dut->event.exceptionPC)) {
      debug_mode_copy(dut->event.exceptionPC, 4, dut->event.exceptionInst);
    }
#endif
    proxy->ref_exec(1);
  }

#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_LOADEVENT) && defined(CONFIG_DIFFTEST_ARCHVECREGSTATE)
  const uint32_t opcode = dut->event.exceptionInst & 0x7f;
  const uint32_t width = (dut->event.exceptionInst >> 12) & 7;
  if ((opcode == 0x07 || opcode == 0x27) && (width == 0 || width >= 5)) {
    Info("RVWMO UNSUPPORTED: exceptioning vector memory instruction at pc=0x%lx\n", dut->event.exceptionPC);
    load_mismatch = true;
  }
#endif

#ifdef FUZZING
  static uint64_t lastExceptionPC = 0xdeadbeafUL;
  static int sameExceptionPCCount = 0;
  if (dut->event.exceptionPC == lastExceptionPC) {
    if (sameExceptionPCCount >= 5) {
      Info("Found infinite loop at exception_pc %lx. Exiting.\n", dut->event.exceptionPC);
      dut->trap.hasTrap = 1;
      dut->trap.code = STATE_FUZZ_COND;
#ifdef FUZZER_LIB
      stats.exit_code = SimExitCode::exception_loop;
#endif // FUZZER_LIB
      return;
    }
    sameExceptionPCCount++;
  }
  if (!sameExceptionPCCount && dut->event.exceptionPC != lastExceptionPC) {
    sameExceptionPCCount = 0;
  }
  lastExceptionPC = dut->event.exceptionPC;
#endif // FUZZING

  progress = true;
}

#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
void Difftest::apply_csr_read_snapshot(int index, uint64_t &restore_mask, uint64_t &restore_pending,
                                       bool &lcofi_changed_after_snapshot) {
  restore_mask = 0;
  restore_pending = latest_non_reg_interrupt_pending;
  lcofi_changed_after_snapshot = false;

  const auto &commit = dut->commit[index];
  auto &snapshot = csr_read_snapshot;
  if (!is_pending_csr_read(commit.instr)) {
    return;
  }

  if (!snapshot.valid) {
    Info("Core %d missing CSR pending snapshot: pc=0x%016lx instr=0x%08x\n", this->id, commit.pc,
         commit.instr);
    csr_snapshot_mismatch = true;
    return;
  }

  const uint64_t snapshot_pending = snapshot.pending & kNonRegInterruptSnapshotMask;
  const uint64_t snapshot_mask = snapshot.mask & kNonRegInterruptSnapshotMask;
  const uint64_t latest_mask = latest_non_reg_interrupt_pending_mask & kNonRegInterruptSnapshotMask;
  const uint64_t rewind_domain = snapshot_mask | latest_mask;
  restore_mask = (snapshot_pending ^ latest_non_reg_interrupt_pending) & rewind_domain;
  lcofi_changed_after_snapshot = snapshot.lcofi_epoch != lcofi_update_epoch;
  if (restore_mask) {
    auto accepted = make_pending_update(restore_mask, snapshot_pending);
    proxy->non_reg_interrupt_pending(accepted);
  }
  snapshot.valid = false;
}

#endif

int Difftest::do_instr_commit(int i) {

  // store the writeback info to debug array
#ifdef BASIC_DIFFTEST_ONLY
  uint64_t commit_pc = proxy->pc;
#else
  uint64_t commit_pc = dut->commit[i].pc;
#endif
  uint64_t commit_instr = dut->commit[i].instr;
  state->record_inst(commit_pc, commit_instr, (dut->commit[i].rfwen | dut->commit[i].fpwen | dut->commit[i].vecwen),
                     dut->commit[i].wdest, get_commit_data(i), dut->commit[i].skip != 0, dut->commit[i].special & 0x1,
                     dut->commit[i].lqIdx, dut->commit[i].sqIdx, dut->commit[i].robIdx, dut->commit[i].isLoad,
                     dut->commit[i].isStore);

#ifdef FUZZING
  // isExit
  if (dut->commit[i].special & 0x2) {
    dut->trap.hasTrap = 1;
    dut->trap.code = STATE_SIM_EXIT;
#ifdef FUZZER_LIB
    stats.exit_code = SimExitCode::sim_exit;
#endif // FUZZER_LIB
    return 0;
  }
#endif // FUZZING

  progress = true;
  update_last_commit();

  // isDelayeWb
  if (dut->commit[i].special & 0x1) {
    int *status =
#ifdef CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
        dut->commit[i].rfwen ? delayed_int :
#endif // CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
#ifdef CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
        dut->commit[i].fpwen ? delayed_fp
                             :
#endif // CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
                             nullptr;
    if (status) {
      if (status[dut->commit[i].wdest]) {
        display();
        Info("The delayed register %s has already been delayed for %d cycles\n",
             (dut->commit[i].rfwen ? regs_name_int : regs_name_fp)[dut->commit[i].wdest], status[dut->commit[i].wdest]);
        raise_trap(STATE_ABORT);
        return 1;
      }
      status[dut->commit[i].wdest] = 1;
    }
  }

#ifdef DEBUG_MODE_DIFF
  if (spike_valid() && (IS_DEBUGCSR(commit_instr) || IS_TRIGGERCSR(commit_instr))) {
    Info("s0 is %016lx ", dut->regs.gpr[8]);
    Info("pc is %lx %s\n", commit_pc, spike_dasm(commit_instr));
  }
#endif

#if NUM_CORES > 1
  if (DEBUG_MODE_SKIP(dut->commit[i].valid, dut->commit[i].pc, dut->commit[i].inst))
    multicore_runtime().exclude("debug-mode skipped instruction lacks complete RVWMO semantics");
  if (runtime_error(multicore_runtime().before_commit(id, i, *dut, *proxy), "reference preparation")) return 1;
  if ((commit_instr & 0x7f) == 0x6b && dut->trap.hasTrap && dut->trap.pc == commit_pc) {
    proxy->skip_one(dut->commit[i].isRVC, false, false, false, 0, 0, dut);
    return runtime_error(multicore_runtime().after_commit(id, *proxy), "termination retirement");
  }
#endif

  // MMIO accessing should not be a branch or jump, just +2/+4 to get the next pc
  // to skip the checking of an instruction, just copy the reg state to reference design
  if (dut->commit[i].skip || (DEBUG_MODE_SKIP(dut->commit[i].valid, dut->commit[i].pc, dut->commit[i].inst))) {
#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
    pending_translations[dut->commit[i].tlbId].clear();
#endif
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
    if (is_pending_csr_read(dut->commit[i].instr)) {
      csr_read_snapshot.valid = false;
    }
#endif
    // We use the physical register file to get wdata
    proxy->skip_one(dut->commit[i].isRVC, (dut->commit[i].rfwen && dut->commit[i].wdest != 0), dut->commit[i].fpwen,
                    dut->commit[i].vecwen, dut->commit[i].wdest, get_commit_data(i), dut);
#if NUM_CORES > 1
    return runtime_error(multicore_runtime().after_commit(id, *proxy), "skipped retirement validation");
#else
    return 0;
#endif
  }

#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  uint64_t csr_restore_mask = 0;
  uint64_t csr_restore_pending = latest_non_reg_interrupt_pending;
  bool lcofi_changed_after_snapshot = false;
  apply_csr_read_snapshot(i, csr_restore_mask, csr_restore_pending, lcofi_changed_after_snapshot);
  if (csr_snapshot_mismatch) {
    return 1;
  }
#endif

#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
  assert(dut->commit[i].tlbId < (1 << 10));
  active_translations.swap(pending_translations[dut->commit[i].tlbId]);
  pending_translations[dut->commit[i].tlbId].clear();
  const bool check_tlb = !active_translations.empty() && spike_valid();
  tlb_commit_pc = commit_pc;
  tlb_mismatch = false;
  if (check_tlb) {
    if (!proxy->supports_tlb_check()) {
      Info("Core %d PTE check requires a Spike built with committed-translation support\n", id);
      return 1;
    }
    proxy->set_tlb_check(this, [](void *context, uint64_t vaddr, bool is_fetch) {
      return static_cast<Difftest *>(context)->check_translation(vaddr, is_fetch);
    });
  }
#endif

  // Default: single step exec
  // when there's a fused instruction, let proxy execute more instructions.
  int result = 0;
  for (int j = 0; j < dut->commit[i].nFused + 1; j++) {
#if NUM_CORES > 1 && !defined(CONFIG_DIFFTEST_SQUASH) && !defined(BASIC_DIFFTEST_ONLY)
    // ponytail: only trust committed fence.i; general self-modifying code needs fetch-time tracking.
    if (j == 0 && dut->commit[i].nFused == 0 && (commit_instr & 0x707f) == 0x100f) {
      if (proxy->exec_fence_i(commit_pc, commit_instr)) {
        display();
        result = 1;
        break;
      }
    } else
#endif
    proxy->ref_exec(1);
#if NUM_CORES > 1
    if (runtime_error(multicore_runtime().note_reference_step(id), "independent REF execution")) return 1;
#endif
#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
    if (tlb_mismatch) {
      result = 1;
      break;
    }
#endif
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
    if (j == 0) {
      const bool pending_csr_write = is_pending_csr_write(dut->commit[i].instr);
      uint64_t post_csr_restore_mask = csr_restore_mask;
      if (pending_csr_write && !lcofi_changed_after_snapshot) {
        // LCOFIP is sticky architectural state. With no later hardware update,
        // the CSR result produced by REF is the newest value and must not be undone.
        post_csr_restore_mask &= ~kLcofi;
      }
      if (post_csr_restore_mask) {
        auto latest = make_pending_update(post_csr_restore_mask, csr_restore_pending);
        proxy->non_reg_interrupt_pending(latest);
      }
      if (pending_csr_write) {
        proxy->sync();
        latest_non_reg_interrupt_pending =
            (latest_non_reg_interrupt_pending & ~kLcofi) | (proxy->csr.mip & kLcofi);
      }
    }
#endif
#ifdef CONFIG_DIFFTEST_SQUASH
    commit_stamp = (commit_stamp + 1) % CONFIG_DIFFTEST_SQUASH_STAMPSIZE;
    load_mismatch |= do_load_check(i);
    if (do_store_check()) {
      return 1;
    }
#endif // CONFIG_DIFFTEST_SQUASH
  }

#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
  if (check_tlb) {
    proxy->set_tlb_check(nullptr, nullptr);
  }
  active_translations.clear();
#endif

#if NUM_CORES > 1
  if (runtime_error(multicore_runtime().after_commit(id, *proxy), "retirement validation")) result = 1;
#endif
  return result;
}

void Difftest::regcpy_dut_to_ref() {
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  // DUT mip.SEIP is software OR external; Spike regcpy must receive only the software-owned bit.
  const uint64_t dut_mip = dut->csr.mip;
  const bool software_seip = dut->non_reg_interrupt_pending.valid
                                 ? dut->non_reg_interrupt_pending.softwareSeip
                                 : latest_software_seip;
  dut->csr.mip = (dut_mip & ~kSei) | (software_seip ? kSei : 0);
#endif
  proxy->regcpy(dut);
#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
  dut->csr.mip = dut_mip;
#endif
}

void Difftest::do_first_instr_commit() {
  if (!has_commit && dut->commit[0].valid) {
#ifndef BASIC_DIFFTEST_ONLY
    if (dut->commit[0].pc != FIRST_INST_ADDRESS) {
      return;
    }
#endif
    Info("The first instruction of core %d has commited. Difftest enabled. \n", id);
    has_commit = 1;
    nemu_this_pc = FIRST_INST_ADDRESS;

    proxy->flash_init((const uint8_t *)flash_dev.base, flash_dev.img_size, flash_dev.img_path);
#if NUM_CORES == 1
    simMemory->clone_on_demand(
        [this](uint64_t offset, void *src, size_t n) {
          uint64_t dest_addr = PMEM_BASE + offset;
          proxy->mem_init(dest_addr, src, n, DUT_TO_REF);
        },
        true);
#endif
    // Use a temp variable to store the current pc of dut
    uint64_t dut_this_pc = dut->commit[0].pc;
    // NEMU should always start at FIRST_INST_ADDRESS
    dut->commit[0].pc = FIRST_INST_ADDRESS;
    regcpy_dut_to_ref();
    dut->commit[0].pc = dut_this_pc;
    // Do not reconfig simulator 'proxy->update_config(&nemu_config)' here:
    // If this is main sim thread, simulator has its own initial config
    // If this process is checkpoint wakeuped, simulator's config has already been updated,
    // do not override it.
  }
  if(has_commit && dut->commit[0].valid && dut->commit[0].pc == FIRST_INST_ADDRESS){
    regcpy_dut_to_ref();
  }
}

int Difftest::do_load_check(int i) {
#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_LOADEVENT)
  auto &load = dut->load[i];
  if (!load.valid)
    return 0;
  if (!multicore_runtime().covered() || (!load.isLoad && !load.isAtomic) || load.isVLoad) {
    Info("RVWMO UNSUPPORTED: load lacks a validated runtime path on core %d\n", id);
    return 1;
  }
  // REF consumed the captured read; the checker retains the final PPO/value obligation.
  load.valid = 0;
#else
  (void)i;
#endif
  return 0;
}

int Difftest::drain_store_checks() {
#ifdef CONFIG_DIFFTEST_STOREEVENT
  store_event_record();
  return do_store_check();
#else
  return 0;
#endif
}

int Difftest::do_store_check() {
#ifdef CONFIG_DIFFTEST_STOREEVENT
  while (!store_event_queue.empty()) {
    auto store_event = store_event_queue.front();
#ifdef CONFIG_DIFFTEST_SQUASH
    if (store_event.stamp != commit_stamp)
      return 0;
#endif // CONFIG_DIFFTEST_SQUASH
    auto addr = store_event.addr;
    auto data = store_event.data;
    auto mask = store_event.mask;

    if (proxy->store_commit(&addr, &data, &mask)) {
#ifdef FUZZING
      if (in_disambiguation_state()) {
        Info("Store mismatch detected with a disambiguation state at pc = 0x%lx.\n", dut->trap.pc);
        return 0;
      }
#endif
      uint64_t pc = store_event.pc;
      display();

      Info("\n==============  Store Commit Event (Core %d)  ==============\n", this->id);
      proxy->get_store_event_other_info(&pc);
      Info("Mismatch for store commits \n");
      Info("  REF commits addr 0x%016lx, data 0x%016lx, mask 0x%04x, pc 0x%016lx\n", addr, data, mask, pc);
      Info("  DUT commits addr 0x%016lx, data 0x%016lx, mask 0x%04x, pc 0x%016lx, robidx 0x%x\n", store_event.addr,
           store_event.data, store_event.mask, store_event.pc, store_event.robidx);

      store_event_queue.pop();
      return 1;
    }

#if NUM_CORES > 1
    if (runtime_error(multicore_runtime().verify_store(id, store_event.storeUid, addr, data, mask),
                      "independent reference store audit")) return 1;
#endif
    store_event_queue.pop();
  }
#endif // CONFIG_DIFFTEST_STOREEVENT
  return 0;
}

// cacheid: 0 -> icache
//          1 -> dcache
//          2 -> pagecache
//          3 -> icache PIQ refill ipf
//          4 -> icache mainPipe port0 toIFU
//          5 -> icache mainPipe port1 toIFU
//          6 -> icache ipf refill cache
//          7 -> icache mainPipe port0 read PIQ
//          8 -> icache mainPipe port1 read PIQ
int Difftest::do_refill_check(int cacheid) {
#ifdef CONFIG_DIFFTEST_REFILLEVENT
  auto &refill = dut->refill[cacheid];
  if (!refill.valid)
    return 0;
  refill.valid = 0;
  const uint64_t address = refill.addr & ~UINT64_C(63);
  if (!in_pmem(address) || !in_pmem(address + 63))
    return 0;
  for (size_t word = 0; word < 8; ++word) {
    uint64_t expected = 0;
    read_globalmem(address + word * 8, &expected, 8);
    if (refill.data[word] != expected) {
      Info("Refill mismatch: core=%d cache=%d address=0x%lx DUT=0x%lx GlobalMem=0x%lx\n",
           id, cacheid, address + word * 8, refill.data[word], expected);
      return 1;
    }
  }
#else
  (void)cacheid;
#endif
  return 0;
}

int Difftest::do_irefill_check() {
  int r = 0;
  r |= do_refill_check(ICACHEID);
  // r |= do_refill_check(3);
  // r |= do_refill_check(4);
  // r |= do_refill_check(5);
  // r |= do_refill_check(6);
  // r |= do_refill_check(7);
  // r |= do_refill_check(8);
  return r;
}

int Difftest::do_drefill_check() {
  return do_refill_check(DCACHEID);
}

int Difftest::do_ptwrefill_check() {
  return do_refill_check(PAGECACHEID);
}

typedef struct {
  PTE pte;
  uint8_t level;
} r_s2xlate;

r_s2xlate do_s2xlate(Hgatp *hgatp, uint64_t gpaddr) {
  PTE pte;
  uint64_t hpaddr;
  uint8_t level;
  uint64_t pg_base = hgatp->ppn << 12;
  r_s2xlate r_s2;
  if (hgatp->mode == 0) {
    r_s2.pte.ppn = gpaddr >> 12;
    r_s2.level = 0;
    return r_s2;
  }
  int max_level = hgatp->mode == 8 ? 2 : 3;
  for (level = max_level; level >= 0; level--) {
    hpaddr = pg_base + GVPNi(gpaddr, level, max_level) * sizeof(uint64_t);
    read_globalmem(hpaddr, &pte.val, 8);
    pg_base = pte.ppn << 12;
    if (!pte.v || pte.r || pte.x || pte.w || level == 0) {
      break;
    }
  }
  r_s2.pte = pte;
  r_s2.level = level;
  return r_s2;
}

#if NUM_CORES > 1 && defined(CONFIG_DIFFTEST_TLBEVENT) && !defined(CONFIG_DIFFTEST_SQUASH)
namespace {

using PteRecords = std::vector<std::pair<uint64_t, uint64_t>>;
constexpr uint64_t kComparableLeafPermMask = 0x1f; // V/R/W/X/U; G is inherited, A/D are hardware state.

// Resolve an actual 4 KiB PPN, including the offset within a superpage.
// Probe without A/D writes; compare stable leaf permissions observed by the DUT.
template <typename ReadPte>
bool walk_translation(uint64_t root, uint64_t vaddr, bool stage2, uint64_t hgatp,
                      ReadPte &read_pte, PteRecords *records, const DifftestTlbEvent *expected,
                      uint64_t &paddr) {
  const unsigned mode = root >> 60;
  if (mode == 0) {
    paddr = vaddr;
    return true;
  }
  if (mode != 8 && mode != 9) {
    return false;
  }
  const int top = mode == 8 ? 2 : 3;
  uint64_t base = (root & ((1ULL << 44) - 1)) << 12;
  for (int level = top; level >= 0; level--) {
    const uint64_t index_mask = stage2 && level == top ? 0x7ff : 0x1ff;
    uint64_t address = base + ((vaddr >> VPNiSHFT(level)) & index_mask) * 8;
    if (hgatp && !walk_translation(hgatp, address, true, 0, read_pte, records, nullptr, address)) {
      return false;
    }
    PTE pte = {};
    if (!read_pte(address, pte.val)) {
      return false;
    }
    if (records) {
      records->emplace_back(address, pte.val);
    }
    if (!pte.v || (!pte.r && pte.w) || pte.rsvd || pte.pbmt == 3) {
      return false;
    }
    base = pte.ppn << 12;
    if (pte.r || pte.x) {
      // G may be inherited from a non-leaf PTE and A/D are updated by hardware.
      if (expected && (((pte.val ^ (stage2 ? expected->s2Perm : expected->s1Perm)) & kComparableLeafPermMask) ||
                       pte.pbmt != (stage2 ? expected->s2Pbmt : expected->s1Pbmt))) {
        return false;
      }
      uint64_t mask = (1ULL << VPNiSHFT(level)) - 1;
      if (pte.n) {
        if (level != 0 || (pte.ppn & 0xf) != 8) {
          return false;
        }
        mask = (1ULL << NAPOTSHFT) - 1;
      } else if (base & (mask & ~PAGE_MASK)) {
        return false;
      }
      paddr = (base & ~mask) | (vaddr & mask);
      return !hgatp || walk_translation(hgatp, paddr, true, 0, read_pte, records, expected, paddr);
    }
    if (pte.n || pte.pbmt || pte.u || pte.a || pte.d) {
      return false;
    }
  }
  return false;
}

template <typename ReadPte>
bool translation_matches(const DifftestTlbEvent &event, ReadPte &read_pte, PteRecords *records = nullptr) {
  uint64_t paddr = 0;
  const bool stage2 = event.s2xlate == onlyStage2;
  const uint64_t root = stage2 ? event.hgatp : event.s2xlate ? event.vsatp : event.satp;
  const uint64_t hgatp = event.s2xlate == allStage ? event.hgatp : 0;
  return walk_translation(root, event.vpn << 12, stage2, hgatp, read_pte, records, &event, paddr) &&
         (paddr >> 12) == event.ppn;
}

void record_translation(std::vector<DifftestTlbEvent> &records, const DifftestTlbEvent &event) {
  for (auto &record : records) {
    if (record.isFetch == event.isFetch && record.vpn == event.vpn && record.satp == event.satp &&
        record.vsatp == event.vsatp && record.hgatp == event.hgatp && record.s2xlate == event.s2xlate) {
      record = event;
      return;
    }
  }
  records.push_back(event);
}

} // namespace

void Difftest::tlb_event_record() {
  // Same-cycle order: new FTQ -> fetch response -> ROB allocation -> data response.
  // No page-table reads or REF mutations happen on the speculative path.
  for (int phase = 0; phase < 4; phase++) {
    for (int i = 0; i < CONFIG_DIFF_TLB_WIDTH; i++) {
      auto &event = dut->tlb[i];
      if (!event.valid || phase != (event.isFetch ? 0 : 2) + !event.clear) {
        continue;
      }
      event.valid = 0;
      assert(event.id < (1 << 10) && event.ftqIdx < (1 << 10));
      if (event.isFetch) {
        if (event.clear) {
          fetch_translations[event.id].clear();
        } else {
          record_translation(fetch_translations[event.id], event);
        }
      } else if (event.clear) {
        pending_translations[event.id] = fetch_translations[event.ftqIdx];
      } else {
        record_translation(pending_translations[event.id], event);
      }
    }
  }
}

bool Difftest::check_translation(uint64_t vaddr, bool is_fetch) {
  auto read_ref = [this](uint64_t address, uint64_t &value) {
    return proxy->read_pte(address, &value);
  };
  auto read_global = [](uint64_t address, uint64_t &value) {
    if (!in_pmem(address) || !in_pmem(address + 7)) {
      return false;
    }
    read_globalmem(address, &value, 8);
    return true;
  };
  for (const auto &event : active_translations) {
    const bool stage2 = event.s2xlate == onlyStage2;
    const unsigned mode = (stage2 ? event.hgatp : event.s2xlate ? event.vsatp : event.satp) >> 60;
    const uint64_t vpn_mask = (1ULL << ((mode == 8 ? 27 : 36) + (stage2 ? 2 : 0))) - 1;
    if (event.isFetch != is_fetch || (event.vpn & vpn_mask) != ((vaddr >> 12) & vpn_mask)) {
      continue;
    }
    if (translation_matches(event, read_ref)) {
      return true;
    }
    // Only pages actually used while REF executes this committed group are checked.
    // Unused fetch lines, masked elements and FOF tails never cause a correction.
    PteRecords records;
    if (!translation_matches(event, read_global, &records)) {
      Info("Core %d committed %s translation mismatch: pc=%016lx vaddr=%lx DUT ppn=%lx "
           "satp=%lx vsatp=%lx hgatp=%lx s2xlate=%u; neither Spike nor GlobalMem matches\n",
           id, is_fetch ? "fetch" : "data", tlb_commit_pc, vaddr, event.ppn,
           event.satp, event.vsatp, event.hgatp, event.s2xlate);
      tlb_mismatch = true;
      return false;
    }
    PteRecords updates;
    for (auto &record : records) {
      uint64_t value = 0;
      if (!read_ref(record.first, value)) {
        Info("Core %d cannot access Spike PTE at %lx (pc=%016lx)\n", id, record.first, tlb_commit_pc);
        tlb_mismatch = true;
        return false;
      }
      if (value != record.second) {
        updates.push_back(record);
      }
    }
    // The entire selected path has passed before any PTE is written.
    for (const auto &record : updates) {
      if (!proxy->write_pte(record.first, record.second)) {
        Info("Core %d failed to update Spike PTE at %lx (pc=%016lx)\n", id, record.first, tlb_commit_pc);
        tlb_mismatch = true;
        return false;
      }
    }
    if (!updates.empty()) {
      proxy->flush_tlb();
    }
    return true;
  }
  return true;
}
#endif

int Difftest::do_l1tlb_check() {
#ifdef CONFIG_DIFFTEST_L1TLBEVENT
  for (int i = 0; i < CONFIG_DIFF_L1TLB_WIDTH; i++) {
    if (!dut->l1tlb[i].valid) {
      continue;
    }
    dut->l1tlb[i].valid = 0;
    PTE pte;
    uint64_t paddr;
    uint8_t difftest_level;
    r_s2xlate r_s2;
    bool isNapot = false;

    Satp *satp = (Satp *)&dut->l1tlb[i].satp;
    Satp *vsatp = (Satp *)&dut->l1tlb[i].vsatp;
    Hgatp *hgatp = (Hgatp *)&dut->l1tlb[i].hgatp;
    uint8_t hasS2xlate = dut->l1tlb[i].s2xlate != noS2xlate;
    uint8_t onlyS2 = dut->l1tlb[i].s2xlate == onlyStage2;
    uint8_t hasAllStage = dut->l1tlb[i].s2xlate == allStage;
    uint64_t pg_base = (hasS2xlate ? vsatp->ppn : satp->ppn) << 12;
    int mode = hasS2xlate ? vsatp->mode : satp->mode;
    int max_level = mode == 8 ? 2 : 3;
    if (onlyS2) {
      r_s2 = do_s2xlate(hgatp, dut->l1tlb[i].vpn << 12);
      pte = r_s2.pte;
      difftest_level = r_s2.level;
    } else {
      for (difftest_level = max_level; difftest_level >= 0; difftest_level--) {
        paddr = pg_base + VPNi(dut->l1tlb[i].vpn, difftest_level) * sizeof(uint64_t);
        if (hasAllStage) {
          r_s2 = do_s2xlate(hgatp, paddr);
          uint64_t pg_mask = ((1ull << VPNiSHFT(r_s2.level)) - 1);
          if (r_s2.level == 0 && r_s2.pte.n) {
            pg_mask = ((1ull << NAPOTSHFT) - 1);
          }
          pg_base = (r_s2.pte.ppn << 12 & ~pg_mask) | (paddr & pg_mask & ~PAGE_MASK);
          paddr = pg_base | (paddr & PAGE_MASK);
        }
        read_globalmem(paddr, &pte.val, 8);
        pg_base = pte.ppn << 12;
        if (!pte.v || pte.r || pte.x || pte.w || difftest_level == 0) {
          break;
        }
      }
      if (difftest_level > 0 && pte.v) {
        uint64_t pg_mask = ((1ull << VPNiSHFT(difftest_level)) - 1);
        pg_base = (pte.ppn << 12 & ~pg_mask) | (dut->l1tlb[i].vpn << 12 & pg_mask & ~PAGE_MASK);
      } else if (difftest_level == 0 && pte.n) {
        isNapot = true;
        uint64_t pg_mask = ((1ull << NAPOTSHFT) - 1);
        pg_base = (pte.ppn << 12 & ~pg_mask) | (dut->l1tlb[i].vpn << 12 & pg_mask & ~PAGE_MASK);
      }
      if (hasAllStage && pte.v) {
        r_s2 = do_s2xlate(hgatp, pg_base);
        pte = r_s2.pte;
        difftest_level = r_s2.level;
        if (difftest_level == 0 && pte.n) {
          isNapot = true;
        }
      }
    }
    if (isNapot) {
      dut->l1tlb[i].ppn = dut->l1tlb[i].ppn >> 4 << 4;
      pte.difftest_ppn = pte.difftest_ppn >> 4 << 4;
    } else {
      dut->l1tlb[i].ppn = dut->l1tlb[i].ppn >> difftest_level * 9 << difftest_level * 9;
    }
    if (pte.difftest_ppn != dut->l1tlb[i].ppn) {
      Info("Warning: l1tlb resp test of core %d index %d failed! vpn = %lx\n", id, i, dut->l1tlb[i].vpn);
      Info("  REF commits pte.val: 0x%lx, dut s2xlate: %d\n", pte.val, dut->l1tlb[i].s2xlate);
      Info("  REF commits ppn 0x%lx, DUT commits ppn 0x%lx\n", pte.difftest_ppn, dut->l1tlb[i].ppn);
      Info("  REF commits perm 0x%02x, level %d, pf %d\n", pte.difftest_perm, difftest_level, !pte.difftest_v);
      return 0;
    }
  }
#endif // CONFIG_DIFFTEST_L1TLBEVENT
  return 0;
}

int Difftest::do_l2tlb_check() {
#ifdef CONFIG_DIFFTEST_L2TLBEVENT
  for (int i = 0; i < CONFIG_DIFF_L2TLB_WIDTH; i++) {
    if (!dut->l2tlb[i].valid) {
      continue;
    }
    dut->l2tlb[i].valid = 0;
    Satp *satp = (Satp *)&dut->l2tlb[i].satp;
    Satp *vsatp = (Satp *)&dut->l2tlb[i].vsatp;
    Hgatp *hgatp = (Hgatp *)&dut->l2tlb[i].hgatp;
    PTE pte;
    r_s2xlate r_s2;
    r_s2xlate check_s2;
    uint64_t paddr;
    uint8_t difftest_level;
    for (int j = 0; j < 8; j++) {
      if (dut->l2tlb[i].valididx[j]) {
        uint8_t hasS2xlate = dut->l2tlb[i].s2xlate != noS2xlate;
        uint8_t onlyS2 = dut->l2tlb[i].s2xlate == onlyStage2;
        uint64_t pg_base = (hasS2xlate ? vsatp->ppn : satp->ppn) << 12;
        int mode = hasS2xlate ? vsatp->mode : satp->mode;
        int max_level = mode == 8 ? 2 : 3;
        if (onlyS2) {
          r_s2 = do_s2xlate(hgatp, dut->l2tlb[i].vpn << 12);
          uint64_t pg_mask = ((1ull << VPNiSHFT(r_s2.level)) - 1);
          uint64_t s2_pg_base = r_s2.pte.ppn << 12;
          pg_base = (s2_pg_base & ~pg_mask) | (paddr & pg_mask & ~PAGE_MASK);
          paddr = pg_base | (paddr & PAGE_MASK);
        }
        for (difftest_level = max_level; difftest_level >= 0; difftest_level--) {
          paddr = pg_base + VPNi(dut->l2tlb[i].vpn + j, difftest_level) * sizeof(uint64_t);
          if (hasS2xlate) {
            r_s2 = do_s2xlate(hgatp, paddr);
            uint64_t pg_mask = ((1ull << VPNiSHFT(r_s2.level)) - 1);
            pg_base = (r_s2.pte.ppn << 12 & ~pg_mask) | (paddr & pg_mask & ~PAGE_MASK);
            paddr = pg_base | (paddr & PAGE_MASK);
          }
          read_globalmem(paddr, &pte.val, 8);
          if (!pte.v || pte.r || pte.x || pte.w || difftest_level == 0) {
            break;
          }
          pg_base = pte.ppn << 12;
        }

        if (hasS2xlate) {
          r_s2 = do_s2xlate(hgatp, pg_base);
          if (dut->l2tlb[i].pteidx[j])
            check_s2 = r_s2;
        }
        bool difftest_gpf = !r_s2.pte.v || (!r_s2.pte.r && r_s2.pte.w);
        bool difftest_pf = !pte.v || (!pte.r && pte.w);
        bool s1_check_fail = pte.difftest_ppn != dut->l2tlb[i].ppn[j] || pte.difftest_perm != dut->l2tlb[i].perm ||
                             pte.difftest_pbmt != dut->l2tlb[i].pbmt || difftest_level != dut->l2tlb[i].level ||
                             difftest_pf != dut->l2tlb[i].pf;
        bool s2_check_fail = hasS2xlate ? r_s2.pte.difftest_ppn != dut->l2tlb[i].s2ppn ||
                                              r_s2.pte.difftest_perm != dut->l2tlb[i].g_perm ||
                                              r_s2.pte.difftest_pbmt != dut->l2tlb[i].g_pbmt ||
                                              r_s2.level != dut->l2tlb[i].g_level || difftest_gpf != dut->l2tlb[i].gpf
                                        : false;
        if (s1_check_fail || s2_check_fail) {
          Info("Warning: L2TLB resp test of core %d index %d sector %d failed! vpn = %lx\n", id, i, j,
               dut->l2tlb[i].vpn + j);
          Info("  REF commits ppn 0x%lx, perm 0x%02x, level %d, pf %d\n", pte.difftest_ppn, pte.difftest_perm,
               difftest_level, difftest_pf);
          if (hasS2xlate)
            Info("      s2_ppn 0x%lx, g_perm 0x%02x, g_level %d, gpf %d\n", r_s2.pte.difftest_ppn,
                 r_s2.pte.difftest_perm, r_s2.level, difftest_gpf);
          Info("  DUT commits ppn 0x%lx, perm 0x%02x, level %d, pf %d\n", dut->l2tlb[i].ppn[j], dut->l2tlb[i].perm,
               dut->l2tlb[i].level, dut->l2tlb[i].pf);
          if (hasS2xlate)
            Info("      s2_ppn 0x%lx, g_perm 0x%02x, g_level %d, gpf %d\n", dut->l2tlb[i].s2ppn, dut->l2tlb[i].g_perm,
                 dut->l2tlb[i].g_level, dut->l2tlb[i].gpf);
          return 1;
        }
      }
    }
  }
#endif // CONFIG_DIFFTEST_L1TLBEVENT
  return 0;
}

inline int handle_atomic(int coreid, uint64_t atomicAddr, uint64_t atomicData, uint64_t atomicMask, uint8_t atomicFuop,
                         uint64_t atomicOut) {
  // We need to do atmoic operations here so as to update GlobalMem
  if (!(atomicMask == 0xf || atomicMask == 0xf0 || atomicMask == 0xff)) {
    Info("Unrecognized mask: %lx\n", atomicMask);
    return 1;
  }

  if (atomicMask == 0xff) {
    uint64_t rs = atomicData; // rs2
    uint64_t t = atomicOut;   // original value
    uint64_t ret;
    uint64_t mem;
    read_globalmem(atomicAddr, &mem, 8);
    if (mem != t && atomicFuop != 007 && atomicFuop != 003) { // ignore sc_d & lr_d
      Info("Core %d atomic instr mismatch GlobalMem, mem: 0x%lx, t: 0x%lx, op: 0x%x, addr: 0x%lx\n", coreid, mem, t,
           atomicFuop, atomicAddr);
      return 1;
    }
    switch (atomicFuop) {
      case 002:
      case 003: ret = t; break;
      // if sc fails(aka atomicOut == 1), no update to globalmem
      case 006:
      case 007:
        if (t == 1)
          return 0;
        ret = rs;
        break;
      case 012:
      case 013: ret = rs; break;
      case 016:
      case 017: ret = t + rs; break;
      case 022:
      case 023: ret = (t ^ rs); break;
      case 026:
      case 027: ret = t & rs; break;
      case 032:
      case 033: ret = t | rs; break;
      case 036:
      case 037: ret = ((int64_t)t < (int64_t)rs) ? t : rs; break;
      case 042:
      case 043: ret = ((int64_t)t > (int64_t)rs) ? t : rs; break;
      case 046:
      case 047: ret = (t < rs) ? t : rs; break;
      case 052:
      case 053: ret = (t > rs) ? t : rs; break;
      default: printf("Unknown atomic fuOpType: 0x%x\n", atomicFuop);
    }
    update_globalmem(atomicAddr, &ret, atomicMask, 8);
  }

  if (atomicMask == 0xf || atomicMask == 0xf0) {
    uint32_t rs = (uint32_t)atomicData; // rs2
    uint32_t t = (uint32_t)atomicOut;   // original value
    uint32_t ret;
    uint32_t mem;
    uint64_t mem_raw;
    uint64_t ret_sel;
    atomicAddr = (atomicAddr & 0xfffffffffffffff8);
    read_globalmem(atomicAddr, &mem_raw, 8);

    if (atomicMask == 0xf)
      mem = (uint32_t)mem_raw;
    else
      mem = (uint32_t)(mem_raw >> 32);

    if (mem != t && atomicFuop != 006 && atomicFuop != 002) { // ignore sc_w & lr_w
      Info("Core %d atomic instr mismatch GlobalMem, rawmem: 0x%lx mem: 0x%x, t: 0x%x, op: 0x%x, addr: 0x%lx\n", coreid,
           mem_raw, mem, t, atomicFuop, atomicAddr);
      return 1;
    }
    switch (atomicFuop) {
      case 002:
      case 003: ret = t; break;
      // if sc fails(aka atomicOut == 1), no update to globalmem
      case 006:
      case 007:
        if (t == 1)
          return 0;
        ret = rs;
        break;
      case 012:
      case 013: ret = rs; break;
      case 016:
      case 017: ret = t + rs; break;
      case 022:
      case 023: ret = (t ^ rs); break;
      case 026:
      case 027: ret = t & rs; break;
      case 032:
      case 033: ret = t | rs; break;
      case 036:
      case 037: ret = ((int32_t)t < (int32_t)rs) ? t : rs; break;
      case 042:
      case 043: ret = ((int32_t)t > (int32_t)rs) ? t : rs; break;
      case 046:
      case 047: ret = (t < rs) ? t : rs; break;
      case 052:
      case 053: ret = (t > rs) ? t : rs; break;
      default: printf("Unknown atomic fuOpType: 0x%x\n", atomicFuop);
    }
    ret_sel = ret;
    if (atomicMask == 0xf0)
      ret_sel = (ret_sel << 32);
    update_globalmem(atomicAddr, &ret_sel, atomicMask, 8);
  }
  return 0;
}

void dumpGlobalMem(const char *banner, uint64_t addr, uint64_t time) {
#ifdef DEBUG_REFILL
  char buf[512];
  if (addr == 0) {
    return;
  }
  Info("============== %s =============== time = %ld\ndata: ", banner, time);
  for (int i = 0; i < 8; i++) {
    read_globalmem(addr + i * 8, &buf, 8);
    Info("%016lx", *((uint64_t *)buf));
  }
  Info("\n");
#endif
}

#ifdef DEBUG_GLOBALMEM
int Difftest::do_global_memory_update() {
#if NUM_CORES > 1
#ifdef CONFIG_DIFFTEST_SBUFFEREVENT
  for (int port = 0; port < CONFIG_DIFF_SBUFFER_WIDTH; ++port) dut->sbuffer[port].valid = 0;
#endif
  return 0;
#else
  // Single-core debug memory follows completed writes.
  uint64_t cycleCnt = get_trap_event()->cycleCnt;
  static bool initDump = true;
  if (cycleCnt >= 100 && initDump) {
    initDump = false;
    dumpGlobalMem("Init", track_instr, cycleCnt);
  }

#ifdef CONFIG_DIFFTEST_UNCACHEMMSTOREEVENT
  for (int i = 0; i < CONFIG_DIFF_UNCACHE_MM_STORE_WIDTH; i++) {
    if (dut->uncache_mm_store[i].valid) {
      dut->uncache_mm_store[i].valid = 0;
      update_globalmem(dut->uncache_mm_store[i].addr, dut->uncache_mm_store[i].data,
                       dut->uncache_mm_store[i].mask, 8);
      if (dut->uncache_mm_store[i].addr == track_instr) {
        dumpGlobalMem("Uncache MM Store", track_instr, cycleCnt);
      }
    }
  }
#endif // CONFIG_DIFFTEST_UNCACHEMMSTOREEVENT
#ifdef CONFIG_DIFFTEST_SBUFFEREVENT
  for (int i = 0; i < CONFIG_DIFF_SBUFFER_WIDTH; i++) {
    if (dut->sbuffer[i].valid) {
      dut->sbuffer[i].valid = 0;
      update_globalmem(dut->sbuffer[i].addr, dut->sbuffer[i].data, dut->sbuffer[i].mask, 64);
      if (dut->sbuffer[i].addr == track_instr) {
        dumpGlobalMem("Store", track_instr, cycleCnt);
      }
    }
  }
#endif // CONFIG_DIFFTEST_SBUFFEREVENT

#ifdef CONFIG_DIFFTEST_ATOMICEVENT
  if (dut->atomic.valid) {
    dut->atomic.valid = 0;
    int ret =
        handle_atomic(id, dut->atomic.addr, dut->atomic.data, dut->atomic.mask, dut->atomic.fuop, dut->atomic.out);
    if (dut->atomic.addr == track_instr) {
      dumpGlobalMem("Atmoic", track_instr, cycleCnt);
    }
    if (ret)
      return ret;
  }
#endif // CONFIG_DIFFTEST_ATOMICEVENT

  return 0;
#endif // NUM_CORES > 1
}
#endif

#ifdef CONFIG_DIFFTEST_STOREEVENT
void Difftest::store_event_record() {
  for (int i = 0; i < CONFIG_DIFF_STORE_WIDTH; i++) {
    if (dut->store[i].valid) {
      store_event_queue.push(dut->store[i]);
      dut->store[i].valid = 0;
    }
  }
}
#endif

#ifdef CONFIG_DIFFTEST_SQUASH
#ifdef CONFIG_DIFFTEST_LOADEVENT
void Difftest::load_event_record() {
  for (int i = 0; i < CONFIG_DIFF_LOAD_WIDTH; i++) {
    if (dut->load[i].valid) {
      load_event_queue.push(dut->load[i]);
      dut->load[i].valid = 0;
    }
  }
}
#endif // CONFIG_DIFFTEST_LOADEVENT
#endif // CONFIG_DIFFTEST_SQUASH

#ifdef CONFIG_DIFFTEST_CMOINVALEVENT
int Difftest::cmo_inval_event_record() {
  if (dut->cmo_inval.valid) {
#if NUM_CORES > 1
    Info("RVWMO UNSUPPORTED: CMO invalidation on core %d\n", id);
    return 1;
#else
    dut->cmo_inval.valid = 0;
#endif
  }
  return 0;
}
#endif // CONFIG_DIFFTEST_CMOINVALEVENT

int Difftest::check_timeout() {
  uint64_t cycleCnt = get_trap_event()->cycleCnt;
  // check whether there're any commits since the simulation starts
  if (!has_commit && cycleCnt > last_commit + first_commit_limit) {
    Info("The first instruction of core %d at 0x%lx does not commit after %lu cycles.\n", id, FIRST_INST_ADDRESS,
         first_commit_limit);
    display();
    return 1;
  }

  // NOTE: the WFI instruction may cause the CPU to halt for more than `stuck_limit` cycles.
  // We update the `last_commit` if the CPU has a WFI instruction
  // to allow the CPU to run at most `stuck_limit` cycles after WFI resumes execution.
  if (has_wfi()) {
    update_last_commit();
  }

  // check whether there're any commits in the last `stuck_limit` cycles
  if (has_commit && cycleCnt > last_commit + stuck_commit_limit) {
    Info(
        "No instruction of core %d commits for %lu cycles, maybe get stuck\n"
        "(please also check whether a fence.i instruction requires more than %lu cycles to flush the icache)\n",
        id, stuck_commit_limit, stuck_commit_limit);
    Info("Let REF run one more instruction.\n");
    proxy->ref_exec(1);
    display();
    return 1;
  }

  return 0;
}

int Difftest::update_delayed_writeback() {
#define CHECK_DELAYED_WB(wb, delayed, n, regs_name)                                                \
  do {                                                                                             \
    for (int i = 0; i < n; i++) {                                                                  \
      auto delay = dut->wb + i;                                                                    \
      if (delay->valid) {                                                                          \
        delay->valid = false;                                                                      \
        if (!delayed[delay->address]) {                                                            \
          display();                                                                               \
          Info("Delayed writeback at %s has already been committed\n", regs_name[delay->address]); \
          raise_trap(STATE_ABORT);                                                                 \
          return 1;                                                                                \
        }                                                                                          \
        if (delay->nack) {                                                                         \
          if (delayed[delay->address] > delay_wb_limit) {                                          \
            delayed[delay->address] -= 1;                                                          \
          }                                                                                        \
        } else {                                                                                   \
          delayed[delay->address] = 0;                                                             \
        }                                                                                          \
        progress = true;                                                                           \
      }                                                                                            \
    }                                                                                              \
  } while (0);

#ifdef CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
  CHECK_DELAYED_WB(regs_int_delayed, delayed_int, CONFIG_DIFF_REGS_INT_DELAYED_WIDTH, regs_name_int)
#endif // CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
#ifdef CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
  CHECK_DELAYED_WB(regs_fp_delayed, delayed_fp, CONFIG_DIFF_REGS_FP_DELAYED_WIDTH, regs_name_fp)
#endif // CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
  return 0;
}

int Difftest::apply_delayed_writeback() {
#define APPLY_DELAYED_WB(delayed, regs, regs_name)                           \
  do {                                                                       \
    static const int m = delay_wb_limit;                                     \
    for (int i = 0; i < 32; i++) {                                           \
      if (delayed[i]) {                                                      \
        if (delayed[i] > m) {                                                \
          display();                                                         \
          Info("%s is delayed for more than %d cycles.\n", regs_name[i], m); \
          raise_trap(STATE_ABORT);                                           \
          return 1;                                                          \
        }                                                                    \
        delayed[i]++;                                                        \
        dut->regs.value[i] = proxy->regs.value[i];                           \
      }                                                                      \
    }                                                                        \
  } while (0);

#ifdef CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
  APPLY_DELAYED_WB(delayed_int, regs_int, regs_name_int)
#endif // CONFIG_DIFFTEST_ARCHINTDELAYEDUPDATE
#ifdef CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
  APPLY_DELAYED_WB(delayed_fp, regs_fp, regs_name_fp)
#endif // CONFIG_DIFFTEST_ARCHFPDELAYEDUPDATE
  return 0;
}

void Difftest::raise_trap(int trapCode) {
  dut->trap.hasTrap = 1;
  dut->trap.code = trapCode;
}

#ifdef CONFIG_DIFFTEST_NONREGINTERRUPTPENDINGEVENT
void Difftest::do_non_reg_interrupt_pending() {
  if (dut->non_reg_interrupt_pending.valid) {
    const uint64_t raw_pending = dut->non_reg_interrupt_pending.rawPending & kNonRegInterruptSnapshotMask;
    const uint64_t raw_mask = dut->non_reg_interrupt_pending.rawPendingMask & kNonRegInterruptSnapshotMask;
    const uint64_t ownership_added = raw_mask & ~latest_non_reg_interrupt_pending_mask;
    const uint64_t ownership_removed = latest_non_reg_interrupt_pending_mask & ~raw_mask;
    const uint64_t ownership_changed = ownership_added | ownership_removed;
    const uint64_t source_update_mask = (
        (dut->non_reg_interrupt_pending.platformIRPMeipValid ? kMei : 0) |
        (dut->non_reg_interrupt_pending.platformIRPMtipValid ? kMti : 0) |
        (dut->non_reg_interrupt_pending.platformIRPMsipValid ? kMsi : 0) |
        (dut->non_reg_interrupt_pending.platformIRPSeipValid ? kSei : 0) |
        (dut->non_reg_interrupt_pending.platformIRPStipValid ? kSti : 0) |
        (dut->non_reg_interrupt_pending.platformIRPVseipValid ? kVsei : 0) |
        (dut->non_reg_interrupt_pending.platformIRPVstipValid ? kVsti : 0) |
        (dut->non_reg_interrupt_pending.localCounterOverflowInterruptReqValid ? kLcofi : 0)) & raw_mask;

    const uint64_t cache_update_mask = source_update_mask | ownership_changed;
    latest_non_reg_interrupt_pending =
        (latest_non_reg_interrupt_pending & ~cache_update_mask) | (raw_pending & cache_update_mask);
    latest_non_reg_interrupt_pending_mask = raw_mask;
    latest_software_seip = dut->non_reg_interrupt_pending.softwareSeip;

    auto ip = make_pending_update(ownership_added | source_update_mask, raw_pending);
    if (source_update_mask & kLcofi) {
      ++lcofi_update_epoch;
    }
    ip.fromAIAMeipValid = dut->non_reg_interrupt_pending.fromAIAMeipValid;
    ip.fromAIAMeip = dut->non_reg_interrupt_pending.fromAIAMeip;
    ip.fromAIASeipValid = dut->non_reg_interrupt_pending.fromAIASeipValid;
    ip.fromAIASeip = dut->non_reg_interrupt_pending.fromAIASeip;
    ip.stimeValid = dut->non_reg_interrupt_pending.stimeValid;
    ip.stime = dut->non_reg_interrupt_pending.stime;

    if (dut->non_reg_interrupt_pending.csrReadSnapshotFlush) {
      csr_read_snapshot.valid = false;
    }
    if (dut->non_reg_interrupt_pending.csrReadSnapshotValid &&
        !dut->non_reg_interrupt_pending.csrReadSnapshotFlush) {
      if (csr_read_snapshot.valid) {
        Info("Core %d overlapping CSR pending snapshots\n", this->id);
        csr_snapshot_mismatch = true;
      } else {
        csr_read_snapshot.valid = true;
        csr_read_snapshot.pending = raw_pending;
        csr_read_snapshot.mask = raw_mask;
        csr_read_snapshot.lcofi_epoch = lcofi_update_epoch;
      }
    }

    proxy->non_reg_interrupt_pending(ip);
    if (ownership_removed) {
      // time->sync() is processed after STIP inside the first update. Apply
      // released bits last so an STCE falling edge exposes retained software state.
      auto released = make_pending_update(ownership_removed, raw_pending);
      proxy->non_reg_interrupt_pending(released);
    }
    dut->non_reg_interrupt_pending.valid = 0;
  }
}
#endif

#ifdef CONFIG_DIFFTEST_MHPMEVENTOVERFLOWEVENT
void Difftest::do_mhpmevent_overflow() {
  if (dut->mhpmevent_overflow.valid) {
    proxy->mhpmevent_overflow(dut->mhpmevent_overflow.mhpmeventOverflow);
    dut->mhpmevent_overflow.valid = 0;
  }
}
#endif

#ifdef CONFIG_DIFFTEST_CRITICALERROREVENT
void Difftest::do_raise_critical_error() {
  if (dut->critical_error.valid) {
    bool ref_critical_error = proxy->raise_critical_error();
    if (ref_critical_error == dut->critical_error.criticalError) {
      Info("Core %d dump: " ANSI_COLOR_RED
           "HIT CRITICAL ERROR: please check if software cause a double trap. \n" ANSI_COLOR_RESET,
           this->id);
      raise_trap(STATE_GOODTRAP);
    } else {
      display();
      Info("Core %d dump: DUT critical_error diff REF \n", this->id);
      raise_trap(STATE_ABORT);
    }
  }
}
#endif

#ifdef CONFIG_DIFFTEST_SYNCAIAEVENT
void Difftest::do_sync_aia() {
  if (dut->sync_aia.valid) {
    struct FromAIA aia;
    aia.mtopei = dut->sync_aia.mtopei;
    aia.stopei = dut->sync_aia.stopei;
    aia.vstopei = dut->sync_aia.vstopei;
    aia.hgeip = dut->sync_aia.hgeip;
    proxy->sync_aia(aia);
    dut->sync_aia.valid = 0;
  }
}
#endif

#ifdef CONFIG_DIFFTEST_SYNCCUSTOMMFLUSHPWREVENT
void Difftest::do_sync_custom_mflushpwr() {
  if (dut->sync_custom_mflushpwr.valid) {
    proxy->sync_custom_mflushpwr(dut->sync_custom_mflushpwr.l2FlushDone);
    dut->sync_custom_mflushpwr.valid = 0;
  }
}
#endif

#ifdef CONFIG_DIFFTEST_VECFOFSYNCEVENT
void Difftest::do_vec_fof_sync() {
  for (int idx = 0; idx < CONFIG_DIFF_VEC_FOF_SYNC_WIDTH; idx++) {
    if (!dut->vec_fof_sync[idx].valid)
      continue;
    struct VecFofSyncInfo info;
    info.fofVl = dut->vec_fof_sync[idx].fofVl;
    info.fofEew = dut->vec_fof_sync[idx].fofEew;
    info.vdNum = dut->vec_fof_sync[idx].vdNum;
    info.vdRegNum = dut->vec_fof_sync[idx].vdRegNum;
    info.vdBase = dut->vec_fof_sync[idx].vdBase;
    memset(info.data, 0, sizeof(info.data));
#ifdef CONFIG_DIFFTEST_ARCHVECREGSTATE
    uint32_t totalRegs = info.vdNum * info.vdRegNum;
    for (uint32_t vd = 0; vd < totalRegs; vd++) {
      uint32_t regIdx = info.vdBase + vd;
      if (regIdx >= 32 || 2 * vd + 1 >= 16) break;
      info.data[2 * vd] = dut->regs_vec.value[regIdx * 2];
      info.data[2 * vd + 1] = dut->regs_vec.value[regIdx * 2 + 1];
    }
#endif
    proxy->vec_fof_sync(&info);
    dut->vec_fof_sync[idx].valid = 0;
  }
}
#endif

void Difftest::display() {
  Info("\n==============  In the last commit group  ==============\n");
  Info("the first commit instr pc of DUT is 0x%016lx\nthe first commit instr pc of REF is 0x%016lx\n",
       dut_commit_first_pc, ref_commit_first_pc);

  state->display(this->id);

  Info("\n==============  REF Regs  ==============\n");
  fflush(stdout);
  proxy->ref_reg_display();
  Info("privilegeMode: %lu\n", dut->csr.privilegeMode);
}

void CommitTrace::display(bool use_spike) {
  Info("%s pc %016lx inst %08x", get_type(), pc, inst);
  display_custom();
  if (use_spike) {
    Info(" %s", spike_dasm(inst));
  }
}

void CommitTrace::display_line(int index, bool use_spike, bool is_retire) {
  Info("[%02d] ", index);
  display(use_spike);
  Info("%s\n", is_retire ? " <--" : "");
}

void Difftest::display_stats() {
  auto trap = get_trap_event();
  uint64_t instrCnt = trap->instrCnt;
  uint64_t cycleCnt = trap->cycleCnt;
  double ipc = (double)instrCnt / cycleCnt;
  Info(ANSI_COLOR_MAGENTA "Core-%d instrCnt = %'" PRIu64 ", cycleCnt = %'" PRIu64 ", IPC = %lf\n" ANSI_COLOR_RESET,
       this->id, instrCnt, cycleCnt, ipc);
}

void DiffState::display(int coreid) {
  Info("\n============== Commit Group Trace (Core %d) ==============\n", coreid);
  int group_index = 0;
  while (!retire_group_queue.empty()) {
    auto retire_group = retire_group_queue.front();
    auto pc = retire_group.first;
    auto cnt = retire_group.second;
    retire_group_queue.pop();
    Info("commit group [%02d]: pc %010lx cmtcnt %d%s\n", group_index, pc, cnt,
         retire_group_queue.empty() ? " <--" : "");
    group_index++;
  }

  Info("\n============== Commit Instr Trace ==============\n");
  int commit_index = 0;
  while (!commit_trace.empty()) {
    CommitTrace *trace = commit_trace.front();
    commit_trace.pop();
    trace->display_line(commit_index, use_spike, commit_trace.empty());
    commit_index++;
  }

  fflush(stdout);
}

DiffState::DiffState() : use_spike(spike_valid()) {}
