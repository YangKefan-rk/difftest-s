# BlackParrot native adapter

This directory converts BlackParrot's private source observations to the shared
C++ events in `rvwmo/event.h`. The shared `ObservationSession` owns memory-order
ranks, expected load bytes, independent REF store audits and final checking.
The adapter does not implement another Runtime, REF or event ABI.

## Components

- `adapter.h/.cpp` validates dynamic instruction identities, selected load
  attempts, delayed writebacks, single-writer publications and source prefixes.
  `ConvertedOutput` preserves DUT architectural snapshots separately from REF.
- `native_bridge.h/.cpp` receives the native `bp_difftest_s_*` DPI records,
  pairs physical facts, and either converts terminal captures or delivers
  source-closed prefixes during simulation. `NativeSink` supports
  capture consumers; it cannot provide a semantic Pass. `NativeVerifier` keeps
  semantic status separate from malformed transport.
- `session_adapter.h/.cpp` supports a borrowed `ObservationSession` and common
  capture validation. `host_session_adapter.h/.cpp` connects the native end facts
  to the public `HostSession`, which owns the fixed hart roster, reference pool,
  source drains and final checks. Install the native host before probe startup
  with `install_native_host_session(configuration, adapter)`. The adapter, public
  host and backing memory must outlive the run. For continuous execution use
  `install_native_online_session(configuration, adapter)` before probe startup.
  A final Pass requires native completion evidence and successful public host
  finalization.
- RTL probes live beside BlackParrot's existing nonsynth monitors. The opt-in
  native build entry is `Makefile.difftest-s` in the BlackParrot repository root.
  That repository's `docs/difftest-s.md` documents standalone dependencies,
  reference-library builds and the caller bootstrap contract.

## Supported native profile

Qualified publications and terminal completion use the fixed synchronous
`e_bp_multicore_4_cfg`: four harts, FSM coherence and writeback data caches.
Core and inverted cache edges retain their common even/odd half-cycle ticks.
Each cache has its own publication producer. Equal-tick cross-producer memory
observations remain unqualified; producer IDs, callback order, UID order and
conversion order never establish their GMO order. The public session can group
certified concurrent ordinary reads without inventing their relative order.
Ambiguous groups containing writes remain Incomplete.

Ordinary scalar loads retain the actual SRAM or forwarding sample tick. Raw
word-aligned facts keep byte masks and forwarding writer identities; public
memory operations use the true contiguous addressed span. A miss sample may
arrive after architectural retirement. Both source times are retained while
the public session waits for the selected sample. An unqualified sample and
retirement on the same source tick remain an explicit incomplete lifecycle.
A load mixing SRAM and forwarding bytes sampled at different ticks also
remains Incomplete until the public contract supports that source shape.

The fixed two-entry WBUF drains one logical store at a time. Its byte merge is
load bypass, with current input before el0 before el1; it is not multi-store
publication coalescing. For the final retired load attempt, the bridge audits
each declared forwarding writer against the captured store byte and rejects a
skipped younger active older store covering that lane. This check runs after
the raw interval closes, including delayed store-input callbacks. Cancelled
attempts remain provisional. These physical-source tags never supply REF
expected values or a cross-hart memory rank; inconsistent tags are Invalid,
while missing or ambiguous source evidence remains incomplete.

For ordinary cached scalar stores, the logical publication point is qualified
WBUF acceptance. The admission monitor checks the concrete UID/attempt,
address, enabled bytes, one-hot bank/target location, known matching tag and
previously observed M/E ownership. This is a per-store acceptance event, not
the earlier cache-line permission grant and not a claim that SRAM was written.

Hit stores register their provisional writer record and publish at acceptance;
their LocalMem byte overlay therefore has zero logical residency. If a store
retires first, its accepted miss request supplies address/data/mask for LocalMem
until fill replay reaches WBUF. Retirement always independently audits the
store against REF, including stores published before retirement. A private
kind-4 memory fact captures the accepted miss payload; kind 1 remains WBUF
acceptance, kind 2 physical drain and kind 3 a load sample.

Physical completion is still mandatory: every admitted store must drain once,
with identical bytes/mask and independently checked SRAM geometry. The monitor
continuously excludes ownership loss and coherence reads of buffered stores.
Those checks remain active after logical publication. The bridge conservatively
retains raw facts and holds source closure until retirement, physical drain and
both proof records are available; this delivery delay does not change the
original admission source position. Missing admission/drain or later source
failure cannot leave a final Pass.

## Reference and completion contract

The embedding initializes independent memory from its program image, creates
a public `HostSession` with one matching BlackParrot reference per hart.
The host owns `SpikeReferencePool` and its `ObservationSession`.
The private host adapter submits captured PC/raw/integer snapshots through
that same public session. Ordinary stores are audited against REF-derived address/data/mask.
The native build accepts an explicit embedding source and matching Spike
headers/library; no hidden factory guesses initial architectural state.

Terminal checking is opt-in. All four harts must actually retire WFI, stop
issuing with no pending pipeline/writeback work, and finish their checked
memory effects. The testbench then asserts a permanent simulation end boundary.
The probes explicitly squash retained younger identities, seal each hart once,
observe the final memory-source edge, and close every registered producer.
Source timestamps must cover the last core and memory evidence. A heartbeat,
software done flag, host MMIO finish or local idle alone does not close a prefix.

`NativeCompletionEvidence::memory_drained` means that the checked scalar memory
effects and their source observations are complete. It does not mean every
network FIFO is empty or every dirty line has reached DRAM. Residual coherence
acknowledgments and cache maintenance may remain after the included instruction
sources close. Full fabric quiescence and final DRAM-image checking require
additional observations.

A native `[BSG-PASS]` is separate from the checker verdict. Semantic builds
require an explicit final `[Difftest-S] Pass` and reject Violation, Invalid,
Unsupported, Incomplete, missing verdict and process failure. Final Pending is
Incomplete. Submission after closure/finalization rejects; a transport failure
invalidates any previously cached successful verdict.

The generic scalar session does not cover AMO/LRSC, FP/vector/split accesses,
cache-block/MMIO effects or trap/interrupt architecture. Those facts remain
explicit Unsupported/Incomplete. The scalar snapshot contract checks PC/raw/
GPR and memory; it does not assert full CSR equality. Hardware ISA features
are not disabled to conceal these limits.

## Native build and bounds

The BlackParrot root `Makefile.difftest-s` delegates to `bp_top/verilator`.
`DIFFTEST_S=0` is the default native baseline. `DIFFTEST_S=1` enables capture;
a run without an installed, finalized semantic verifier is rejected by the
native finish API. Capture alone cannot provide Pass.

`DIFFTEST_S_SEMANTIC=1` requires `CFG=e_bp_multicore_4_cfg`,
`DIFFTEST_S_BOOTSTRAP_SOURCE`, `DIFFTEST_S_SPIKE_HOME` and the matching
`DIFFTEST_S_SPIKE_LIBRARY`; it enables the audited coherence and terminal
protocols. Pass absolute paths for these inputs, `DIFFTEST_S_DIR` and
`SIM_PROG`, because the entry changes directory before invoking the native
Makefile. The Spike dependency must provide `difftest/ref_api.h`, the
BlackParrot profile ID 7 and the versioned external-memory, scalar-state and
retirement-observer APIs. A compatible Spike tree can build the library with
`CPU=BLACKPARROT MULTICORE_DIFF=1 EXTERNAL_MEMORY=1 PURE_API=1 DEBUG=` in a
fresh absolute `BUILD_DIR`; use the resulting `riscv64-spike-ref-api.so`.

The caller bootstrap is one C++ translation unit defining
`extern "C" int bp_difftest_s_session_start(const char *elf, uint32_t harts)`.
The testbench calls it before probe startup with the independent program path
and hart count. The caller supplies its ELF loader and initial architectural
state, constructs and validates a four-hart public `HostSession` and borrowed
`HostSessionAdapter`, then installs `install_native_online_session` for
`DIFFTEST_S_ONLINE=1` or `install_native_host_session` for terminal replay.
Return zero only after successful installation. The backing memory, host,
adapter and borrowed callback objects must survive until simulation finishes;
they cannot be startup-function stack objects. Test workloads, oracles, fault
fixtures and runners live outside production repositories.

Enabled builds default to direct compiler invocations. Use a fresh generated
model directory when changing probes, bootstrap dependencies or build options,
or when moving artifacts; an explicit
`OBJCACHE=ccache` opt-in needs an isolated, validated cache. The wrapper checks
native exit status and the BSG verdict in both capture and semantic modes.

`Configuration` bounds live instructions, outstanding stores and exact
publication deduplication history. History exhaustion returns Unsupported.
Callers retain inputs on Waiting and deliver queued prefixes with
`take_output()` before adding observations on that producer. The terminal
capture path has session bounds of 65,536 allocated instructions and 1,048,576
observations. The online path instead bounds unresolved work:
65,536 live native identities and 32,768 events in one ready source prefix.
Already consumed facts are released; publication transaction IDs use monotonic
producer frontiers instead of lifetime history. A genuinely unbounded unresolved
hardware request or an oversized live prefix remains an explicit failure.

## Online source progress

Build with `DIFFTEST_S_ONLINE=1` and an embedding that installs
`install_native_online_session`; this requires semantic checking. The native
wrapper uses a distinct online build tag. Its post-negedge phase barrier calls
`bp_difftest_s_advance(delivered_through_tick)` after core/cache/coherence monitor
callbacks and NBA updates. This is a delivery notification, not a memory rank
or an assertion that no delayed result exists.

The bridge keeps unresolved load, identified writeback and store/proof pairs
behind their active allocation frontier. Retirements reach the same public
HostSession in each hart's final retirement order. The bridge retains an exact
unaccepted batch for retry; an accepted Pending batch is never resubmitted.
After source closure and public acceptance it reclaims native identities, raw
facts and indexes. A cancelled attempt may retain its stable retry UID without
pinning other harts indefinitely; a retry or squash cannot use a source time
inside an already closed prefix. WFI itself never silently squashes younger
identities or substitutes for the final stopped/drained-source protocol.

## Stable-byte load-order windows

`load_order.h` retains constant-size order summaries per hart. An ordinary SRAM
load that crosses an older W-to-R FENCE can receive a model-order witness only
when its complete raw sampling interval is closed and none of its enabled bytes
has any hart's logical store-input transition in that interval. Writer
identity transitions matter even when the data values are equal. Mixed
forwarding, and fully forwarded loads whose forwarding tick crosses the prior
store-publication boundary remain Incomplete/Unsupported because they do not
have a certified model-order point. Missing evidence, overlapping writes, or
an interval with no legal point also remains Incomplete/Unsupported. This
certificate covers the observed W-to-R scalar SRAM window; it does not claim
complete handling for every FENCE predecessor/successor combination.

The same interval rule also handles a same-hart WBUF acceptance tied with a
physical load sample. Current-input forwarding may include the accepted store
at the interval's first tick only when each overlapping byte has that exact
observed writer. All other overlapping writer transitions are rejected,
including same-value writes. The chosen point is strictly later, lies inside
the closed sampling interval and is still subject to the public PPO checks.
It is not a fabricated global store/load phase for simultaneous cross-hart
accesses. Physical drain is a completion obligation, not another logical write.

The raw `NativeMemoryFact` keeps its actual array/forwarding and callback times.
A derived `LOAD_ORDER_WINDOW` record separately identifies the original interval
and selected model point; that point is not a new observed hardware timestamp.
Terminal capture/replay does not generate interval certificates. Its raw
validation rejects an uncertified SRAM or forwarded W-to-R crossing as
Incomplete before public PPO checking, matching the online evidence boundary.

The public session still checks independent REF bytes, store audits and every
supported PPO condition at retirement. The private certificate never constructs
expected values from DUT actual data, and it does not change the public checker
or claim a complete coherence-protocol proof.
