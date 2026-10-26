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
  pairs physical facts, and converts complete captures. `NativeSink` supports
  capture consumers; it cannot provide a semantic Pass. `NativeVerifier` keeps
  semantic status separate from malformed transport.
- `session_adapter.h/.cpp` borrows a public session. Install it before the first
  probe initialization with `install_native_session(configuration, adapter)`.
  The adapter, session, reference pool and backing memory must outlive the run.
  A final Pass requires both native completion evidence and public finalization.
- RTL probes live beside BlackParrot's existing nonsynth monitors. The opt-in
  native build entry is `black-parrot-sim/Makefile.difftest-s`.

## Supported native profile

Qualified publications and terminal completion use the fixed synchronous
`e_bp_multicore_4_cfg`: four harts, FSM coherence and writeback data caches.
Core and inverted cache edges retain their common even/odd half-cycle ticks.
Each cache has its own publication producer. Equal-tick cross-producer memory
observations remain unqualified; producer IDs, callback order, UID order and
conversion order never establish their GMO order. The public session rejects
runs without the relative-order evidence it requires.

Ordinary scalar loads retain the actual SRAM or forwarding sample tick. Raw
word-aligned facts keep byte masks and forwarding writer identities; public
memory operations use the true contiguous addressed span. A miss sample may
arrive after architectural retirement. Both source times are retained while
the public session waits for the selected sample. An unqualified sample and
retirement on the same source tick remain an explicit incomplete lifecycle.
A load mixing SRAM and forwarding bytes sampled at different ticks also
remains Incomplete until the public contract supports that source shape.

Store publication requires the matching physical SRAM drain, logical final
UID/attempt, exact byte data/mask and the coherence monitor's five proof bits:
ordinary scalar access, known matching tag, observed M/E ownership, the actual
SRAM write, and continuous exclusion of conflicting coherence actions while
buffered. A naked buffer drain, permission ACK or cache request is insufficient.
Publication keeps its physical tick even when it precedes LocalStore retirement.
The public session waits for the later LocalStore and independent REF audit;
it does not retime publication or trust DUT bytes as expected data.

## Reference and completion contract

The embedding initializes independent memory from its program image, creates
one matching BlackParrot reference per hart through the public
`SpikeReferencePool`, and supplies its callback to `ObservationSession`.
`SessionAdapter` compares the captured PC/raw/integer result through that
session. Ordinary stores are audited against REF-derived address/data/mask.
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

`DIFFTEST_S=1` enables capture. `DIFFTEST_S_SEMANTIC=1` also requires
`DIFFTEST_S_BOOTSTRAP_SOURCE`, `DIFFTEST_S_SPIKE_HOME` and the matching
`DIFFTEST_S_SPIKE_LIBRARY`; it enables the audited coherence and terminal
protocols. Test workloads, oracles, fault fixtures and runners live outside
production repositories.

Enabled builds default to direct compiler invocations. Use a fresh generated
model directory when changing probes or moving artifacts; an explicit
`OBJCACHE=ccache` opt-in needs an isolated, validated cache. The wrapper checks
native exit status and the BSG verdict in both capture and semantic modes.

`Configuration` bounds live instructions, outstanding stores and exact
publication deduplication history. History exhaustion returns Unsupported.
Callers retain inputs on Waiting and deliver queued prefixes with
`take_output()` before adding observations on that producer. The current native
capture also has hard session bounds of 65,536 allocated instructions and
1,048,576 observations. It fails on overflow rather than dropping events;
long-program streaming capture is a separate extension.
