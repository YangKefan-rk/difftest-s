# BlackParrot native adapter

This directory converts BlackParrot observations to the shared C++ events in
`rvwmo/event.h`. It does not own an independent Runtime, REF, or GMO resolver.
`Adapter` acceptance means conversion or buffering, never an RVWMO verdict.

## Boundaries

- `adapter.h/.cpp`: validates caller-supplied instruction identities, final load
  attempts, single-writer store publication, architectural writebacks and
  producer positions. `ConvertedOutput` keeps architectural DUT results for an
  independent reference session. Unknown physical provenance stays unknown.
- `native_bridge.h/.cpp`: the native testbench's private `bp_difftest_s_*` DPI
  capture and conversion. Its scalar records are not a public DPI protocol.
  Install a `NativeSink` before initialization to hand observations to a
  coordinator-owned session. Without a semantic session it reports Incomplete.
- The native RTL probes live beside BlackParrot's existing nonsynth monitors;
  the opt-in `Makefile.difftest-s` lives in `black-parrot-sim`.

The supported native baseline is the sim-pinned RTL, using its synchronous
multicore coherent cache configuration. All harts share source time; the core
and inverted cache edges carry separate half-cycle ticks. Equal-tick events
remain unqualified. Producer IDs identify channels and never establish order.
Asynchronous clock configurations need an independently proven time mapping.

## Integration obligations

The embedding host must supply all of the following before claiming a check:

1. A negotiated producer roster and lossless source-prefix closure proof.
2. `ObservationStream::submit/drain` and
   `CheckerEventConsumer::consume_closed` handling Pending and errors.
3. Hardware-qualified memory ranks, preserving unresolved same-tick conflicts.
4. Independent per-hart REF execution and store address/data/mask audits;
   DUT actual bytes must never supply REF expected bytes.
5. Trap, interrupt, squash, retirement, exit and memory-drain session handling.

The bridge retains factual SRAM write-buffer drains as publication candidates.
It does not upgrade a cache request, permission ACK, or physical drain to
`StorePublish` without a profile-specific visibility and commitment proof.
The cache array and forwarding paths can sample distinct ticks for one load;
these facts must be retained rather than assigning the response timestamp to
all bytes. Early architectural retirement followed by a late miss sample also
retains both times and exposes the current shared consumer limitation.

The adapter emits the schema-v2 whole-instruction squash event. The shared
consumer still does not support every native atomic, trap/interrupt,
cache-block or FP lifecycle. Those remain explicit gaps. Heartbeats and local
idle are diagnostics, not watermarks or all-hart completion. An upstream
native `[BSG-PASS]` is not a Difftest-S pass.

## Resource bounds

`Configuration` bounds live instructions and outstanding unpublished stores.
Successful publication transaction history has a separate hard session bound;
exhaustion returns Unsupported without dropping deduplication state. Callers
must respect Waiting backpressure and deliver queued watermarks with
`take_output()` before adding observations on that producer. The native bridge
also bounds captured instructions and observations and fails on overflow.
