# Rocket native observation adapter

This directory converts Rocket-private observations into the common Difftest-S
C++ event contract. It does not define a DPI ABI, a reference stepper, a source
clock, a global ordering algorithm, or a final RVWMO verdict.

## Components

- `CacheTracker` associates a same-edge core request and DCache request, decodes
  the actual HellaCache requestor tag, retains the SRAM source position, and
  normalizes load/store bytes. Its live association table is capacity-limited.
- `EventEmitter` maps monotonic native instruction tokens to logical OperationId,
  captures only the selected load attempt, and retains committed stores until
  their actual publication. Speculative instructions remain private until
  retirement and its observations are available, so squash does not leave an
  allocation stranded in the semantic consumer.

Unsupported speculative instructions remain opaque until confirmed retirement;
a wrong-path FP/AMO allocation can be squashed without rejecting a valid scalar
execution. Keeping such an identity is not support for its memory semantics.

Both accept source observations supplied by the embedding simulator. A successful
method call means capture accepted; it does not mean the DUT or memory model passed.

## Native RTL inputs

The matching Rocket branch enables its optional outputs using the default-false
`freechips.rocketchip.rocket.EnableDifftestRocketCache` configuration field:

- `Rocket.io.difftest`: allocation, request/token, pipeline kills, raw scalar WB
  retirement, deferred integer writeback, and trap facts.
- `HellaCacheModule.io.difftest`: native cache attempts, SRAM-read qualification,
  S1 rejection/S2 qualification, cached loads, pstore transitions and actual drain.
- `RocketTileModuleImp.difftestCoreRequestor` and `difftestCacheRequestors`: the
  core's real index and the final number of HellaCache arbiter inputs.

Only blocking DCache currently provides native observations. Other cache
implementations expose `available=false`; scratchpad observation is rejected.
The ordinary cached scalar profile must not silently accept unavailable probes,
uncached/MMIO/implicit accesses, merged stores, AMO/LRSC, vector, or split accesses.

Collect observations on the modules' actual clock edges. A clock-gated module's
held valid signal is not a new event on every ungated host clock. The shared
profile must establish a common synchronous source-time domain.

## Producer and source-time ownership

The embedding session registers `rvwmo::hart_producer_id(hart)` and the selected
`rvwmo::memory_fabric_producer_id(fabric_index)`, then supplies them through
`EmitterConfiguration::producer` and `publication_producer`. Zero publication
producer explicitly disables publishing; it cannot silently reuse the hart ID.

The emitter routes StorePublish to that fabric channel and all other events to
its hart channel. `close_through()` closes only the hart channel. Only the shared
session, after receiving all participating cache/fabric observations, may close
the fabric prefix. A hart watermark cannot reject an older publication that is
still valid in the independently open fabric channel.

Each emitted event needs a unique producer sequence, including metadata sharing
one WB edge: LocalStore and Retire keep the same real cycle but distinct event
ordinals. This logging identity does not prove a cross-hart memory order.

Native cache request IDs include PTW/other requestors and are not instruction IDs.
`CacheTracker::bind()` checks the core and cache handshakes have the same source
edge, request address/command/size, and correctly encoded requestor/tag. Do not
hardcode core requestor zero or identify requests by destination register alone.
Release each association only after its downstream capture succeeds; discard
cancelled instructions' associations. Capacity Pending must retain and retry input.

The actual load value comes from qualified LoadGen result data, not a synthesized
expected value or a raw SRAM word that bypasses LoadGen. Its source position is
retained from the request's observed SRAM read edge, not stamped at S2 or DPI
arrival. Preserve the original WB retirement position even when the final sample
arrives later. The common session must defer/retry a retirement awaiting a sample.

The core probe includes the decoder's `mem` qualifier and `mem_cmd` beside raw
instruction bits. The emitter checks this evidence against the raw integer
opcode, function width and operation command; this catches memory instructions
whose raw encoding is not a base integer load/store. Ordinary load masks must
contain all requested bytes. The tracker preserves the virtual address's byte offset across translation
and requires the actual pstore drain address to match its accepted physical
address. A wrong drain value still flows from the drain probe to independent REF
store audit; the accepted store bytes are never substituted for it.

Store probe addresses include the original byte offset, while pstore data/masks
use lanes relative to the aligned 8-byte word. For example, a byte store at
`base+3`, mask `0x08`, word data `0x8877665544332211` becomes address `base+3`,
one byte `0x44`, and normalized mask `{1}`. Do not add the lane offset twice.
The publication converter reads actual drain data again; it must not reuse the
accepted store bytes and thereby hide corruption between acceptance and drain.

## Integration sequence

1. Pass every native instruction allocation to `EventEmitter::begin()`, including
   non-memory instructions, x0 destinations and raw compressed encodings.
2. Bind core/DCache requests and retain their native cache-attempt IDs.
3. For a qualified cached load, convert with `CacheTracker::load_sample()` and
   pass the result to `EventEmitter::sample_load()`. Cancel or discard killed
   attempts; never select the last packet merely because it arrived last.
4. Save accepted pstore bytes. At architectural store commit, obtain
   `CacheTracker::local_store()` with the original commit source and call
   `EventEmitter::commit_store()`. Retire all instructions in program order.
5. On the observed logical store drain, convert fresh actual bytes with
   `CacheTracker::publication()` and call `EventEmitter::publish_store()`. Retain
   the input on Pending, then release its association after successful capture.
6. Deliver `take_batch()` to the public ObservationStream. Advance only genuinely
   complete source prefixes; the caller owns shared fabric closure.
7. Require both private buffers to drain (`EventEmitter::finalize()` and
   `CacheTracker::finalize()`). These are liveness checks, not RVWMO verdicts.
8. The shared session supplies qualified memory ranks, independent REF access
   checks/store audit, architectural register comparison, trap/hart completion
   handling and final memory drain before declaring a verdict.

Core EX/MEM/WB can report the same killed token at several stages. These are
repeated native termination facts, not separate instructions. The emitter keeps
a bounded 32-token termination history for source-ordered scalar pipeline input.
Known repeats are idempotent; unknown tokens and retirement after termination
remain errors. Process same-edge cache rejection before instruction termination
to avoid releasing an association twice; candidate samples precede their squash.

The default blocking DCache resolves pstore-to-load RAW hazards by nack/drain/
replay, not byte forwarding. Its default ECC granule disables merging. A profile
that observes storeMerge must fail closed until a real multi-member/writer
implementation is enabled; it cannot invent separate publication ranks.

## Validation boundary

Tests, reference oracles, injection patches and generated outputs live outside
the production repositories. The current development evidence includes strict
C++/sanitizer contract tests, real Rocket Scala compilation, and full default-off
and dual-core enabled TestHarness CHIRRTL elaboration. These checks do not
substitute for production transport wiring, RTL execution, or a final multicore
RVWMO result. Source selection is `DIFFTEST_S_DUT=rocket`; the common build and
Chipyard harness wiring remain owned by the integration coordinator.


## Architectural retirement capture

`RetirementCapture` joins the ID returned by `EventEmitter::begin()` with
independent `RocketCoreObservation.retire` and `lateWrite` facts. Call
`allocate(instruction, id)` once for each accepted allocation, `retire()` with
the native WB PC/raw/control/value, and `late_write()` only with the observed
scoreboard token/destination. Repeated EX/MEM/WB squash facts are idempotent
within the bounded scalar kill history; retirement cannot be retracted.

Keep the two capture capacities consistent and retain native inputs on Pending;
a successfully accepted allocation/retirement must not be resubmitted to that
component when the other component needs retry. The embedding collector owns
this per-input progress, batch delivery and watermark closure.

`take_ready()` returns logical-ID/PC/raw/integer-result records in retirement
order after any deferred integer value is known. A missing deferred value keeps
`finalize()` pending. The original retirement source is retained, not replaced
by the late writeback timestamp. Writes to x0 normalize to no architectural
write; a nonzero pending scoreboard destination cannot be reused. The record
contains DUT actual state for comparison, never a REF expected load value.

The public session maps each private `CapturedRetirement` to its existing
`rvwmo::ArchitecturalRetirement`: copy `id`, `pc` and `instruction`; select
`ArchitecturalDestination::Integer` when `integer_write` is true (otherwise
`None`), then copy `destination`/`value` to `destination_register`/
`destination_value`. No second public transport or snapshot ABI is introduced.
FP/unsupported instruction comparators fail closed. The collector must check
every capture result and deliver snapshots before session finalization.

Storage is bounded by the configured pending-instruction capacity plus 32
scoreboard slots and the 32-token squash history. Allocation, retirement and
writeback identity lookup take O(log N); completed records are drained once.
No ordinary ALU instruction history is retained after its snapshot is drained.

The emitter tracks its unretired frontier separately from retired stores that
await publication. Retiring a new instruction no longer scans every retained
store. Hart watermark checks inspect only unretired allocations; they still
inspect every such allocation because native token order alone does not prove
allocation source-time order. Publication identities and store bytes remain
live until their real publication is accepted.


A caller-qualified store publication may physically precede the WB/LocalStore
metadata. The emitter retains that original source and exports it only after
confirmed retirement. Its source must follow the instruction allocation; it
need not follow the later metadata capture. The released public session defers
an early publication until its LocalStore record arrives. This does not prove
that a raw cache drain is a global publication: the embedding collector still
supplies the actual coherence/publication evidence.
