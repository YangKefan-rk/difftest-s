# Incremental RVWMO checking

The checker keeps instruction identity, reference execution and memory-order
validation separate. `HostSession` owns independent per-hart references over
shared, independently initialized GlobalMem. `ObservationSession` accepts
source observations and architectural retirement snapshots; `Checker` owns
LocalMem, timed memory snapshots and PPO summaries. Accepted input or successful
reference execution is not a final verification result.

## Retired stores and early load checking

An ordinary store may retire before it publishes. After its address, byte mask
and data pass independent reference audit, `Checker` can retire its PPO metadata
through `PpoChecker::retire_deferred`. The pending store keeps its publication
obligation and the lower/upper bounds required by subsequent PPO rules. Its
later `observe_store` resolves those bounds without replaying retired
instructions. Atomic, acquire/release and LR/SC operations retain the complete
timestamp path.

Known timestamps use a fast path when the current effect is strictly later
than every preceding memory effect and no predecessor store time is unresolved.
Address, read-source, fence and register-dependency summaries still advance.
Otherwise the checker evaluates the applicable summaries and retains unresolved
constraints. A missing timestamp alone does not establish an inversion.

A load can complete its value check before a supplying local store publishes
only when its source prefix is certified complete. `ObservationSession` closes
whole source cycles and prevents a pending earlier memory event from being
overtaken. It passes that certificate into the load snapshot. A local store whose
publication is absent from that complete prefix is known to publish after the
sample, even though its exact future rank is unavailable. The model selects the latest eligible
local byte version, and PPO keeps the store's strict lower-bound obligation
after the load snapshot is released. Contradictory later publication is rejected.

Direct `Checker`/`Memory` callers default to no closed-prefix certificate.
They retain the conservative wait unless they independently establish the same
ordering contract. The existing Nanhu `Runtime` uses that default; it must not
infer completeness merely from not having received a publication packet.
Candidate bytes may advance a reference before final source verification, but
load acceptance still requires independent source-store audit and PPO/value
checks. DUT load results never initialize expected reference bytes.

## Coalesced publication

`StorePublishEvent` can carry several logical stores under an explicit
`coalesced_program_order` producer certificate. All members belong to one hart
and epoch and first become externally visible as one complete, indivisible
physical effect at a qualified source point. The producer supplies every
member, including stores whose bytes are completely overwritten, and the final
writer of each enabled byte.

The semantic consumer validates the full member list, byte-mask union and
final byte values against LocalStore records. It then linearizes members in
program order, reserving one consecutive rank per member before the next
memory effect. These are model ranks within the certified group, not separate
hardware timestamps. GlobalMem is updated by final byte writer; all logical
members retain independent reference-audit and PPO duties. Omitting a fully
overwritten member cannot discharge its outstanding publication obligation.

An uncertified merged effect is unsupported; an ambiguous cross-producer tie
remains incomplete. Current independent-effect groups accept single-store
publications only. The optional C wire ABI v1 still transports one store per
publication; multi-member support is in the typed C++ event/session interface.
BOOM's typed adapter entry requires the same certificate. Its current native
RTL decoder emits individual DCache writes and does not invent merged groups.
Nanhu's direct Runtime retains its existing group/member/byte-writer path.

## Retention and finalization

Resolved history is represented by address, dependency and ordering summaries.
Completed load snapshots and unreferenced store records are released. Unresolved
stores retain rule bounds and relations to other pending stores, with explicit
capacity limits. Pending-store relations can still grow quadratically up to
that limit; address summaries grow with the accessed address set. This is not
a constant-space guarantee for arbitrary unbounded programs.

Resource limits must never discard unresolved obligations to obtain Pass.
Only an explicit unaccepted Pending permits retry after progress. Capacity
exhaustion reported as Incomplete, or failure after partial consumption, is
terminal; never replay an accepted operation.
Final success requires all relevant store publications, reference audits,
retirements and source drain evidence. Instruction-class support and trustworthy
hardware order observations remain adapter-specific requirements; these
optimizations do not establish full-ISA or full-RVWMO completeness.

## Explicit observed-prefix verdict

`DIFFTEST_S_OBSERVED_PREFIX=1` enables a **limited** final marker only for
four-hart builds with `CONFIG_DIFFTEST_SOURCEPREFIXEVENT`. The default run is
unchanged. After the usual `Runtime::finish()` has passed architecture,
read-value and PPO checks, closed every required observed source prefix and
found no pending semantic events/stores/atomics, the runtime emits exactly one
`RVWMO_PREFIX_FINAL_V1 ` JSON line. Its `verdict` is `PassObserved`, its `scope`
is `observed_prefix_only`, and `physical_drain_certified` is always `false`.
The line also includes four independently compared hart counts, the closed and
last-effect source cycles, and zero pending counters.

This does **not** ignore any already observed operation or turn an unsupported
instruction into success. It deliberately does not claim that every L1/L2,
store-buffer, CHI or transport producer has become physically idle, so a later
producer event remains outside the checked prefix. A caller must expose this
scope explicitly and never equate `PassObserved` with the full `Pass` contract
from `HostSession::final_report()`. For a whole-run verdict, adapters still
need independent physical-idle and fully-delivered evidence for every required
producer before calling `HostSession::drain_producer` and `finalize`.

## Optional LinkNan observed-prefix semantic sidecar

The legacy `Runtime` owns an independent, read-only export after
`DIFFTEST_S_OBSERVED_PREFIX=1` produces `RVWMO_PREFIX_FINAL_V1`. Set
`DIFFTEST_S_SEMANTIC_OUTPUT` to an absolute per-case file path; the writer
exclusively creates it without replacing any existing case artifact. Set
`DIFFTEST_S_SEMANTIC_CASE_ID`, `_RUN_ID`, `_ELF_SHA256`, `_BACKEND_SHA256`, and
`_LAYOUT_SHA256` for case identity. Missing or invalid identity skips export
without changing REF, Checker, or the observed-prefix verdict.

The `difftest-s-observed-prefix.v1` JSON carries original producer
`sourceId`/`sourceSequence`, sampled source cycles, post-TLB physical byte
masks, and every required hart/source producer's actual closure watermark.
Only the final retired scalar load attempt and fully retired, REF-audited
coalesced store publication group enter `events`. `operation_scope` is
`scalar_load_store_only` in both this sidecar and the pinned immutable layout.
Atomic, LR, and successful SC effects remain independently checked by the
runtime but are deliberately excluded from scalar interaction scoring; each
accepted atomic observation contributes once to `excluded_atomic_effect_count`.
A same-source-cycle enabled-byte overlap between an excluded atomic and scalar
effect makes scalar completeness unavailable, since its within-cycle phase is
unverified. Source positions are never
replaced with checker ranks or host callback order. The source reset observer
must see assert then deassert on all four harts before labeling epoch 1.
Any omitted or unverifiable **scalar** effect yields `complete:false` and
diagnostic `incomplete_reasons`; no inferred load source, within-cycle order,
or physical-drain certificate is included. The scalar-only scope never claims
a complete all-memory interaction stream or an atomic read-from relation. The separate static layout must pin the shared NoC observation
cycle and its coarse, **unordered** same-cycle interpretation.

After writing, fsyncing, and reading the exact bytes back, the runtime emits
one `RVWMO_SEMANTIC_EXPORT_V1` marker with the sidecar's SHA-256, layout hash,
run ID, completeness, and closed-through cycle. Consumers must match this
checker-issued attestation to the real file and pinned build/layout provenance;
a self-declared `complete:true` sidecar alone is not trusted.

## Optional SFUZZ semantic interaction tap

`ObservationSession::set_semantic_event_observer` installs an optional
read-only callback **before** source submission. It observes source-closed raw
`RuntimeEvent` references only after the semantic consumer accepts them;
callbacks must copy or synchronously serialize, not retain the reference.
The hook covers LoadSample, LocalStore, StorePublish, InstructionRetire,
InstructionCancelAttempt and InstructionSquash. An observer exception disables
feedback but does not change the checker verdict. The host can supply this
callback through `HostSessionConfiguration::semantic_event_observer`.

The output is provisional until `HostSession::finalize` succeeds and
`semantic_feedback_publishable()` is true. Only then can the adapter publish
its case-local artifact using `semantic_source_watermarks()` and
`semantic_completed_cycle()`. The adapter must join each load sample to its
**final retired attempt**, exclude canceled/squashed work, and keep a
coalesced store publication as one transaction with all its member identities.
Its original `SourcePosition` is not a checker global-order rank or host
callback order. The adapter must separately prove post-TLB physical addresses
and the reset epoch/clock/phase mapping to any RTL functional-point window;
this generic checker does not invent that mapping. No certification means
feedback is unavailable, not a zero interaction score or a different verdict.
