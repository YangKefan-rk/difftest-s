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
