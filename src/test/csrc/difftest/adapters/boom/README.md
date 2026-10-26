# BOOM native observations

This directory converts BOOM V4 observations into the shared Difftest-S event
and retirement types. The RTL bundles and `NativeFrame` are private BOOM
records, not another transport ABI. The common session owns reference execution,
shared-memory checking, producer registration and cross-hart order.

## Components

- `word_bytes` joins core and queue identities and extracts physical byte lanes.
- `boom_event_adapter` validates bounded ROB/LDQ/STQ and load-attempt lifetimes.
- `retirement_snapshot` converts independently captured architectural results
  into `ArchitecturalRetirement` for the shared session.
- `native_collector` consumes complete native source edges and stages delayed
  load observations until a source prefix can safely close.

The selected V4 configuration supplies the actual queue capacities. Circular
queue indices in core records include a wrap bit; the independently observed
queue allocation supplies the physical slot and its generation. Do not replace
those facts with a host counter or an allocation's initial load attempt.

## Source frames and delayed loads

Create one `NativeCollector` per hart and epoch. Set `initial_cycle` to the first
checked source edge and provide every subsequent edge, including empty ones.
The ingress must establish a lossless common source clock before decoding the
records. A missing edge, repeated edge, mismatched epoch or trap cannot pass.

Merge `core.allocate` with `lsu.allocate` in the same frame. Collect `lsu.begin`
and the union of `lsu.cancel` and `lsu.nack`. Equivalent cancellation facts are
normalized after their complete identities have been checked. A TLB retry may
begin on the edge reporting the previous attempt's cancellation; the collector
orders that private cancellation before the new begin. It still rejects a replay
that arrives in an earlier frame without cancellation of its predecessor.

Use only `lsu.complete` for the selected load result. `cache.load` and
`lsu.forward` describe related pipeline stages and must not generate duplicate
samples. Preserve the selected result's real `source_cycle`, sampling evidence,
physical address, width, byte mask and known writer identities. Response delivery
time is not the load's source time. Unknown byte writers remain unknown.

`begin_load_attempt` retains the earliest possible source cycle privately. It
does not consume a public producer sequence. `take_ready` releases a safe source
prefix in cycle order and then assigns strictly increasing hart-channel
sequences. An unresolved attempt keeps its possible sample cycle open. Sequence
numbers only organize one source channel; they do not qualify order between
independent channels. Simultaneous local load samples without a supported order
representation remain Incomplete.

`core.retire` is paired with the independent `lsu.retire_load` address, final
attempt and `retire_load_data`. Physical predicated-off retirements validate
ROB/PC/raw identity and squash the instruction. They do not execute REF.
Unsupported speculative memory can be tracked and squashed where its queue
shape is representable; an actual unsupported retirement remains Unsupported.

## Stores and shared-session ownership

`lsu.local_store` creates a local logical store. `lsu.store_release` releases its
physical STQ slot. Neither event authorizes publication. A publication requires
the actual cache data-write observation, complete single-writer evidence,
transaction identity and the fabric source supplied by the common integration.
Store retirement, native slot release, publication and independent REF audit
are separate obligations.

Independent tile caches must not be combined into one fabric producer whose
sequence is assigned by hart traversal. That would impose host order on
simultaneous independent publications. Register the actual source channels or
supply hardware-qualified arbitration evidence through the common owner. The
collector closes only its hart channel; the fabric owner must close fabric
prefixes after complete delivery.

Wrap the shared reference callback once. For every successful independent REF
store result, pass its unchanged identity, address, bytes and mask to the matching
collector's `audit_reference_store`. Return the same reference result to the
session for its own audit. Do not execute the reference instruction or take its
store trace twice. An audit that is unavailable after stepping REF requires an
explicit retained obligation or a terminal integration error, not a blind REF
retry.

## Backpressure and completion

`capture` reports whether it accepted the frame. A staging-capacity Pending
accepts nothing: retain the complete frame, drain ready output and retry.
Failures after partial frame application are terminal and cannot be retried as
an untouched frame. `take_ready` transfers ownership of its batch and snapshots
to the caller. Retain them until the session accepts them; never regenerate or
resubmit an already accepted batch because session progress is Pending.

`completion()` checks only private lifecycle and source/cache drain. A true
four-hart result also requires the common session's final verdict, every hart's
independent reference state, closed fabric/transport prefixes and native workload
completion. Hart park, an empty STQ or a successful host conversion is not that
verdict. Scalar integer RAM is the current generic path; unsupported architectural
state, atomics/LRSC, split access, FP/vector, trap and MMIO must not be dropped.

## WFI retirement

An actually retired `WFI` (`0x10500073`) has no scalar register or CSR write;
its PC, raw instruction and absence of a GPR result are checked through the
ordinary reference step. The validated scope is M-mode with no pending
interrupt. Other system instructions, CSR effects and trap/interrupt handling
retain their explicit coverage limits.

WFI retirement does not complete a hart or close any source prefix. BOOM may
stall its ROB at WFI until an interrupt arrives. Seeing its execution request,
a quiet cache or a parked program counter cannot substitute for architectural
retirement, an explicit completion boundary, or physical and transport drain.
