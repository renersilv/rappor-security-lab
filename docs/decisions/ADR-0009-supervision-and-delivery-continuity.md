# ADR-0009: Supervision and delivery continuity

Status: accepted under the owner request of 2026-11-18; implementation and installed proof required.

## Problem

The owner repeatedly has to resume technical work through chat. Review transport
exhaustion can return before operational recovery; notification transport failure
can block already-authorized diagnosis. Stopping the timer for maintenance stops
all observation, while the service-level publication gate suppresses supervision.

## Decision

Reuse the existing worker, timer, locks, Azure adapter and bounded recovery.
Separate supervision from candidate-dependent execution. Maintenance is explicit
private state, never an expiring permission: observation and deferred notices
remain possible, but maintenance cannot launch a model, test, repair or publication.
Candidate-dependent work must still validate publication immediately before dispatch.
No extra daemon, VM, cloud resource, API key or inference/test allowance is created.

A notification transport error preserves the existing pending notification and
must not prevent authorized technical diagnosis. Persistence, validation and
operational authorization errors remain fatal; only the outbound comment error
is deferrable. The private owner-required state blocks execution independently of delivery.
The Azure blocked transition follows successful delivery of the required notice;
acknowledgment follows both delivery and that transition.

Review transport failures are distinguished from review rejection and owner action.
Record actual consumed transports idempotently, bound to the current review job.
Only the corresponding exhausted ordinary review can reach existing recovery.
Work-review hard ceilings and terminal repair outcomes remain unchanged; no empty
timer cycle resets counters, authorizes work or fabricates a successful verdict.

## Completed evidence behind an older executor gate

The same supervision journey may review a newly completed, manifest-bound campaign
pass before an older suspended executor/candidate repair gate. A read-only controller
validates campaign authority, completion, checkpoint ancestry and exact evidence.
The old review marker is not evidence that the new pass was reviewed. Repeated
activations reuse the same protected review job and consumed transport count.
A matching review transport incident retains its existing bounded recovery lane;
this admission cannot replace that incident, renew a work review or runtime quota.

This lane only reviews evidence and ends the activation. It cannot start the
executor, settlement, Web ZIP or candidate repair, clear an unrelated gate, or
claim that execution resumed. Review delivery notices explicitly retain the prior
technical gate. Transport exhaustion publishes a separate idempotent notice and
status without treating it as a rejected verdict. An outbound notice failure is
retried from the same persisted exhausted job without another model call;
persistence/validation failures remain fatal. Maintenance, publication and resource checks still apply before
model dispatch. Releasing an older gate requires its own exact authoritative
reconciliation; a review approval alone does not supply that authority.

## Exact supersession by a different reviewed offline target

A newly approved independent review may stop pursuing an old failed objective and
select a different already-authorized offline target. This does not prove the old
defect repaired. The existing resume operation may archive and remove only the
exact suspended `codex_exit` gate of that predecessor when its protected recovery
is `unrepairable`, its incident/pass/origin and authority match, and the current
review/checkpoint/after state independently grants a fresh offline entry. Recompute
the selection from immutable before-state and verdict; same-target corrections,
runtime grants, owner requirements, external-action recovery and delivery failures
do not qualify. Existing release routes keep their original authority.

Before removal, persist an immutable record of the exact retry bytes/hash, recovery
and incident snapshots, review references and typed continuation. Recheck under
the existing wrapper lock; a replaced gate is never removed. Crash replay reuses
that record, missing gate without a record is not success, and subsequent targets
cannot renew counters or supersede a new incident using this old proof. Recovery,
ledgers, attempts and historical evidence remain unchanged. Persist notice intent
before removal, then deliver the existing continuation notice without promising a
root-cause repair. Status distinguishes the historical superseded incident from a
new live gate. Source tests do not establish actual release or product acceptance.

## Acceptance

Offline fault injection proves failed notices do not gate safe progress, retries
retain pending intent, maintenance cannot execute work, publication absence blocks
runtime while permitting status, and exhausted review routing preserves bounds.
Install only reviewed, tested source under existing locks. Preserve pass241 and all
historical state; no fifth Web ZIP journey is authorized. Installed operation and
full product acceptance are separate evidence gates.
