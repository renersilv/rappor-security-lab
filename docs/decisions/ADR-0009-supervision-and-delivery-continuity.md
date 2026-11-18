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

## Acceptance

Offline fault injection proves failed notices do not gate safe progress, retries
retain pending intent, maintenance cannot execute work, publication absence blocks
runtime while permitting status, and exhausted review routing preserves bounds.
Install only reviewed, tested source under existing locks. Preserve pass241 and all
historical state; no fifth Web ZIP journey is authorized. Installed operation and
full product acceptance are separate evidence gates.
