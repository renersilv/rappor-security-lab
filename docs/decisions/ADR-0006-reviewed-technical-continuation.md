# ADR-0006: Reviewed technical correction without renewing product evidence

Status: accepted by the owner through AB#301 revision 631, 2026-11-11.

## Problem

The product preparation bound also stops concrete offline corrections. A generic
`campaign_70` fingerprint then reuses an unrelated operational retry budget, and
the recovery installer refuses a stalled campaign. The owner becomes the dispatcher
even when the independent reviewer already identified a correctable defect.

## Decision

Keep all product preparation counters, runtime evidence, acceptance requirements,
authorizations and inference consumption unchanged. At the preparation bound,
an independently reviewed concrete rejection may open a separate technical
incident. Its only initial scope is offline correction in the existing executor.
The protected checkpoint binds the original findings, candidate, source and pass.
An outstanding incident keeps its identity even if finding wording or source
changes. It permits at most two correction candidates; unchanged source is not
progress. Each technical checkpoint permits one executor launch, including a
failed or interrupted launch. Existing timeouts and serialized locks still apply.

Only a subsequent independent pass referencing the same incident and exact
failing-before/passing-after regression artifacts can close it. The corrected
executable fingerprint must differ. That review may permit one already-authorized
read-only preflight; it cannot authorize inference, reauthentication, a scan,
mutation, a new deadline or a new budget. Product acceptance remains unproven.
The next review must establish real progress, a concrete different technical
incident, or a truthful stop. No global count of distinct resolved incidents is
substituted for the old preparation bound.

Historical stopped review artifacts remain immutable. The host may re-evaluate
only the exact saved rejection into this offline route, preserving a snapshot of
the stopped marker. A matching operational retry gate is archived and released
only after the bound correction checkpoint exists. Restart and notification
replay cannot create another correction candidate or refund a retry. A terminal
technical incident remains stopped and visible; an actionable owner requirement
continues to require the existing typed owner-action contract.

Operational fingerprints identify the outstanding incident independently of its
changing source binding. Source-only transport repairs remain in ADR-0004's
isolated repair pipeline; a review rejection is handled by this correction route,
not by allowing a recovery model to rewrite a stopped campaign.

## Verification and rollout

Exercise rejection, offline correction, independent approval and read-only resume
through the real shell dispatcher and protected controller. Cover equivalent
failure exhaustion, distinct incidents, unchanged source, missing regression,
owner action, partial-write restart, preserved counters/authorization/ledger and
immutable historical results. Install only between worker invocations under the
existing locks after independent source review. Installation itself proves no
product journey and authorizes no remediation-model start.
