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

The public-descriptor observation can use its own small versioned entrypoint,
`src/public-observation-manifest.mjs`, without loading a Windows collector, SSH
credential or inference ledger. Its reviewed request binds the installed source
hashes, candidate, review and existing 15-second single-request limit. A real outer
runtime manifest binds the materialized receipt. Independent validation reads that
manifest and receipt, rejects missing/false activity and artifact drift, and
recomputes the retained safe public body's hash. Projection-only evidence remains
retained for diagnosis but cannot pass this complete-body observation. Approval of
this passive path does not approve remaining Windows credential, cleanup or IDE
checks, renew an inference budget, or create an absolute authorization deadline.

## Verification and rollout

Exercise rejection, offline correction, independent approval and read-only resume
through the real shell dispatcher and protected controller. Cover equivalent
failure exhaustion, distinct incidents, unchanged source, missing regression,
owner action, partial-write restart, preserved counters/authorization/ledger and
immutable historical results. Install only between worker invocations under the
existing locks after independent source review. Installation itself proves no
product journey and authorizes no remediation-model start.

## Installed source delivery and recovery context

Passes 205/206 exposed a delivery defect: the preserved task worktree predates
the installed reusable contracts. Relative source hints made the executor rebuild
an unproven contract. The host now supplies absolute installed paths, exact Git
revision and hashes for a closed set of reusable helpers and their regressions.
Bytes must match that installed revision. Reading or retaining those exact sources
does not merge, reset or otherwise change the task worktree. The handoff is source
availability, not execution authority or a correction-budget renewal.

Recovery diagnosis receives the validated sanitized findings, next action, scope,
preparation count and technical history for the exact current review. A generic
changes_requested label is insufficient to diagnose its failure. Historical review
results, protected state and the exhausted two-candidate bound remain unchanged.

## Bound public observation ingestion

The review packet and the public observer's runtime manifest are two distinct
materialized layers. Objective accounting validates the nested manifest's context,
activity flags, exact artifact hashes and live-to-operation-to-descriptor links
against the outer snapshot before considering runtime evidence. An absent outer
activity field does not discard that validated observation; an explicit false
field remains a veto. The real record_review boundary is regression-tested with
the observer's generated files. Historical packets and review results are never
rewritten, and an independent preparation verdict cannot be promoted by ingestion.
Python bytecode caches are ignored as generated files; unexpected source remains
visible to the unchanged clean-worktree gate.

## Start correction provenance at the rejection

The typed correction route starts at the first current-schema independent offline
rejection, rather than waiting for preparation exhaustion. Unresolved cleanup does
not prevent correcting its implementation offline. The protected review bundle
provides the outstanding route explicitly, and approval must cite its exact incident
and distinct, relevant regression artifacts. Missing proof cannot become a silent
approval followed by an operational stall. Equivalent defects retain the two-candidate
bound, while product preparation counters and all inference authorizations remain
unchanged. Historical results without route/proof are not upgraded retroactively.

An approval with unresolved cleanup still cannot leave the technical route for
runtime. Free-text instructions to clean up are not a verifiable restriction on
resources or actions. The existing gate remains closed until cleanup is eligible
or a separately reviewed protected checkpoint binds an exact authorized operation.
No historical null proof is reconstructed from prose or a behavior_change flag.

## Exact operational settlement continuation

For a corrected technical defect whose prior operation left cleanup unresolved,
a separate internal settlement_only scope can authorize one exact cleanup/probe.
It requires the same bound before/after repair proof and a closed typed plan:
original pass manifest/runtime receipt, unchanged candidate and authorization,
exact prior task/root and ownership-receipt names, installed fixed entrypoint
hashes and the original settlement deadline. It cannot accept arbitrary commands,
new resources or inference. The controller retains this plan and evidence in its
protected checkpoint; the entrypoint reserves one immutable execution intent.

Settlement is operational cleanup, not product evidence or acceptance. Only a
new receipt bound to that plan, pass and sources with observed absence, verified
process ownership and successful fixed transport probe permits the next existing
read-only observation. Missing/ambiguous ownership or incomplete cleanup stops.
Automatic and assisted checkpoints share these validators. Assisted recovery of
a historical untyped review uses a new explicit proof and preserves that result,
its consumed correction attempts and all campaign counters. Replaying a checkpoint
or request cannot execute settlement again.

A rejected settlement with an unused second correction returns only to offline repair under the same incident and cleanup origin. It removes the active settlement plan; a fresh changed-source regression proof and independent checkpoint are required before any further operation. A rejection after the second correction stops without renewing limits.

Recovery validation uses a self-contained temporary source snapshot because a Git
worktree's metadata points outside its read-only sandbox. Capture only tracked
regular files and explicitly authorized new regression files, reject symbolic
links or changes during capture, and preserve executable modes. Commit these exact
bytes into a fresh local Git repository with no remote or inherited configuration.
Its tree hash identifies test inputs only; it is never an installed revision or
product acceptance. Mount that snapshot read-only with the existing resource,
network and host-isolation limits, and retain its file hashes and tree provenance
in the validation log. The repair branch, protected state and quotas are unchanged.
