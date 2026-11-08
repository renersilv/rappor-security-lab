# ADR-0003: Review campaign checkpoints in the existing worker

Status: accepted under the owner's explicit repair request; laboratory #25.

The #24 campaign adapter returns successfully at review_pending without scheduling
its independent review. The timer therefore cannot advance without this chat.
Keep #24's checkpoint boundary and protected evidence chain, but have the host
wrapper run a fresh, tool-disabled, read-only reviewer at that boundary. It is not
the executor's saved session and cannot write a checkpoint or start experiments.

The host snapshots the current campaign, result, prior handoff and exact candidate
manifest plus sources before invoking review. Large vendor files are hash-verified
and explicitly identified as omitted, never silently presented as reviewed. Missing
material evidence requires correction. No candidate code is executed by the review
host. Reviewer output is strictly typed; source, state and bindings are rechecked
before the host appends a protected #24-compatible receipt. Immutable before/after
state and intent make interruption recovery idempotent. The executor receives the
specific next action through the existing prompt, never through executable shell.

The installed campaign contract and budgets do not change. A correction permits
offline repair only. A technical continuation remains subject to its existing
preflight, consent, exact identity, deadlines and cleanup; static review never
accepts a platform or authorizes remediation inference. An unresolved cleanup or
missing source cannot approve live work. Owner-only actions are distinct from
correctable defects. No source edit or executor result advances a checkpoint.

The existing service, shared/run locks, timer and three-attempt operational retry
gate are reused. Review timeouts count as failures, unlike an executor time slice.
Three reviews without independently established behavior change or fresh bound
runtime evidence stop with a deduplicated operational notice; changing names,
prose, timestamps or test counts cannot renew it. Behavior change also requires
a different executable-content fingerprint; filenames are excluded from that hash.
That stop keeps doing and is not mislabeled as missing owner authorization.
Control status exposes the independent review phase and next actor. A review
transition persists before notification so notification retry cannot rerun review.

Install this isolated change under the existing shared/run/integration locks when
the current worker is inactive. Preserve the #19 worktree, session, candidate,
contract digest, counters and all historical evidence. No private-state migration
or contract rebinding is necessary. Verify real review/continuation after offline
tests; mocked transport tests are not evidence of a successful real review.


## Executor owner-action claims require independent review

An executor result requesting owner_required is a claim, not an accepted owner
block. Finish preserves that exact result and routes the valid current manifest
to review_pending. Only the independent reviewer can confirm the typed action and
location after checking why remaining authorized work cannot continue.

An already finished unreviewed owner claim may enter the same review without a
pre-review state rewrite: require the exact current bound result, completed pass,
unchanged candidate and all existing authorization/receipt checks. A review of
that same pass already confirmed as owner_required cannot be silently reassessed.
Preparation remains bounded by existing review transport and no-progress limits.
The host never grants another experiment start, resets a counter, rewrites the
original result or clears an Azure owner block through this change. A confirmed
technical correction yields only the existing offline reviewed continuation;
any historically posted Azure block requires the authorized transition separately.

Readiness decisions must use typed runtime fields, exact enabled MCP endpoint,
correct Appx identity and evidence from the actual interactive session. Missing
substring matches, SSH window handles and local auth file presence cannot prove
an owner action. Renderer readiness timeout remains a technical failure. Fresh
observations must use corrected code and a new manifest; old evidence is immutable.

## Reconcile an explicitly assisted review after exhaustion

AB#305 repairs the stale automatic stop after an operator has installed a passing
independent checkpoint under ADR-0002. Reconciliation does not create or approve
that checkpoint. It requires the complete current campaign binding, an exact
completed-pass match, the receipt's before-state hash matching the stalled marker,
the previous-review chain, and a protected copy of the original automatic marker
alongside the operator receipt. The initial campaign amendment may change only
the phase to active and the review checkpoint. An owner-required or unbound review
cannot release exhaustion.

The automatic marker records a distinct `operator_reviewed` phase with immutable
references to that receipt and the original stalled marker. Replays revalidate
these bindings, including after the next pass begins. Counters and objective
history remain unchanged: the next automatic preparation can exhaust the same
limit again, while only fresh validated runtime evidence can reset it. Automatic
review cannot manufacture the required operator snapshot to renew itself.
