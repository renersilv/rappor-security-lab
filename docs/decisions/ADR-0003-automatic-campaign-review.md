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
