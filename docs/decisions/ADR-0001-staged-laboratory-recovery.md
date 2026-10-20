# ADR-0001: Persistent preparation and independent review

Status: accepted by the owner on 2026-10-20; implementation tracked by laboratory #21.

## Context

Issue #19 legitimately preserves an earlier commit and an unfinished diff while preparing
an end-to-end experiment. The ordinary one-commit delivery loop interprets preparation
as invalid delivery and dirty blocked work as corruption. Repeated issue amendments
also mixed old authorizations with the current contract. A successful helper or a large
test count is not proof of the complete client journey.

## Decision

Use an explicit opt-in preparation contract in the existing João runner. The fixed
batch, per-executor session, private state, locks and final integration remain intact.
Preparation progresses through implementation, deterministic checks, a separate
read-only review and corrections. Review is a development operation, not a real AI
remediation experiment. It must not invoke that experiment or modify its budget.

Persist review intent before starting the reviewer, bound each attempt to the exact
tracked and untracked source snapshot and contract, cap review/correction rounds at
three and count interrupted reviews. A changed snapshot invalidates a pass. Missing
or malformed evidence fails closed. Operational errors retain existing bounded retries.

A successful preparation enters an explicit owner wait when the next experiment is
not authorized. That wait preserves all work, does not count as a failed delivery and
does not spawn another model at each timer. It is not final acceptance and cannot
advance the batch or change #19/#17 to done. Only an explicit subsequent contract and
validated authorization may release the experiment; `resume` alone cannot grant quota.

OAuth recovery for #19 uses the official CLI and public UI of the already authorized
isolated account with the same scopes. Recovery is bounded, serialized, audited and
never overrides a denial, revocation, missing credential or security review. Offline
implementation does not require a currently authenticated browser.

The existing product publication and independent laboratory gates remain authoritative.
No new service, virtual machine, API key, global retry loop or cross-repository executor
permission is introduced. A product defect still needs a scoped product issue.

## Acceptance and operational rollout

Test restart at each persisted phase, malformed and changed state, negative review,
review exhaustion, exact worktree binding, dirty-work preservation, idempotent wait
notifications and rejection of premature final delivery. Install only under the existing
sequential, run and main-integration locks after the active worker finishes. Preserve
all #19 changes and history; do not integrate its unfinished implementation as part of #21.
