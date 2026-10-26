# ADR-0002: Continue the authorized native campaign without resetting preparation

Status: accepted within the owner's explicit continuation authorization, 2026-10-23;
implementation tracked by laboratory #22. Activation remains separately verified.

## Context

The installed preparation wrapper correctly stopped after its independent review,
but has no transition consuming a later authorization. The owner subsequently
authorized ten native Windows CLI starts. One failed before scanning; the remaining
nine and two untouched IDE reservations cannot be represented by clearing the old
Linux ledger or resetting the preparation's three review attempts.

## Decision

Keep the preparation state and saved session immutable. A separate private campaign
marker binds that state, the same issue/worktree/branch/session, the protected native
authorization, the candidate, and historical attempt receipt hashes. Activation is
explicit and runs under the existing sequential and executor locks. It changes no
quota or old receipt, and it does not start a model or alter an issue label itself.

The existing stage wrapper routes an activated campaign to the same run_codex
continuation before reconciling the historical preparation snapshot. It appends a
current native-only contract and reuses the existing timeout/retry infrastructure.
It does not invoke the old Linux runner. Missing, changed or malformed authorization,
history, session or binding fails closed. Every actual native attempt must still be
consumed by the native runner before inference and remain within ten starts/600s.

The stage contract remains opt-in and forbids final delivery. Three consecutive
executor returns without a new attempt or changed source fingerprint stop at a
technical review boundary without consuming test budget or resetting old reviews. A private per-pass
result can request further technical continuation, independent review, or a genuine
owner action. None of these states proves #19/#17 acceptance, publishes the product,
or consumes an IDE reservation. The control command reports the current campaign
instead of presenting the superseded authorization wait as an owner obligation.

## Verification and rollout

Offline tests cover authorization/quota boundaries, history gaps and tampering,
private-file requirements, original state/session preservation, exhausted budgets,
wrong owner waits, result binding, status and wrapper routing without any inference.
Deliver the bridge as an isolated #22 Git commit based on installed laboratory main,
using a dedicated assisted worktree. Service preflight requires clean main: never
copy loose changes over that repository. Integrate only the reviewed isolated commit
under existing sequential, executor and laboratory integration locks, preserving
the unrelated unfinished #19 worktree and every pending change.

Activation requires the exact current candidate receipt with version, SHA and HML
origin. Verify publication separately before writing it. After activation succeeds,
change #19 from blocked to doing before starting the service: its release gate
selects doing/to-do/validating before the wrapper can execute. Preserve that gate.
A running worker keeps its locks; do not bypass it.

## Public reanalysis contract correction — 2026-10-23

The assisted handoff incorrectly required a separate reanalysis tool. The public
MCP contract uses start_workspace_analysis for both baseline and reanalysis; the
latter supplies the existing analysisConfigurationId and exact revision ID. The
continuation contract now preserves product/computer/origin/folder identity and
per-operation consent/cleanup without depending on an unadvertised tool name.
This corrects the laboratory instruction, not the product, budget or acceptance
criteria. Amend the installed contract binding through the audited handoff only
after the active bounded operation finishes; never replace it beneath a worker.

## Post-acceptance continuation — laboratory #23

After root and João independently accept the native CLI cycle, its test inference
stops. The same executor, worktree, saved session and review mechanism may continue
the remaining authorized #19 preparation and technical verification without another
remediation-test inference. This includes managed technical checks, bounded negative
cases and IDE preparation; it does not renew the exhausted Linux budget, spend the
eight unused native starts or either IDE reservation, or satisfy the remaining AI/
IDE/full acceptance matrix by inference. The earlier native-only contract describes
the completed campaign stage, not a reason to leave permitted follow-up work idle.

An assisted reviewed amendment binds the later contract and sets the existing phase
to active under the same locks, preserving the original state/contract/session/
preparation/result/receipt hashes and every counter. Record that amendment in the
existing private diagnostics. No new architecture, service, process, budget or final
acceptance rule is introduced; a concrete unavailable user action remains explicit.

## Bounded reviewed continuation — laboratory #24

Source changes are provenance, not independent progress. The #19 continuation
reached pass 47 because new observation notes or harness edits changed the source
snapshot and renewed the old three-pass heuristic. A reviewed diagnosis also
failed to reach the resumed session when it existed only in an untracked note.

Use the existing campaign controller with a monotonic independent-review
checkpoint. At most three executor launches may follow that checkpoint. Count
before invoking the executor, including failed and timed-out launches without a
finish result. Notes, commits, helper changes, consumed experiments and executor
claims cannot renew this window. Exhaustion is technical `review_pending`, never
an inferred owner authorization request or product acceptance. Preserve an actual
`owner_required` result. The review never resets cumulative passes or test budgets.

An assisted operator review binds the exact campaign state, latest pass, immutable
private evidence, concrete diagnosis/correction, verified cleanup and next action.
It also binds a private handoff file by path and SHA-256. The controller validates
that binding on every use and includes its exact text in the continuation prompt.
The executor result schema cannot supply or advance a review checkpoint. The
operator review is separate from the executor and must not release the same
failure on a bare claim or unchanged diagnosis. Receipt flags and model completion
are not independent acceptance proof; the reviewer must inspect referenced evidence.

Install #24 from its own reviewed worktree/commit under the existing locks, after
the active pass and cleanup finish. Existing campaigns require an explicit audited
upgrade of this metadata, with before/after hashes and retained original state.
There is no inferred checkpoint or silent migration. Keep the timer off through
upgrade and the first single-pass verification. The same session, #19 worktree,
branch, authorization, candidate and historical receipts remain bound. This adds
no service, model-test authorization or #19/#17 acceptance shortcut.
