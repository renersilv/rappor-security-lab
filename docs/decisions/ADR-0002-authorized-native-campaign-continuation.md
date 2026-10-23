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
