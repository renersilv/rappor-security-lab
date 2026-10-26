# Native campaign bridge rollout

Laboratory #22 delivers this bridge in an isolated Git commit based on installed
main. Its assisted branch is assist/joao-authorized-campaign. It must not integrate
the unfinished #19 batch or change any historical preparation/attempt receipt.

Service preflight requires its installed repository to remain on clean main.
Never copy loose bridge files over it. Validate the isolated commit, then integrate
using the existing shared sequential lock, João run.lock and laboratory
main-integration.lock. Check clean main and exact intended ancestry before and after
the fast-forward. Preserve the entire unfinished #19 worktree separately. Do not
change the product repository or publication during this laboratory delivery.

Run ordinary offline npm test/npm run check before delivery. These checks use
mocked local dependencies, not real scanners or the Windows VM. Campaign tests
exercise the real wrapper/resume path with a fake model transport and verify that
unfinished acceptance cannot advance to integration or finalization.

Create a protected candidate JSON only after confirming published metadata:
{"version":"vMAJOR.MINOR.PATCH","sha":"40-lowercase-hex","origin":"https://linux-ai2.taile60a95.ts.net:8443"}.
Do not infer the target from a moving branch or retain the historical v0.83.0 pin.

Once #22 is validating or done, run with the existing protected paths:

    bash ops/joao/activate-campaign.sh AUTHORIZATION_JSON NATIVE_ATTEMPTS_ROOT CANDIDATE_JSON
    bash ops/joao/control.sh status
    gh issue edit 19 --repo renersilv/rappor-security-lab --remove-label blocked --add-label doing
    systemctl --user start --no-block joao.service

Keep the existing product release gate installed. It runs before the wrapper and
selects doing/to-do/validating issues, so #19 must enter doing AFTER validated
activation and BEFORE service start. Changing the label alone cannot authorize a
campaign. Activation cannot bypass publication or resource locks. Confirm release
gate success and actual worker progress instead of reporting service start alone.

Activation acquires shared/run locks nonblocking; exit75 means an active worker,
not missing owner authorization. It preserves stage.json, reviews, session, attempts
and quotas. Repeating activation cannot reset anything. Prepare and validate the
native runner before a test start; its contract requires current public metadata,
readiness and rerun consent, and bans the old Linux runner. Capacity recovery uses
only existing official retention, preserving evidence, VM disks and persistent data.

Review_pending is a technical review boundary, not owner approval. The #24 checkpoint policy below supersedes the old source-fingerprint heuristic;
three executor launches require review regardless of file or attempt changes. Owner_required must identify an action unavailable with existing
authorization/credentials. Neither activation nor a completed model turn proves
acceptance. Inspect campaign results and independent end-to-end proofs.

## Reviewed post-CLI continuation — laboratory #23

The native CLI cycle has an accepted receipt and João's independent review. Do not
reactivate the campaign from scratch, reset its counters or repeat that cycle.
Deliver the #23 documentation change as an isolated Git commit, keeping installed
main clean and the unfinished #19 worktree intact. This is the existing ADR-0002
continuation, not another process, authorization budget or acceptance criterion.

After the worker's current operation and cleanup have finished, obtain the existing
shared, executor and laboratory integration locks. Confirm phase review_pending,
the expected executor/checkpoint values and root plus João's accepted evidence.
Before any amendment, preserve private immutable copies and SHA-256 hashes of the
original campaign state and contract, saved session, preparation state/reviews,
latest result, authorization reference and original attempt/acceptance receipts.
Verify that the recorded two starts and both historical receipt hashes still match.
Never modify those source receipts or infer acceptance from model-turn-completed.

Record the amendment intent in the existing private diagnostics with issue #23,
UTC time, the old/new contract hashes, original state/evidence hashes and the reason:
continue remaining authorized technical work without test-model inference. After
Git integration, verify the exact new contract. Update only contractSha256 to that
hash and phase to active in the existing campaign state, atomically; preserve all
other fields, including authorization, session/stage bindings, consumed counts,
receipt hashes, executorPasses, lastFinishedPass, noProgressPasses and progress
fingerprint. Append a completed amendment receipt outside campaign.json containing
the before/after state hashes and evidence references. This neither clears an
operational suspension nor permits bypassing a failed binding check.

Preserve the existing release gate and check #19 is doing before service start.
Release locks before starting the existing service. Verify actual continuation,
not just successful activation. Do not spend the eight unused native starts or two
IDE reservations, invoke the old Linux runner, or request another authorization for
already permitted preparation. The contract directs managed technical checks,
no-model negatives and IDE preparation until a precise user action or genuine new
review boundary remains. No part of this rollout claims all #19/#17 criteria passed.


## Reviewed launch window and explicit handoff — laboratory #24

Integrate the isolated #24 commit only after the active pass and cleanup finish.
Keep joao.timer stopped. Obtain the existing shared sequential, João run and
laboratory main-integration locks; confirm clean installed main and preserve the
unfinished #19 worktree. Run the offline suite before integration. No product
publication, VM, scanner or test inference is part of this controller rollout.

There is deliberately no executor-accessible review/release action in
campaign-control.py. Renewal is the existing assisted operator amendment under
these locks, after independent examination of evidence. Before editing state,
copy its exact bytes and SHA-256, the old contract, saved session, authorization,
preparation and receipt references into immutable private diagnostics. Never reset
executorPasses, lastFinishedPass, consumption, legacy counters/fingerprints,
authorization, candidate or receipt hashes. The legacy noProgressPasses and
progressFingerprint values remain historical metadata, not launch authority.

Create an operator-owned directory with mode0700 below the fixed location
~/.config/rappor-security-lab/campaign-reviews/. Put the reviewed handoff, exact
before-state snapshot and review receipt there as ordinary non-symlink mode0600
files. All referenced artifacts must be absolute canonical paths, owned by the
service user, mode0600 and at most1MiB. The handoff and evidence text must be
nonempty, at most32768 characters and contain no NUL. Diagnosis, correction and
cleanup can reference existing private evidence; keep raw secrets out of the
handoff because its exact text will be sent to the existing executor session.

The review receipt has exactly these fields (every reference below is an object
with exactly path and sha256):

- schema:1, issue:24, targetIssue:19;
- reviewedThroughPass: the exact current executorPasses, including reviewed
  failed launches that have no finish result;
- authorizationSha256, stageSha256, sessionSha256, candidateSha256: unchanged
  campaign bindings; contractSha256: the newly installed executable contract hash;
- beforeState: the preserved exact campaign snapshot. Its worktree, branch,
  attemptsRoot and protected bindings must match; its executorPasses must equal
  reviewedThroughPass;
- previousReview: the before-state reviewCheckpoint reference, or null for the
  explicit first upgrade. A later review keeps this chain and never rewrites it;
- handoff: the protected file containing the independently reviewed diagnosis,
  correction and exact next action, including what must not be repeated;
- diagnosis, correction, cleanup: independently inspected evidence references;
- failureFingerprint: a stable SHA-256 of the independently classified failure,
  or null only when the reviewer establishes that no failure is being retried.

For the same failureFingerprint, a later review cannot reuse the same correction
hash. A later reviewed pass cannot reuse the earlier cleanup hash. These are
freshness guards, not proof of semantic success: an operator must not fabricate
new evidence or alter prose merely to pass them. Review artifacts are not accepted
because an executor wrote a successful flag. No source edit, note, changed commit,
failed test start or model completion advances the checkpoint.

Prepare the prospective campaign by copying every field of the original and
changing only contractSha256 (when installing the new contract), reviewCheckpoint
to the review-receipt reference, and phase to active after technical review. Do not
clear a genuine owner_required condition through a routine technical amendment.
Validate the prospective binding with the installed controller before writing it.
Missing reviewCheckpoint fails closed for old campaigns: there is no silent
upgrade or inferred pass0 checkpoint. Fresh activations explicitly start with
reviewCheckpoint:null and an initial three-launch window.

Archive the prospective state and a private amendment intent with before/after
hashes and all evidence references, then atomically replace campaign.json and
write the completion record. A retry after interruption verifies those exact
hashes instead of reapplying or inventing a new checkpoint. None of this edits
campaign-result.json, stage.json, session, authorization or historical outcomes.

The checkpointer's protected directory is an operational/sandbox boundary, not
cryptographic separation from another process running as the same OS user. Do not
expose the assisted amendment procedure as an executor tool or add its directory
to the executor's writable roots. Path/hash validation detects missing, changed,
replayed and unbound artifacts; it does not authenticate who wrote a same-UID file.
The independent reviewer remains responsible for evidence and semantic diagnosis.

For example, an audited checkpoint at pass48 permits launches49,50,51. A fourth
launch is refused even if every pass adds notes/commits or fails before finish.
lastFinishedPass can remain below reviewedThroughPass after a reviewed aborted
launch; it is never rewritten to invent a completion. An owner_required result
is preserved at both the review and native-budget ceilings. Technical exhaustion
uses review_pending and keeps the operational Issue doing.

After amendment, run control.sh status and campaign-control.py prompt privately:
confirm the checkpoint, three remaining launches and exact reviewed handoff.
Release the locks, start joao.service once with the timer still stopped and verify
that the same saved session receives that handoff. Review its real outcome and
cleanup before restoring normal timer operation. The wrapper does not itself
perform an independent review or accept #19/#17; this repair prevents unbounded
self-renewal and makes the next reviewable task explicit.


A later bound campaign-result.executorPass also rejects an accidentally restored
older campaign counter. This does not make complete same-UID/disk restoration
rollback-proof: restoring campaign state and all later results together is outside
this boundary and is forbidden. Never restore an old campaign as a recovery shortcut.
Review-reference rollback with the current cumulative counter cannot buy launches;
a checkpoint farther behind either closes the window or fails validation.
