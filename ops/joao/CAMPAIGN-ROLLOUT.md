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

Review_pending is a technical review boundary, not owner approval. Three returns
without another attempt or changed source fingerprint enter that state without
resetting budget. Owner_required must identify an action unavailable with existing
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
