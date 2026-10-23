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
