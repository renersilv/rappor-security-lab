# João autonomous runner

The runner executes fixed laboratory Issue batches without an interactive terminal.
It never deploys targets and has no path to the Rappor Security product repository.

## Lifecycle

`run.sh cycle` validates the repository and remote before reading the queue. It
resumes the single saved `doing` Issue first. Otherwise it captures every eligible
open `to-do` Issue in numeric order. Eligibility means the Issue was opened by
`renersilv`, or a comment by that account contains the explicit marker
`/joao approve`.

The captured list does not change during the cycle. A private `joao/batch-*` branch
and worktree are created from `origin/main`. Codex runs as `gpt-5.6-sol` with
`xhigh` reasoning, one Issue at a time, and has three hours per Issue. A timeout
keeps the Issue in `doing`, retains its JSONL events, session and worktree, and
resumes on the next cycle. A crash after delivery recognizes the exclusive
`validating` state and advances without rerunning Codex. Batch publication and
per-Issue outcome/cursor transitions are crash-idempotent. A legitimate `blocked`
Issue advances only when its worktree is clean and unchanged, so independent batch
items continue. Correctable operational errors do not become `blocked`.
Codex event, error and prompt files remain private until delivery is verified. A
new attempt archives the preceding files instead of truncating them. Equivalent
operational failures receive at most two later timer attempts; the third preserves
the Issue in `doing` and suspends further Codex calls with one sanitized owner
notice.
Before an external action, João checks that action's prerequisites. Routine recovery
already authorized for the isolated account is not a new owner decision. Independently
authorized offline work may continue while a later live-test gate remains unavailable.

### Opt-in preparation stages

Issue #19 is governed by `contracts/19.json` and `contracts/issue-19.md` (ADR-0001).
The installed runner appends this single current contract instead of accumulating old
Issue instructions. A preparation return in `doing` triggers deterministic checks and
an independent, read-only, approval-disabled review in a separate session. The same
configured model/effort is retained; no test-model experiment or API key is used.

The private `stage.json` binds issue, branch, exact worktree, contract digest and source
snapshot, including untracked source. Review rounds are persisted before invocation and
limited to three, including interrupted reviews and failed checks. Findings feed the next
implementation turn as data. Changing source invalidates a pass; malformed state fails
closed. Review diagnostics are retained privately across rounds.

A passed preparation waits for campaign authorization; a genuinely missing external
prerequisite also waits. These waits preserve dirty work and prior commits without a
suspension or delivery-invalid retry. Timers emit one sanitized transition notice and
then make no model calls. `resume` cannot authorize a campaign or bypass this wait.
An exhausted review limit requires assisted diagnosis, not repeated resets. Final
delivery is forbidden while the preparation-only contract is installed. Transition to
a campaign/final-delivery contract is a separate, explicit, reviewed change; only then
may the ordinary full acceptance/integration checks apply. This mechanism never marks
#19/#17 complete on preparation evidence.

The existing serialized worker may recover an expired #19 OAuth session once per
credential generation through the official CLI and public browser, after a classified
refresh failure. The fixed isolated account, current grant, unchanged scopes, eight-hour
expiry boundary, private permissions and normal browser sandbox are checked. Revoked or
missing grants do not trigger recovery. Unavailable live access does not stop offline work.
No new service is installed. Direct parallel login is not permitted.

After every Issue is delivered as `validating`, the wrapper acquires its private
main-integration lock, incorporates current `origin/main` into the batch branch,
resolves ordinary conflicts only in that worktree, and runs both `npm test` and
`npm run check`. The wrapper then fast-forwards and pushes `main` without rewriting
history. Only after that does it move the batch from `validating` to `done`; it
never closes Issues. Integration and finalization read only the private delivered
list. The wrapper rejects a delivered Issue that was returned or blocked, and
removes an integrated remote batch branch with an exact SHA lease.

Private state is stored below
`${XDG_STATE_HOME:-$HOME/.local/state}/rappor-security-lab/joao` with mode `0700`.
It contains only the batch, delivered and non-delivered lists, branch, base and
delivered revisions, worktree, cursor, current Issue, phase and Codex session needed
for recovery. The runner's state, worktree and locks are distinct from Raimundo's.
It also exports a private `TMPDIR` below this state root so scanner and test
processes do not depend on the machine-wide `/tmp` capacity. Existing worktrees
must match the exact root, Git common directory, branch and saved base ancestry
before use. This logical separation is not a physical security
boundary: Codex uses the operator's existing `CODEX_HOME` authentication and session
store.

Every fetch and push URL configured for `origin` must resolve exactly to
`renersilv/rappor-security-lab`. This prevents repository confusion, but `gh` still
uses the operator's existing credential. That credential is a residual operational
risk: the wrapper does not create or store a replacement credential, validates the
repository slug strictly, and the versioned prompt explicitly prohibits access to
the product repository. The existing Codex and GitHub credentials therefore remain
residual risks rather than physically isolated capabilities.

## Control

```sh
ops/joao/control.sh status
ops/joao/control.sh resume
```

`status` never prints the session identifier or failure fingerprint. It reports a
closed failure class and attempt count when an Issue retry exists. `resume` removes
only the applicable suspension gate and starts the service; it does not erase the
fixed batch, session, worktree or private diagnostics.

## Review and installation

The versioned user units assume the repository is checked out at
`$HOME/rappor-security-lab`. Installation is intentionally a separate owner action.
The service fixes a closed executable `PATH`, applies hardening supported by the
unprivileged user manager and runs the preflight as `ExecStartPre` in the same
environment as each cycle. The preflight pins the repository-local commit identity
to `Joao <codex@openai.com>`; GitHub access and pushes still use the operator's
existing authenticated credential. With the timer stopped, review and run:

```sh
systemctl --user stop joao.timer
mkdir -p "$HOME/.config/systemd/user"
install -m 0644 ops/joao/systemd/joao.service "$HOME/.config/systemd/user/joao.service"
install -m 0644 ops/joao/systemd/joao.timer "$HOME/.config/systemd/user/joao.timer"
cmp ops/joao/systemd/joao.service "$HOME/.config/systemd/user/joao.service"
cmp ops/joao/systemd/joao.timer "$HOME/.config/systemd/user/joao.timer"
systemd-analyze --user verify ops/joao/systemd/joao.service ops/joao/systemd/joao.timer
ops/joao/run.sh preflight
systemctl --user daemon-reload
systemctl --user enable --now joao.timer
systemctl --user is-enabled joao.timer
systemctl --user is-active joao.timer
```

An administrator may enable user lingering with `loginctl enable-linger USER` so
the user manager survives logout and starts after reboot. Do not place tokens,
credentials or other secrets in the optional João environment file.

## Local validation

The deterministic test harness replaces GitHub, Codex, timeout and integration
effects with local functions. It covers closed-batch capture, owner approval,
reboot/session recovery, timeout artifacts, validating recovery, blocked
continuation, conflicting labels, repository URL rejection, stale worktrees,
atomic capture recovery, Issue-boundary recovery, staged merge recovery,
delivered-head preservation, wrapper-only integration, leased branch deletion,
final states, real lock contention and sanitized controls.
It also covers precondition-first blocking and preservation when a blocked Issue
violates the unchanged-worktree invariant, as well as bounded equivalent failures,
diagnostic preservation and explicit recovery.

```sh
bash -n ops/joao/run.sh ops/joao/control.sh ops/joao/test/run-tests.sh
shellcheck -x ops/joao/run.sh ops/joao/control.sh ops/joao/test/run-tests.sh
bash ops/joao/test/run-tests.sh
npm test
npm run check
systemd-analyze --user verify ops/joao/systemd/joao.service ops/joao/systemd/joao.timer
```
