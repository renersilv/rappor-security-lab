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
`validating` state and advances without rerunning Codex. A legitimate `blocked`
Issue advances only when its worktree is clean and unchanged, so independent batch
items continue. Correctable operational errors do not become `blocked`.

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
for recovery. The runner uses separate run and main integration locks and shares no
path with Raimundo. Existing worktrees must match the exact root, Git common
directory, branch and saved base ancestry before use.

Every fetch and push URL configured for `origin` must resolve exactly to
`renersilv/rappor-security-lab`. This prevents repository confusion, but `gh` still
uses the operator's existing credential. That credential is a residual operational
risk: the wrapper does not create or store a replacement credential, validates the
repository slug strictly, and the versioned prompt explicitly prohibits access to
the product repository.

## Control

```sh
ops/joao/control.sh status
ops/joao/control.sh resume
```

`status` never prints the session identifier. `resume` only removes the suspension
marker and starts the service; it does not erase the fixed batch.

## Review and installation

The versioned user units assume the repository is checked out at
`$HOME/rappor-security-lab`. Installation is intentionally a separate owner action.
The service fixes a closed executable `PATH`, applies process hardening and runs
the preflight as `ExecStartPre` in the same environment as each cycle. With the
timer stopped, review and run:

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
delivered-head preservation, wrapper-only integration, leased branch deletion,
final states, real lock contention and sanitized controls.

```sh
bash -n ops/joao/run.sh ops/joao/control.sh ops/joao/test/run-tests.sh
shellcheck -x ops/joao/run.sh ops/joao/control.sh ops/joao/test/run-tests.sh
bash ops/joao/test/run-tests.sh
npm test
npm run check
systemd-analyze --user verify ops/joao/systemd/joao.service ops/joao/systemd/joao.timer
```
