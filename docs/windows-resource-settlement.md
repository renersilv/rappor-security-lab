# Reviewed Windows task settlement

`src/windows-resource-settlement.mjs` is the narrow host entrypoint for the
`settlement_only` continuation in ADR-0006. The current authorized incident concerns
historical pass 220 of campaign 19 (operational work item AB#301). Its receipt is
operational cleanup evidence, never product acceptance or new inference progress.

The host dispatcher invokes:

```text
node src/windows-resource-settlement.mjs REQUEST_PATH REQUEST_SHA256 PROTECTED_ROOT
```

The production protected root is
`~/.config/rappor-security-lab/campaign-reviews`. The request has exactly
`schema`, `scope`, `checkpoint`, `plan`, and `outputDirectory`. References have
`path` and `sha256`. The entrypoint independently checks the current protected
`~/.local/state/rappor-security-lab/joao/campaign.json`, its active pass after
`begin`, its current checkpoint, the passing diagnosis, the settlement correction,
the exact cleanup origin, and the protected historical review chain. The plan
binds the historical manifest and runtime receipt, both original script hashes,
and every installed local source dependency. The controller owns the decision to
enter this phase; the executor model cannot grant it by producing a JSON packet.

The only resources are the task `RapporLab-Pass{originPass}-IdeReadiness` and root
`C:\RapporLab\runtime\pass{originPass}-ide-readiness`, derived from the protected
pending incident. The caller cannot supply a command, target, arbitrary root, PID,
or cleanup selector. SSH uses the existing `joao@127.0.0.1:2222` adapter convention
and `RAPPOR_WINDOWS_SSH_KEY`. Before SSH, the existing fixed
`ops/joao/windows-host-identity.py` read-only helper must verify the historical
laboratory domain UUID, QEMU generation, and exact loopback listener ownership;
the guest probe confirms the same UUID. The helper has at most 15 seconds within
the same total budget, and its source is part of the installed source map.
Identity failure or exhausted budget starts no guest operation. The credential is held through a validated descriptor,
checked before and after transport, and closed before success is published.
No VM lifecycle, authentication, model, IDE launch, scan, or configuration operation
is exposed.

The fixed PowerShell script verifies original script bytes, excludes reparse paths,
and validates the task action and principal before stopping or removing that exact
task. Process ownership uses the existing `owned-processes.json` and
`observer-ownership.json` formats. PID, process name, session, start ticks, and a
retained process handle must match before termination. Unknown related processes,
unreadable relevant process metadata, query failures, or missing evidence retain
`unresolved`. Missing ownership files are acceptable only when the exact task is
quiescent and the relevant inventory is empty. Other processes are not terminated.
Task/root absence and the owned process inventory are verified again after cleanup.

One monotonic 55-second total budget covers validation, probe, cleanup, credential
closure, and result verification; each transport call is at most 45 seconds. The
complete script is read from stdin by a fixed encoded bootstrap. A local process
kill, SSH exit 255, incomplete JSON, timeout, or unclosed pipe cannot prove remote
quiescence. No retry renews this deadline.

An exclusive, synced `settlement-<plan SHA>.intent.json` beside the plan reserves
one execution even if a different output directory is requested. Outputs stay
under the private state `tmp` directory. Success is written exclusively as
`settlement-result.json` after credential closure and source revalidation; it binds
plan, checkpoint, intent, candidate, pass, incident, and source hashes. The CLI
returns its path/hash and the intent path/hash. Failure never writes a successful
receipt. `settlement-unresolved.json` records a closed `failedStage` and
`reasonCode` for host identity, credential open/validation/closure, transport
probe, resource cleanup, source validation, or result publication. Transport
failures use fixed timeout/pipe/exit codes; remote output and exception text are
never copied into this diagnostic. A retained intent prevents blind replay after interruption; the controller
must assess missing cleanup evidence without assuming absence.

Focused verification:

```sh
node --test --test-isolation=none test/windows-resource-settlement.test.mjs test/windows-settlement-transport.test.mjs
node --test --test-isolation=none ops/joao/check-windows-settlement-powershell.mjs
```

The explicit PowerShell check stays outside default Node test discovery so that
ordinary unit tests do not acquire a container-image dependency. It uses the already installed .NET SDK image with PowerShell, no network,
no credentials, and a read-only container filesystem plus a temporary filesystem.
It executes the actual fixed script with local Scheduled Task/process fixtures and
reproduces the previous multiline stdin failure before testing the corrected
framing. This is not an execution against Windows, and Windows identity API calls
are isolated fixture seams; real host/guest settlement remains to be verified by
the authorized dispatcher. The stdin transport and held credential implementation
were narrowly extracted from the reviewed pass222 offline correction; the general
Windows adapter and its VM lifecycle remain unchanged.
