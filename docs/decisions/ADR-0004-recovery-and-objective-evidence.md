# ADR-0004: Bounded technical recovery and product objective evidence

Status: accepted under the owner's explicit request; laboratory #26.

## Problem

The existing worker stops after three equivalent failures without investigating
them. Review and executor loops measure changes in the harness, not completion of
the critical product journeys. The owner becomes the poller and repair dispatcher.

## Decision

Use the existing serialized worker, timer, locks and private diagnostics. Before
an operational suspension requests assisted intervention, a fresh independent
diagnosis receives a minimized immutable incident bundle. A repair is a bounded
patch in a separate worktree, not authority to edit installed main or private
campaign state. The diagnostic model has no tools; it returns typed diagnosis and
complete replacement contents for allowlisted automation files and new regression
tests. Existing tests, authorizations, safety contracts, recovery authority and
product files cannot be changed. Secrets and raw transcripts are not included.

The host applies a patch only after validating paths, size and the exact base.
It runs the new regression against unchanged source first, then all required
offline automation tests against the repair. Both run in a bubblewrap namespace
without network, host credentials, campaign state, host processes or VM access.
An independent fresh reviewer inspects the exact diff, source and test outcomes;
only a pass plus green checks permits integration. The host, not the model,
creates the commit and fast-forwards clean laboratory main under the existing
integration lock. A pending push is retried without another model or commit.

The original campaign, issue, saved session, worktree, receipts and quotas remain
unchanged. Recovery does not clear a denial, refresh a test authorization, erase a
failed review or modify evidence to make it pass. A validated automation repair
archives and releases only its matching operational retry gate. Repeated incidents
are bounded to two repair candidates per fingerprint; model/check timeouts count.
Unrepairable evidence or scope violations stop visibly with concrete diagnosis,
not a fictional request for authorization. A typed owner action remains distinct.
No new daemon, infrastructure, remediation inference or product publication exists.

Offline checks use a transient resource service inside the existing user manager,
limited to 1 GiB, 64 tasks and one CPU; it is not another persistent service.
A proven installed repair may grant three additional reviewer transports to the
same bound review job when its initial three were exhausted. Preserve the cumulative
counter and original responses; the grant binds the installed commit, immutable
recovery receipt and exact bundle. Two repair candidates cap the total at nine
reviewer transports; a failed candidate grants nothing. This cannot grant a single
remediation-test start. Persist final notification intent before releasing the
retry gate and flush it on ordinary cycles, including after a restart.

Maintain a versioned objective matrix anchored to issue #19's accepted evidence
and outstanding #17 criteria. Reviewers classify objective and evidence level;
the host checks referenced hashes, candidate and pass. A claimed acceptance is only
an acceptance candidate, never final acceptance. Mock results, code changes and
notes cannot advance product evidence. After three preparations without material
runtime evidence, direct a diagnostic replan towards the smallest missing proof,
without suspending for chat review or creating another test budget. Keep accepted
Windows CLI, technical-only Linux evidence, IDE, managed, negatives and Web distinct.
After six reviews without new validated runtime evidence including that replan,
stop visibly. Harness behavior changes and passing offline tests do not reset this
bound. Use the append-only objective preparation streak as a lower bound, including
when an older review marker incorrectly reset its counter. Replaying a stopped
finish is idempotent and preserves all evidence, authorization and acceptance. Unverifiable protected state
also fails closed before any repair-model call.

## Verification and rollout

Test fault diagnosis, out-of-scope patches, failing-before/passing-after regression,
review rejection, exact-state preservation, restart/push recovery, bounds and
objective replay/tampering. Verify isolation in the actual host namespace. Install
the isolated #26 commit only between active worker invocations under shared, run
and lab integration locks. Do not manufacture a failure in the live campaign;
exercise recovery with an isolated test state and report that limit explicitly.

## AB#305: Recovery sandbox launch boundary

The hardened worker's inherited restrictions prevent bubblewrap from creating its
namespaces when launched in a transient scope. The exact worker hardening was
reproduced with harmless probes: the scope failed before execution, while a
transient service launched by the existing user manager ran inside bubblewrap.
The worker and host security policies remain unchanged. The manager executes only
the fixed bubblewrap command; candidate code runs after its namespace isolation,
read-only mounts, cleared environment and no-new-privileges boundary. There is no
unsandboxed fallback. Resource and runtime limits remain enforced on the transient
service, including bounded termination of its control group.

A trusted sandbox preflight checks actual filesystem, process, network and
no-new-privileges isolation before invoking any diagnosis model or consuming a
repair candidate. Failures retain private diagnostics and existing retry/candidate
history. This does not refund consumed candidates, renew an objective checkpoint
or claim that a stalled campaign has made progress.

## AB#305: Fixed Windows host identity observation

The exact hardened worker was observed under the `unprivileged_userns` profile,
which denied reading the existing QEMU process executable. The same fixed
read-only observation launched by the user manager succeeded. Preserve worker
hardening and global policy; expose only the installed `windows-host-identity.py`
command without arguments. It passes retained, hash-pinned probe bytes to a
short-lived service (256 MiB, 32 tasks, one CPU, 40 seconds). The child verifies
the pin before running. This boundary authorizes only two fixed domain queries
and bounded `/proc` reads for the existing `joao-windows-x64` domain, UUID, QEMU
process generation and ownership of `127.0.0.1:2222` forwarded to guest port22.
It accepts no candidate code, arbitrary command, path, domain or transport option,
and performs no SSH, guest command, VM mutation or inference.

The installed reviewed source remains the trust boundary, not cryptographic
separation from another process owned by the same OS user. The fixed payload pin
rejects unintended changes and the child executes the same retained bytes rather
than rereading a mutable path. The receipt is a fresh identity observation, never
product acceptance, an experiment-budget grant or authorization for guest activity.
Failures are sanitized and inconclusive. No persistent service or general host
dispatch capability is introduced.
