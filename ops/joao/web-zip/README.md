# Concrete Web ZIP runner

This is the separate adoption correction of the offline assisted pass237 repair. The original 40-test packet remains immutable. It does not
create a campaign checkpoint, change counters, release a retry, or authorize a
Windows launch. Historical candidates remain unchanged.

## Public journey

The selected product revision is `3105b01067ac415786d9c041cc922195c00c9cc4`,
version `v0.92.0`. The first-upload Web route is
`/products/{productId}/analyses/new?type=source-code`. The public wizard selects
ZIP, a reviewed synthetic analysis name and `Development`, then opens its native
file picker and shows the final confirmation. That single confirmation sends
multipart `name`, `environment`, `idempotencyKey` and `package` to
`/api/products/{productId}/analysis-definitions/uploaded-code`. The response supplies
the new execution, definition and exact revision IDs. This is `createUploaded` in
`web/rappor-web/src/lib/analysis-definitions-client.ts` and the creation wizard in
`managed-analysis-panel.tsx` at that revision.

The earlier adoption source selected the rerun route and required an existing ZIP
definition. The bounded official catalogue observation found no such definition;
this correction exercises the original first-upload journey without a preparatory
upload or an invented definition. Historical packets remain unchanged. There is
no retained rerun branch in this entrypoint.
The ZIP route has no workspace-operation consent descriptor or descriptor expiry.
The implementation observes the official confirmation, native picker, matching
upload request/response, execution page, revision, product, scanner coverage,
score, problem count and same-execution history. It retains screenshots with
verified byte hashes. Missing selectors or metadata remain inconclusive; generic
page text is not a substitute. No product implementation is copied into this lab.

## Entrypoint and authorization

`node source/web-zip-runner.mjs prepare --request PATH --sha256 SHA --output PATH`
materializes a private instruction, deterministic ZIP and exact source package.
It does not contact Windows. The request is the closed shape enforced in
`prepareWebZipPackage`; real product IDs and the authorized desktop SID/session
must be supplied by protected host input, never invented from a title or prefix.
The closed `product` input contains `productId`, `analysisName` and `environment`.
The name must match `Rappor Lab Web ZIP [A-Za-z0-9][A-Za-z0-9 ._-]{0,79}` and the
environment must be `Development`. Definition and revision IDs are response
observations, never request inputs. Both must match the rendered execution, and
the host packet preserves that binding. The visible coverage metric must say
Complete/Completa with all three tools; three completed tools with partial
Semgrep coverage cannot establish complete coverage.

`run` has the same arguments and is host-only. The current protected campaign must
be active at that exact executor pass, with an independently approved
`bounded_no_model` Web runtime grant. The checkpoint must explicitly bind the full
request as `correction.webZipRequest = {path, sha256}` and the exact executable
source closure in its manifest. Output is fixed to
`<checkpoint-directory>/web-zip-output-pass<N>`; the exclusive durable intent is
`<checkpoint-directory>/web-zip-pass<N>.intent.json`. A different output directory
cannot repeat the launch. Model sandboxes cannot write this protected authority.
No dispatcher integration or runtime approval is delivered by this packet.

The owner amendment dated 2026-11-17 permits three Web ZIP attempts in total,
including consumed pass238. Attempt two or three requires independently reviewed
changed executable source and the same regression failing before and passing after,
bound to the prior checkpoint/request and exact manifest artifacts. Every request
still has one launch and its own immutable intent; source repair cannot replay an
old request or refund an attempt. Current verified cleanup remains mandatory.
The fourth attempt is rejected; other targets and offline/model budgets are
unchanged. See ADR-0008 for the closed retry proof and assisted admission boundary.

The request binds the existing `previousReview`, not the future checkpoint that
will reference it. Materialize request, correction, review and campaign in that
order. The runtime receipt must name the same predecessor; the current receipt is
always selected and hash-verified through the protected campaign. This avoids a
circular content hash without relaxing request or current-authority binding.

All executable imports are included in `SOURCE_NAMES` and hashed in the request.
The existing laboratory protected-input, stdin transport, settlement transport
and host identity helpers are copied byte-for-byte and imported locally. The
fixed identity helper also has its independently known source/probe hashes.
The API dependency seams are for offline process tests; the CLI exposes no
arbitrary commands, hosts, credentials, or platform overrides.

## Windows ownership and lifecycle

One parent materializes the locked, hash-verified instruction, archive and worker
under an exact request-derived private root. Canonical ancestors, ACLs, host UUID,
account SID and interactive session are checked. The scheduled worker uses that
same instruction. Edge is created suspended, assigned to a kill-on-close Windows
job and only then resumed; the job contains its descendants even when ownership
discovery fails. Native dialogs must belong to the retained browser process and
its owner window. Pre-existing browsers and unrelated dialogs are not selected.

The total host budget is 600000 ms, including preparation, identity verification
and transport. The guest receives only the remaining absolute deadline. Work
reserves 90000 ms; cleanup reserves 15000 ms for parent settlement. Mutations
recheck the remaining budget immediately before they occur. Only the parent
removes the scheduled task after the worker has stopped. A primary write failure
cannot suppress cleanup. Partial ownership, failed cleanup or unconfirmed remote
quiescence remains unresolved. Transport failures retain only closed diagnostic
metadata, never raw stderr or credentials; stderr on a supposedly successful
transport rejects that result.

## Explicit limits

The adoption runner performs at most one official password-form login in the same
owned Edge instance and fresh profile. It reads only the existing fixed private
`issue19-hml.env` through a no-follow, stable file descriptor; the two environment
values are parsed as data, never sourced as shell code. No credential is read by
`prepare`. The runtime-only SSH stdin envelope carries the login material; it is
absent from the request, archive, package and receipts. On Windows the parent uses
DPAPI CurrentUser for the temporary `login.dpapi` passed to the worker. The parent
removes that exact file independently during cleanup and the host requires proof
of absence. Strings may remain in process memory; this is not a memory-erasure
claim.

The worker checks the same owned CDP target and exact origin/login path, fills the
public `login-email` and `login-password` controls, and clicks the official form
submit button once. Network event collection remains disabled during login and
no authentication screenshots are taken. It does not import cookies, call a bypass
endpoint, solve MFA, reset a password, register an account or retry rejected login.
The existing 600-second absolute budget covers this step as well. A rejected or
unavailable login remains unresolved; no credential or owner-action requirement
is inferred without real evidence. Product creation, separate configuration changes and inference remain outside
this runner. The reviewed first ZIP submission creates its own analysis definition
and execution through the official Web form, within the same one-upload allowance.

The safe channel exists but neither credential validity nor a usable desktop was
proven in this offline correction. DPAPI CurrentUser transfer from the SSH process
to the interactive process is a Windows integration precondition still to verify.

Process tests exercise the actual Node entrypoint and generated PowerShell
parent/worker with local child processes and Windows API doubles. They are not a
Windows desktop, Edge, native picker, upload or scanner acceptance result. The
Windows-only job object and UI APIs still require the future authorized live
check. The original pass237 packaging/result writers are historical context and
are not part of the new executable source closure or entrypoint.

## Repository regression commands

The source closure and synthetic fixtures are versioned together. Fast Node
contracts require no credentials, network, Windows or PowerShell:

```sh
node --test --test-concurrency=1 ops/joao/web-zip/test/web-zip-runner-contract.test.mjs ops/joao/web-zip/test/web-zip-adoption-final-authority.test.mjs ops/joao/web-zip/test/web-zip-first-upload.test.mjs ops/joao/web-zip/test/web-zip-creation-browser.test.mjs
```

The process regression requires local PowerShell (or the already approved isolated
SDK container), with Windows APIs explicitly doubled and no network:

```sh
PWSH_BIN=/usr/bin/pwsh node --test --test-concurrency=1 ops/joao/web-zip/integration/check-web-zip-linked-process.mjs ops/joao/web-zip/test/web-zip-adoption-final-authority.test.mjs ops/joao/web-zip/test/web-zip-first-upload.test.mjs ops/joao/web-zip/test/web-zip-creation-browser.test.mjs
```

The linked-process file imports the contract file, so the second command includes
the contract, authority, first-upload and browser cases without listing the contract a second time. Missing
PowerShell is a failed prerequisite, never a skipped acceptance test. These checks
cannot prove native DPAPI, Windows UI or PowerShell5.1 integration.
