# Rappor Security Lab

Laboratório independente e controlado para validar a Rappor Security como uma caixa-preta.

O repositório manterá aplicações e estados deliberadamente vulneráveis, suas versões corrigidas, alvos públicos isolados e um manifesto de resultados esperados. O objetivo é medir detecção, falsos positivos, falsos negativos, normalização, agrupamento, score, ciclo de correção e comportamento visível da interface.

Este repositório não contém código do produto, dados de clientes ou credenciais reais. Nenhum alvo do laboratório deve ser usado em produção.

Antes de contribuir, leia:

1. `AGENTS.md`;
2. `docs/STATUS.md`;
3. `docs/BENCHMARK-CONTRACT.md`;
4. `docs/SAFETY.md`.

## Executable benchmark manifest

`schemas/benchmark-manifest.schema.json` defines the versioned ground-truth format.
`manifests/example.json` covers controlled code, public and connected layers, an
external informational target, all lifecycle states, and example TP/FP/TN/FN
outcomes. Scanner evidence is input only and is deliberately excluded from reports.

Run the bundled example without installing dependencies:

```sh
npm test
node src/compare.mjs manifests/example.json
```

A separate observation file has the same shape as `exampleRun`: `status` is one of
`completed`, `partial` or `failed`, and `observations` contains `caseId` and boolean
`present` values. Generate both report formats with:

```sh
node src/compare.mjs manifests/example.json run.json \
  --json report.json --markdown report.md
```

Partial and failed runs are always non-clean. Controlled target discrepancies block
the verdict; external target discrepancies remain informational.

## Controlled code corpus

`corpus/code` contains four static, non-deployable revisions: `vulnerable`,
`partially-fixed`, `fixed` and `reintroduced`. Each revision has a JavaScript
dynamic-code fixture, a Rappor-owned non-functional marker fixture and a Kubernetes
configuration fixture. The fixed variants preserve the same deterministic
`parseQuantity("2") === 2` assertion.

The files under `scanner-profiles` pin the local Semgrep rule, Gitleaks marker rule
and Trivy misconfiguration mode. No scanner or network access is required for the
repository checks:

```sh
npm run check
```

`src/verify-corpus.mjs` verifies the expected signal matrix, functional assertion
and content digests referenced by the benchmark manifest. These fixtures are for
static scanning only. Do not build, run or publish the Kubernetes manifests as a
service.

## Controlled public vibe-coding target

`targets/public/vibe-coding` is a generated static fixture with four states
published through the owner-authorized, isolated laboratory Vercel account. Vercel
is the real host; Next.js, Lovable and the network-disabled Supabase client are
explicit controlled signals. Each page exposes exactly one public JavaScript
resource, below the six-resource scanner budget. Its response matrix covers
security headers, cookie attributes, an inert password form, mixed content,
synthetic elevated markers, and negative controls for Supabase publishable and anon
values.

`build.mjs` generates `vulnerable`, `partially-fixed`, `fixed` or `reintroduced`
into separate deployment directories; each selection has a content digest pinned
in `manifests/public-vibe-coding.json`. The local verifier starts only an ephemeral
loopback server and performs independent HTTP, DOM and resource-budget assertions:

```sh
node src/verify-public-target.mjs
```

The target has no registration, write route, analytics or visitor persistence.
Publication and deployment changes are not part of repository checks and require an
owner-authorized, disposable Vercel account and isolated laboratory domain. See the
target README for the deployment safety boundary.

## Controlled public black-box comparison

`src/run-public-black-box.mjs` verifies the selected public client contract and
visible version, checks the exact state marker on each approved controlled URL,
then submits the four targets sequentially through the unauthenticated passive
public scan contract. It polls only same-origin status paths with ephemeral tokens
and never persists those tokens, internal scan identifiers, raw response bodies,
masked evidence or remediation text.

The mapping contract is pinned in
`scanner-profiles/rappor-public-black-box.json`. A live run must write both formats
to a temporary location for sanitization review before a dated record is admitted:

```sh
npm run public:black-box -- \
  --expected-version vMAJOR.MINOR.PATCH \
  --json /tmp/public-black-box.json \
  --markdown /tmp/public-black-box.md
```

The dated record in `observations/public-controlled` compares detection,
normalization, grouping, score, lifecycle and presentation separately. Coverage
reported as partial or failed remains non-clean even when individual findings are
present. `src/verify-public-black-box-report.mjs` checks the retained record against
the manifest, mapping-profile digest and sanitization boundary without contacting
the deployment.

## Disposable Supabase authorization target

`targets/connected/supabase-authorization` declares four immutable database states:
RLS absent, partial remediation, complete remediation and reintroduction. Its
manifest pins the expected table grants and policies alongside independent
anonymous and authenticated read/write cases.

Local checks verify the SQL, state digests, manifest and the bounded HTTP protocol
without contacting Supabase. A live lifecycle uses a publishable key for Auth and
Data API requests, `HEAD` for reads, `return=minimal` for writes, and an external
PostgreSQL service definition for administrative migrations:

```sh
npm run supabase:lifecycle -- --output /tmp/supabase-authorization-run.json
node src/compare.mjs \
  manifests/supabase-authorization.json \
  /tmp/supabase-authorization-run.json
```

No project URL, credential, user identifier, row body or inserted identifier is
retained in the report. Project provisioning and deletion are explicit owner
actions because they require an isolated Supabase organization, credentials from a
secure channel and irreversible provider operations. Follow the target README for
the complete lifecycle, reset and disposal verification procedure. The controls
follow Supabase's current guidance for [API keys](https://supabase.com/docs/guides/getting-started/api-keys),
[RLS](https://supabase.com/docs/guides/database/postgres/row-level-security) and
[project deletion](https://supabase.com/docs/guides/platform/delete-project).

The dated record in `observations/supabase-connected` retains only the pinned
state revisions, boolean access assertions, comparison classifications and reset
confirmation. Verify that record locally, without credentials or network access:

```sh
node src/verify-supabase-connected-report.mjs
```

## Controlled provider configuration ground truth

`targets/connected/provider-configuration` extends the connected laboratory with
independent, real provider states for the seven current Supabase Security Advisor
families and Vercel Git Fork Protection. Supabase uses empty synthetic PostgreSQL
objects plus bounded catalog assertions; Vercel uses only the four existing
controlled projects and the official project API. Both lifecycles start and end
safe, run cleanup in `finally`, and fail closed when a provider response or
post-condition changes.

`manifests/provider-configuration.json` pins positive, negative and reintroduced
cases without retaining a provider resource identifier. Live observations keep
only logical case identifiers, boolean post-conditions, immutable fixture
revisions, classifications and cleanup confirmation. See the target README for
the protected runtime configuration and commands.

The dated records in `observations/provider-configuration` contain the real
Supabase and Vercel ground-truth lifecycles. Validate both locally without provider
credentials or network access:

```sh
node src/verify-provider-configuration-report.mjs
```

## Connected-service HML lifecycle

`src/run-connected-service-lifecycle.mjs` is the common black-box runner for the
real Supabase and Vercel analysis journeys in HML. It uses only the rendered Web
flow and the same-origin public API contracts exposed by that flow. The runner
requires one existing `Active` provider connection, `Authorized` controlled
resources, the dedicated mode-`0600` HML credential file and an absolute
mode-`0600` checkpoint outside the repository. It never stores a provider,
Product, configuration or execution identifier in its report.

The runner creates or reuses the dedicated Product and connected-service
configurations. A pending execution identifier is kept only in the protected
checkpoint, so restarting polls the same execution instead of creating a
duplicate. Each provider checkpoint is bound to the selected visible HML version
and full laboratory commit; a new baseline uses a new protected checkpoint path
and an older checkpoint is preserved rather than relabeled. Provider cleanup
runs in `finally`; a failed, partial or unavailable scan is never interpreted as
a clean absence. Reports distinguish `Passed`,
`Failed`, `BlockedByConsent` and `Inconclusive` and retain only logical states,
versioned coverage, canonical rule families, logical affected-item groups, safe
score/evolution fields and cleanup confirmation. A repeated family is a true
duplicate only when it repeats the same logical affected item (or the same
transient fingerprint); distinct items in one family remain distinct findings.
Manifest cases without a comparable published coverage check are reported as
`Inconclusive`, never as passed. The lifecycle comparison separately validates
finding transitions, score progression, resolution, reintroduction and history.
Vercel states select four independent controlled projects and definitions, so
resolution and reintroduction are compared through covered finding transitions
while cross-definition evolution history remains explicitly `Inconclusive`.

With the protected environment already loaded, run a provider lifecycle with:

```sh
npm run connected:lifecycle -- \
  --provider vercel \
  --checkpoint /absolute/protected/path/vercel-checkpoint.json \
  --expected-version vMAJOR.MINOR.PATCH \
  --source-commit 40_HEX_GIT_COMMIT \
  --json /tmp/vercel-connected-lifecycle.json

npm run connected:verify -- /tmp/vercel-connected-lifecycle.json
```

Supabase uses the same command with `--provider supabase` plus the protected
`SUPABASE_LAB_*` and PostgreSQL service configuration documented below. The live
run is allowed only while its disposable project is independently reachable; an
`Active` HML connection by itself is not proof that the provider target works.

## External public observations

`observations/public-external` contains dated, sanitized observations made through
the selected Rappor Security public browser form. The bounded target set uses exact
Google Firing Range and badssl.com test URLs with operator-purpose evidence pinned
by commit. Raw evidence, response bodies, cookies and internal scan identifiers are
excluded.

These observations are exploratory and always informational. They are kept outside
controlled benchmark manifests and cannot block a verdict or redefine controlled
ground truth. Verify the checked-in record locally, without contacting any external
service:

```sh
node src/verify-external-public-baseline.mjs
```

The allowed URLs, capture procedure and handling for changed or unavailable pages
are documented in [`targets/external/public-passive/README.md`](targets/external/public-passive/README.md).

## Persistent Windows agent laboratory

`ops/windows-agent-lab` integrates the isolated `joao-windows-x64` libvirt session VM with an unattended live gate that exercises the official application UI. The runner checks host and guest capacity plus the preserved overlay's authorized 55 GiB absolute and 2 GiB per-run growth limits before and during disk-consuming phases. The runner is intended to verify the protected official MSIX and provenance, clean package installation, idempotency, application and runtime upgrade, restart recovery, heartbeat transitions, rotation, credential revocation and five recoverable failures. A complete accepted observation still requires real evidence for these steps and Semgrep, Gitleaks and Trivy analyses for the pinned public repository and a synthetic local folder. The local-folder run follows the explicit host Codex → HML MCP → restricted SSH → official Windows app path.

The live command requires external mode-`0600` SSH, HML credential and MSIX files, plus the existing host ChatGPT login and HML MCP OAuth. The one-shot AI attempt is serialized, consumes a private persistent marker before launch and has a 600-second total termination bound. Raw setup output, source, credentials, OAuth state, operation values and computer identifiers never enter reports. A successful run preserves the current controlled VM and retains only the dated sanitized observation:

```sh
npm run windows:agent -- --json /tmp/windows-agent.json --markdown /tmp/windows-agent.md
node src/verify-windows-agent-report.mjs /tmp/windows-agent.json /tmp/windows-agent.md
```

The VM boot unit, safety boundary, exact restore behavior and runtime variables are documented in [`targets/connected/windows-agent/README.md`](targets/connected/windows-agent/README.md).

## Current workspace AI laboratory

Issue #19's independent CLI/Linux slice uses the real Codex CLI, the isolated HML
MCP OAuth connection and the official Linux client against a private copy of the
controlled synthetic corpus. The original four-start authorization and its two
consumed CLI attempts remain immutable. One audited extension permits exactly a
fifth global start and a third CLI start while preserving two starts exclusively
for IDE/Windows proof. The extension is bound to the original receipt and the
pre-extension state digest; its activation and the third reservation are persisted
in one atomic write. Each process tree is limited to 600 seconds, and failure,
refusal or timeout still consumes its reservation.

The inert control and live preflight are:

```sh
bash ops/current-workspace-lab/run-codex-bounded.sh --self-test
bash ops/current-workspace-lab/run-codex-bounded.sh --prepare
bash ops/current-workspace-lab/run-codex-bounded.sh --preflight
```

The live command uses the exact short natural-language prompt pinned in
`scanner-profiles/current-workspace-ai.json` and never sends a product identifier,
computer identifier, path, endpoint or credential to the model. See
[`targets/connected/current-workspace/README.md`](targets/connected/current-workspace/README.md)
for the authorization, evidence and incomplete-matrix boundaries.

The 2026-10-17 CLI observation consumed the audited third CLI start after a
32-tool preflight. It observed the prepared client and exact computer selection,
then stopped for native folder consent before any baseline scanner completed. The
workspace stayed at the vulnerable revision with its functional assertion and all
three independent signals intact. The observation is explicitly `partial` and
`inconclusive`; it does not claim remediation or substitute for IDE/Windows proof.

## Autonomous execution

The reviewed operational contract, controls and user-service examples for João are
documented in [`ops/joao/README.md`](ops/joao/README.md). Installation is an
explicit owner action; repository checks do not install or start the units.

### Windows preparation before a real AI attempt

Installing the MSIX does not prove that its runtime was updated. After each package
installation, and when resuming a saved package-upgrade checkpoint, run the official
application setup through its public connect URI and visible controls. The UI adapter
allows only download, preparation, start and one public readiness refresh. A persistent
failure after that refresh stops the preparation; it never repeats a failed update.
It never clicks connection replacement, revocation, OS installation, license acceptance
or arbitrary controls. An unexpected step is a diagnosis to investigate, not permission
to edit private product state.

Before consuming an AI marker, independently require the same active online computer,
the published protocol and `source.current-workspace.v1`. `localFolderCompatible` is
not a first-use prerequisite: it depends on already registered workspaces. Product
release numbers and image revisions are not capability checks. Scanner provenance
remains exact and is validated by real executions.

If the VM has no desktop session, João can use its existing private laboratory login
and loopback console to open one in the existing VM. No new VM, permanent automatic
login or copied user credential is needed. Recheck capacity and the shared locks.
The UI probe reports only fixed action names and booleans, never raw window text.
Use `prepareOfficialWindowsRuntime` independently for preparation without an AI call.
Technical setup failures remain under investigation; missing current official artifacts
must be reported to Raimundo with a reproduction, rather than pretending the old MSIX
is current. Keep prior attempt receipts. Preparation never rearms an exhausted AI quota.

With the protected runtime variables loaded, the bounded preparation-only command is:

```sh
npm run windows:agent -- --prepare-runtime
```

It validates the current protected candidate, stages it for Windows Authenticode
verification, removes the staged copy, and checks capacity, Docker runtime, public
delivery protocol and the single preserved computer before exercising the official
setup UI. It does not create an observation, invoke Codex or read or change the
one-shot marker.

Before the one-shot marker is consumed, `runAiAnalysis` now prepares the existing
Edge session through visible login controls using the private laboratory account.
It accepts only the exact HTTPS origin and a single matching page. Password inputs
are never logged, and both temporary credential copies are removed even if login
fails. Ambiguous pages and a rejected login stop preparation without retrying the
password. The existing MCP OAuth connection must also be ready before inference.

The interactive continuation stages a short-lived scope for the exact preserved
computer and `C:\RapporLab\corpus`. The UI adapter confirms only the public origin,
the browser operation matching the command and Computer processing, and the native
read-only folder consent matching that computer and folder. Other dialogs fail
closed. No native consent or browser session is fabricated. The scope is removed
after the attempt.

The single owner-authorized attempt completed on 2026-10-14 through host Codex →
HML MCP → restricted SSH → the official Windows client. Semgrep 1.172.0, Gitleaks
8.30.1 and Trivy 0.74.0 completed in 198 seconds and produced 70 open findings with
a security score of 19.958358398579. Trivy used the explicitly reported
`approved-offline-stale` database state; this observation does not portray its
database as fresh. The result proves the public Windows continuation route, not
native Windows AI, remediation or score improvement.

The original attempt record did not confirm its first automatic cleanup. A separate
hashed verification record proves the later assisted finalization: the disposable
product was archived, the empty read-only source restored, the UI scope and corpus
removed, the temporary MCP connection removed, its OAuth grant revoked and the VM
shut down. Reports retain both facts instead of rewriting the original result.
Subsequent lifecycle reconciliation reads only those pinned private receipts and
never rearms the marker or launches another inference.

The bounded AI launcher uses the installed Codex [App Server protocol](https://learn.chatgpt.com/docs/app-server)
with the existing account login, an ephemeral thread, `on-request`, `auto_review`
and `workspace-write` with restricted network, verified before sending a turn.
The installed CLI parser probe remains an inert compatibility check, not the live
transport. Reviewer notifications are captured as closed categories; a timeout is
not reported as an approval refusal. A human approval request or review denial
stops the attempt. The observer never grants an approval itself. No authentication
is copied to the VM and no API key is introduced. The original one-shot receipt and
600-second total bound remain mandatory; this preparation grants no new attempt.

`bash ops/windows-agent-lab/run-codex-once.sh --check-interactive` checks the actual
installed transport policy without a prompt or inference. It does not consume or
rearm the one-shot marker and does not prove the AI analysis completed.

Capacity recovery is part of preparation, before any AI receipt. On 2026-10-13,
assisted preparation removed exactly two unreferenced superseded agent images and
one unreferenced historical Trivy cache after validating its read-only contents as
only `db/trivy.db` and `db/metadata.json`. The current public manifest image and
all container references were protected; configuration, credential, state, IPC,
source and current vulnerability-database volumes remained intact. Never use a
blanket volume prune or remove evidence to pass the capacity check.

If Docker's existing Windows data disk retains freed blocks, stop Docker through
its public desktop CLI, stop WSL, verify the exact existing data VHDX is detached,
and use Microsoft's `compact vdisk` maintenance operation before restarting Docker.
No new disk, VM, reset or capacity increase is authorized. Then run Windows ReTrim
and measure both guest free bytes and the host overlay's allocated size again.
Do not parse an English success sentence as a cross-locale contract: the Portuguese
DiskPart reply initially produced a false failure, while file-size and capacity
measurements confirmed recovery from 7,947,157,504 to 5,910,822,912 VHDX bytes.
The checked post-maintenance state had 13.52 GiB guest free and a 51.54 GiB overlay;
these are dated measurements, not permission to skip fresh admission checks.
Docker was restarted and retained the same configured computer.

Reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/compact-vdisk

Before inspecting browser controls, the UI preparation wakes the existing VM display
with a single Shift key through the existing libvirt console. This restores the
public accessibility tree after display idle without changing power policies or
automatically unlocking a session. A locked or ambiguous session still fails closed.

During an official runtime update, the capacity monitor continues to check host,
guest and overlay limits if Docker is momentarily unavailable. Initial preparation
admission also permits only `docker-not-ready` before starting the existing daemon;
it still checks all disk limits. A healthy daemon is preserved instead of restarting
its task. Ordinary execution admission, action admission and final verification still
require Docker to be ready. The
existing bounded UI preparation must recover normally; a transient Docker state is
neither an accepted installation nor permission to skip disk thresholds.

The selected package is 1.0.0.19 for product #309, with 1.0.0.17 as the actual
installed upgrade baseline. The producer manifest is preserved verbatim. The lab
checks the selected artifact hash, seven payload hashes, embedded revision, native
signature, installed client-info response and preserved computer identity.
Historical packages and receipts remain evidence but are not prerequisites for a
new candidate. The current candidate has its own immutable upgrade checkpoint.
Package preparation does not accept the scanner or AI journey.

MSIX installation uses the already authenticated laboratory desktop with a limited,
short-lived scheduled task. SSH logon alone can fail AppX PLM initialization with
0x80070005. The bridge preserves native signature, exact package SHA-256 and
installed-version checks and removes its temporary task and result files. It does
not elevate the desktop account or change Windows deployment policy.

Readiness invokes WSL and Docker through bounded native probes. A failed command
reports only an allowlisted phase and numeric exit code, never raw command output
or credentials. A probe timeout remains a failed check; it does not establish
readiness or permit the AI attempt.

Cold-boot recovery is pinned separately from the MSIX: published runtime revision
`e29d96a0b46cd25cde6e3a9b022e177488e869df`, image digest
`sha256:0cf6d1ef378aa8ff72abb04d4f65b35c9ef0b078c04e0501ed701c09762dbce3`
and protocol 7. The public preparation path must restore the preserved computer as
online with `source.current-workspace.v1`; a manual same-container recovery is not
accepted as the cold-boot result.
