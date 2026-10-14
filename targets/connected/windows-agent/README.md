# Persistent Windows application laboratory

This target validates the released Windows application journey against the isolated
`joao-windows-x64` libvirt session VM. It is an active, owner-authorized target.
It must never be pointed at a customer tenant, production control plane, personal
computer, or non-synthetic source tree.

## External prerequisites

- the existing persistent VM named in `scanner-profiles/windows-agent-lab.json`;
- a loopback-only SSH forward and its mode-`0600` private key;
- a dedicated HML account supplied in a mode-`0600` environment file;
- the credential-free HML origin supplied outside Git;
- the selected official laboratory MSIX supplied outside Git through
  `RAPPOR_WINDOWS_MSIX_PATH`, with its adjacent provenance manifest;
- an existing host Codex login through ChatGPT and OAuth access to the HML MCP
  server; no OpenAI API key is accepted;
- Docker Desktop terms already reviewed by the laboratory owner.

The runner refuses heavy execution when host or guest capacity is below the pinned
thresholds. It preserves the existing overlay and enforces the owner-authorized
55 GiB absolute ceiling and 2 GiB maximum growth per run at admission, between
disk-consuming phases and while polling the managed analysis. Credentials, OAuth
state, operation values, computer identifiers, private paths, source, raw API
responses, scanner output and setup logs are never admitted to a report.

## Controlled lifecycle

The live gate performs these bounded phases:

1. verify VM autostart, loopback SSH, PowerShell, WSL 2, Docker Desktop, Compose,
   Linux containers, host capacity and guest capacity;
2. validate the protected MSIX hash, length, identity, signature, architecture,
   embedded source, build contract, payload set and preserved `1.0.0.17` baseline
   before staging the laboratory-only `1.0.0.19` candidate;
3. prove update without manual removal, idempotent reinstall, clean package
   installation and reuse of the same authorized computer;
4. prove stop/start, suspend/resume, heartbeat offline/online, credential rotation
   and credential revocation recovery;
5. exercise Docker stopped, safely simulated incompatible architecture, unavailable
   image, expired credential and invalid prior configuration, restoring the valid
   state after every case;
6. run Semgrep, Gitleaks and Trivy through the managed profile for the immutable
   public source and reconcile the copied synthetic local-folder result with the
   pinned receipt of the single consumed Codex → HML MCP → restricted SSH → official
   `Rappor.LocalClient` attempt. Reconciliation never launches another inference;
7. archive disposable HML records, retain the authorized computer, remove only
   declared transient laboratory files and recheck the absolute and growth limits.

The one-shot AI wrapper uses an atomic private marker before launch, a non-blocking
serialization lock and a 589-second soft limit plus a 10-second forced-termination
grace. A failed, timed-out or refused attempt cannot be repeated automatically.
`ops/windows-agent-lab/run-codex-once.sh --self-test` validates those controls with
an inert short-lived process and no AI or credential.

## Runtime configuration

Set these variables outside Git:

```text
RAPPOR_WINDOWS_HML_BASE_URL
RAPPOR_WINDOWS_HML_CREDENTIALS_FILE
RAPPOR_WINDOWS_SSH_KEY
RAPPOR_WINDOWS_MSIX_PATH
```

The credentials file contains `RAPPOR_HML_EMAIL` and `RAPPOR_HML_PASSWORD`. Run the
live lifecycle only from the laboratory host and only after the dedicated MCP OAuth
login is active:

```sh
npm run windows:agent -- --prepare-runtime
npm run windows:agent -- \
  --json /tmp/windows-agent.json \
  --markdown /tmp/windows-agent.md
node src/verify-windows-agent-report.mjs /tmp/windows-agent.json /tmp/windows-agent.md
```

Review the temporary mode-`0600` files for sanitization before copying a dated pair
into `observations/windows-agent`. The checked-in report is verified without a VM,
credentials or network access.

The preparation-only command validates and exercises the official graphical setup
without invoking Codex, creating an observation or changing the private one-shot
marker. It is required after package installation or reinstall and when resuming the
preserved lifecycle checkpoint.

Historical checkpoints remain evidence but cannot substitute for the current one.
Current candidate provenance pins the preserved `1.0.0.17` installed baseline and
laboratory-only `1.0.0.19` replacement. The public runtime baseline is independently
pinned to protocol 7, revision `e29d96a0b46cd25cde6e3a9b022e177488e869df`
and digest `sha256:0cf6d1ef378aa8ff72abb04d4f65b35c9ef0b078c04e0501ed701c09762dbce3`.

The consumed real-attempt result and its later finalization verification are separate
mode-`0600` receipts with pinned SHA-256 values. The original record retains its
unconfirmed automatic-cleanup outcome; the verification record establishes the final
post-state. The checked-in observation includes only their hashes and sanitized
facts. It never includes product, computer, operation or assessment identifiers.

## Recovery boundary

This Issue preserves the current VM and does not reset or replace its overlay. The
runner changes only the selected application package, declared agent configuration
test copies, the exact synthetic corpus copy and disposable HML records. Failure
cleanup restores a backed-up valid agent configuration and restarts the existing
Docker agent. Disk reclamation may use supported Windows component cleanup,
compression, trim and offline sparse compaction, but never deletes laboratory
evidence or creates another VM or disk.
