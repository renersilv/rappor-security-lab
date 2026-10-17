# Current workspace AI laboratory

This target validates Issue #19's real CLI/Linux path with an isolated HML tenant,
the official Linux client, the existing ChatGPT subscription login and a controlled
synthetic workspace. It does not validate the required IDE/Windows path and cannot
be used to mark Issue #19 complete by itself.

## Safety and external prerequisites

- use only the protected Issue #19 preparation and authorization receipts;
- use the `rapporLabIssue19` invocation override without changing global MCP
  configuration;
- never introduce an OpenAI API key or copy OAuth state to another profile;
- preserve the initially empty computer catalog and reuse the prepared synthetic
  product;
- install only the public hash-pinned Linux client and pinned agent revision;
- keep the existing Issue #18 computer and VM untouched; the VM remains stopped;
- never retain a product, computer, operation, path, callback, token, source file,
  browser session or raw tool response in a report.

The original owner authorization permits four starts globally, at most 600 seconds
each. Its two CLI/Linux starts were consumed and remain immutable. A separately
protected extension binds the original receipt and exact two-attempt state digest,
raising the limits to five global and three CLI/Linux starts while preserving two
starts for IDE/Windows. The extension activation and third CLI reservation are
written atomically to the private mode-`0600` history before Codex starts. A failed,
refused or timed-out start still counts. A sixth global or fourth CLI start fails
closed. The lock and history live outside Git and are shared by all worktrees and
sessions.

## Commands

The preparation and self-test do not invoke AI:

```sh
bash ops/current-workspace-lab/run-codex-bounded.sh --self-test
bash ops/current-workspace-lab/run-codex-bounded.sh --prepare
bash ops/current-workspace-lab/run-codex-bounded.sh --preflight
```

The live run uses the exact short natural prompt pinned in
`scanner-profiles/current-workspace-ai.json`. It runs from a private copy of the
controlled vulnerable corpus, not from a product repository or customer source:

```sh
bash ops/current-workspace-lab/run-codex-bounded.sh --run
bash ops/current-workspace-lab/run-codex-bounded.sh --status
```

The Codex observer verifies `on-request`, automatic review, `workspace-write`,
restricted network and an ephemeral thread before sending the prompt. It never
answers a human-consent request. If the official client or browser requires human
action, the attempt stops with a closed owner-action category and preserves the
remaining authorization. The process-tree watchdog terminates the attempt within
the authorized bound.

The AI result is only one evidence source. Acceptance also requires independent
workspace inspection, functional assertions, complete comparable scanner coverage,
rendered Web comparison and the still-pending IDE/Windows matrix. Partial or failed
coverage is never a clean result.

## Dated partial result

The third and final authorized CLI/Linux start ran on 2026-10-17 after the audited
extension and a successful 32-tool MCP preflight. The real journey observed the
assisted client installation, approved computer and exact computer selection, then
stopped at native folder consent. Ten automatic reviews were approved. No scanner,
baseline score, guidance, remediation, rerun or Web comparison completed.

The controlled workspace was unchanged and functional, with all three independent
vulnerable signals still present. The sanitized observation is stored under
`observations/current-workspace/` as `partial` and `inconclusive`. Both IDE/Windows
starts remain unused; no further CLI/Linux start is authorized.
