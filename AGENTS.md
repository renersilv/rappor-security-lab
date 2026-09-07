# AGENTS.md

## Mission

Build and maintain an independent, controlled validation laboratory for Rappor Security. The laboratory proves what the product detects, misses, resolves, reintroduces, normalizes, groups and presents. It is not product source code and must never be used as a production environment.

## Source of truth

Read in this order before changing the repository:

1. `docs/STATUS.md`;
2. the current approved GitHub Issue;
3. `docs/BENCHMARK-CONTRACT.md`;
4. `docs/SAFETY.md`;
5. documents referenced by the Issue.

Versioned decisions take precedence over assumptions. Work on one Issue at a time and respect its non-goals.

## Scope boundary

- João works only in `rappor-security-lab`.
- João never changes, merges, publishes or deploys `rappor-security`.
- Product unit, integration and architecture tests remain the responsibility of the product implementation Issue.
- This repository owns black-box validation targets, ground truth, orchestration and sanitized reports.
- A product discrepancy becomes a narrowly reproducible Issue in `renersilv/rappor-security`; João does not fix it here.
- Do not duplicate private product internals to make a benchmark pass. Exercise released or explicitly selected public contracts.

## Work queue

- The operational labels are `to-do`, `doing`, `validating`, `done` and `blocked`.
- Use one temporary branch per captured batch named `joao/batch-*`; never work directly on `main`.
- Keep at most one open Issue in `doing`.
- New Issues created after a batch starts wait for the next batch.
- A technical failure that João can investigate remains `doing`.
- Use `blocked` only for a real owner decision, authorization, credential supplied through a secure channel or owner-controlled external change.
- Deliver an implemented Issue open with `validating`. It moves to `done` only after the batch branch is integrated and its laboratory validation passes. The owner closes accepted work.

## Safety rules

- Never store or publish a real credential, customer record, production identifier or captured customer evidence.
- Secret fixtures must use explicitly synthetic, non-functional values approved by `docs/SAFETY.md`.
- Never connect the laboratory to a production account, database, tenant, network or secret store.
- Public test targets must be owned by the laboratory or explicitly documented by their operator as security test targets.
- Third-party checks are passive and bounded. Never fuzz, enumerate, authenticate, mutate data or attempt exploitation on a third-party target.
- Active authorization and data-access tests run only against disposable laboratory resources owned by the repository operator.
- Intentionally vulnerable deployments use isolated projects, dummy data, least-privilege credentials, bounded cost and no trust path to Rappor Security infrastructure.
- Scanner inputs and reports must be safe to publish. Evidence remains minimized and masked.
- Do not add GitHub Actions or another paid CI dependency without explicit owner approval.

## Benchmark quality

- Every positive case has an independent ground-truth identifier and a safe negative counterpart.
- Every vulnerable state has a fixed state; lifecycle suites also include partial remediation and reintroduction.
- Pin target commits, deployment revisions, scanner profiles and expected-result manifest versions.
- Do not use a moving third-party branch or live external page as a deterministic release gate.
- Distinguish true positive, false positive, true negative and false negative.
- A changed scanner rule set, vulnerability database or target revision starts a new benchmark baseline.
- Validate raw detection, safe normalization, correlation, score behavior, lifecycle state and user-visible presentation separately.
- AI remediation is accepted only when the functional checks pass and the same finding is absent from the repeated scan without introducing a new covered issue.
- A failed or partial scanner run is not a clean result.

## Language and data conventions

- English is mandatory for source code, identifiers, comments, schemas, manifests, fixtures, logs, metrics and technical test output.
- Portuguese is allowed in GitHub Issues and owner-facing operational messages.
- Persist instants in UTC and pin immutable revisions where possible.
- Keep synthetic user-facing samples in both `pt-BR` and `en-US` only when localization behavior is under test.

## Validation and commits

- Run checks proportional to the changed target and contract before completion.
- Keep intentionally expected findings distinct from repository supply-chain or CI security checks.
- Never weaken a safety control merely to make an expected result pass.
- Use coherent commits in the format `type(scope): description`.
- Preserve pre-existing work and never discard another worktree or batch.

