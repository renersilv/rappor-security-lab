# ADR-0005: One Azure operational queue with preserved campaign evidence

Status: accepted by the owner on 2026-11-06.

## Decision

Azure DevOps `rappor/Security` is the only operational queue. The reviewed common
queue adapter validates the inherited Basic process, explicit `Custom.RapporAgent`
and `Custom.RapporOrigin`, authenticated authorization, revision, priority and
phase. The existing Rener account may be shared; a declared origin is not proof of
which human or process used that account. João executes only owner-authorized
laboratory Tasks. GitHub remains Git hosting; no Issue API fallback exists.

A private host-owned binding pins the common adapter bytes and runner revision,
Azure configuration and state directory, and exact Security project. One explicit
preserved-campaign mapping binds the historical campaign 19 batch branch to its
real Azure work item. The historical batch, current_issue, session, contracts,
receipts, authorization and budgets are not renumbered. A matching number alone
never activates the campaign; new Azure items do not inherit historical contracts.
The binding is included in protected recovery inputs.

The host captures one fixed batch in adapter order. Read-only phase inventories
check implementation uniqueness without recapturing work. Every mutation passes
through the common adapter and its revision checks. A real owner block must be
returned to To Do by the configured authorized actor; campaign review cannot
silently clear it. Technical failures remain doing and retain bounded recovery.

Internal done means laboratory integration and validation, awaiting the configured
acceptor. It does not set Azure Done or accept the product. Models receive only the
current sanitized item and cannot select the queue. Product defect creation uses only the reviewed common adapter's bounded
report-finding operation. The current authorized João Task and stable finding key
bind an idempotent Issue with origin joao, agent raimundo and explicit priority;
existing owner authorization permits its To Do creation without repeated chat
approval. The caller cannot choose another origin, executor or acceptor. Never
create GitHub Issues or invent an alternate queue.

## Installation and verification

Install only at the protected between-runs point under existing locks after the
common Azure cutover is active and the exact mapping has been checked. Require a
private binding and pinned adapter on every operation. No source default guesses
an Azure ID. Verify API failure, wrong role/type/project/revision, mapping tampering,
new AB#19, fixed order, notification replay and preservation of campaign balances.
This source change does not activate services or authorize any remediation inference.

## Publication readiness condition

The versioned read-only publication gate replaces the old host-specific GitHub
handoff gate. Under a shared main-integration lock it requires no publication
reservation and exact deployed current/build-version markers for the explicitly
selected candidate. The active campaign's candidate hash is checked; a future
non-campaign task may supply the same private explicit candidate format. Missing
or changed markers fail closed. Product Git main may contain newer operations-only
commits and is not the deployed-candidate identity. This gate never queries a work
queue, releases dependencies, mutates a phase, accepts work or grants a test budget.
It is a local readiness observation; public health/runtime checks still belong to
the test contract and must be rechecked before external actions.
