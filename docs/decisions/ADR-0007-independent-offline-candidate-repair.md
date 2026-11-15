# ADR-0007: Independent offline repair after executor correction exhaustion

Status: authorized by the owner on 2026-11-15 under AB#301.

## Problem

A valid rejected candidate exhausts ADR-0006's two correction candidates. The
dispatcher then misclassifies the terminal review as a Codex transport failure.
ADR-0004 can neither edit that candidate nor release its stopped review. Repeating
the dispatcher cannot repair the defect and makes the owner an operational relay.

## Decision

Retain the two executor corrections and all historical receipts. Add a separate
host-owned offline repair operation to the existing serialized worker. It accepts
only a current, hash-bound, independently rejected offline candidate with an
exhausted technical incident. Owner requirements and unverifiable bindings never
enter this operation. No new daemon, infrastructure, product task or runtime
authorization is introduced.

A fresh tool-less repair model receives the exact source packet and rejection.
At most two proposals are reserved durably per incident, including failures.
Each proposal may change only existing candidate implementation files and add
bounded regression files. Installed helpers, authorization, manifests, historical
evidence and campaign state cannot be modified. Existing imports, named test
bodies and assertions remain byte-identical; only a uniquely delimited
`const makeSnapshots = ` fixture before `const observation = ` may be adjusted
when stricter validation requires valid inputs. These adjustments
are explicit in the independent diff review and cannot weaken the scenario.

The host applies files to a separate private snapshot. New regressions run on the
original source and must fail for the actual defect, then pass on the correction.
All retained tests also run on the correction. Node/Python checks execute under
Bubblewrap, without host home, network, credentials, host processes, sockets or
Windows access, under the existing resource limits. Timeout or sandbox failure is
not a valid reproduced defect. Tests cannot approve themselves: a fresh independent
review inspects the exact original and changed sources and actual bound logs.

Only green checks and independent approval allow the host to emit an immutable
checkpoint for **offline adoption** into the same task. The incident remains at
attempt two; its fingerprint binds the rejected source, not the repaired bytes.
The next ordinary independent candidate review still requires matching regression
proof before any read-only runtime observation. Adoption is not acceptance and
cannot authorize inference, scanning, login, cleanup or a deadline extension.
A rejected adoption cannot reopen this incident's repair allowance.

State and checkpoints are persisted before external calls; restart reuses the
same proposal, logs, review and checkpoint. Transport attempts are separately
bounded. Historical failed states are retained, never reset. Only the matching
operational retry is archived and released after a verified checkpoint exists.
The worker reports repair progress or a concrete terminal reason once per change.
Real owner actions remain explicit; a technical stop is never presented as missing
owner authorization or as successful product delivery.

## Verification

Test the real dispatcher from rejected review through independent repair, actual
isolated before/after regression, independent rejection/approval, offline adoption
and normal review. Exercise restart at each saved boundary, stale/tampered input,
path traversal, test weakening, source drift, timeouts, exhausted budgets and
unrelated retry gates. Preserve campaign counters, authorization, inference ledger
and historical reviews byte-for-byte except the new bound checkpoint transition.
Install under the established shared/run/integration locks and verify the live
worker enters this operation without a chat-triggered restart of the campaign.
