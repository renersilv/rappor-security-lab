import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { validateClosedLedger } from "../src/closed-ledger.mjs";
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const ledger = () => ({ schemaVersion: 9, authorizationId: "synthetic-test-authorization",
  maxStarts: 4, maxCliLinuxStarts: 2, reservedIdeWindowsStarts: 2,
  authorizationSha256: "a".repeat(64), attempts: ["cli-linux", "cli-linux", "ide-windows"].map((client, index) => ({
    sequence: index + 1, client, outcome: "failed", startedAtUtc: "2026-01-01T00:00:00Z",
    endedAtUtc: "2026-01-01T00:01:00Z", processExit: 0,
  })) });
const bytes = value => Buffer.from(JSON.stringify(value));
const policy = value => ({ sha256: hash(bytes(value)), authorizationId: "synthetic-test-authorization",
  maxStarts: 4, maxCliLinuxStarts: 2, reservedIdeWindowsStarts: 2,
  counts: { "cli-linux": 2, "ide-windows": 1 }, lastAttempt: { sequence: 3, client: "ide-windows", outcome: "failed" } });

test("reviewed closed ledger validates every attempt and keeps the remaining reservation", () => {
  const value = ledger();
  assert.deepEqual(validateClosedLedger(bytes(value), policy(value)), {
    sha256: hash(bytes(value)), total: 3, counts: { "cli-linux": 2, "ide-windows": 1 }, active: false,
  });
});

for (const [name, mutate] of [
  ["sequence gap", value => { value.attempts[0].sequence = 2; }],
  ["duplicate sequence", value => { value.attempts[1].sequence = 1; }],
  ["wrong earlier client", value => { value.attempts[0].client = "ide-windows"; }],
  ["unknown client", value => { value.attempts[0].client = "other"; }],
  ["active earlier attempt", value => { value.attempts[0].outcome = "started"; }],
  ["unknown outcome", value => { value.attempts[0].outcome = "success"; }],
  ["invalid timestamp", value => { value.attempts[0].startedAtUtc = "2026-02-30T00:00:00Z"; }],
  ["reversed times", value => { value.attempts[0].endedAtUtc = "2025-01-01T00:00:00Z"; }],
  ["boolean exit", value => { value.attempts[0].processExit = true; }],
  ["missing exit", value => { delete value.attempts[0].processExit; }],
  ["changed authorization", value => { value.authorizationId = "different"; }],
  ["increased limit", value => { value.maxStarts++; }],
  ["invalid provenance", value => { value.authorizationSha256 = "invalid"; }],
  ["last result changed", value => { value.attempts[2].outcome = "completed"; }],
]) {
  test(`rejects ${name} even with matching file hash and unchanged last sequence`, () => {
    const value = ledger(); mutate(value);
    assert.throws(() => validateClosedLedger(bytes(value), policy(value)));
  });
}

test("independent reviewed hash rejects replacement even when invariants remain plausible", () => {
  const value = ledger(); const expected = policy(value);
  value.attempts[0].processExit = 1;
  assert.throws(() => validateClosedLedger(bytes(value), expected), /ledger-review-hash-mismatch/u);
});

test("missing policy, boolean counts, and missing expected final outcome fail closed", () => {
  const value = ledger();
  assert.throws(() => validateClosedLedger(bytes(value)), /reviewed-ledger-policy/u);
  for (const update of [{ counts: undefined }, { counts: { "cli-linux": true, "ide-windows": 1 } },
    { lastAttempt: null }, { lastAttempt: undefined }, { maxStarts: true }]) {
    assert.throws(() => validateClosedLedger(bytes(value), { ...policy(value), ...update }));
  }
});
