import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const SHA256 = /^[a-f0-9]{64}$/u;
const SETTLED = new Set(["completed", "failed", "refused", "needs-owner-action", "timed-out"]);
const CLIENTS = ["cli-linux", "ide-windows"];

// Expected values must come from the independently reviewed checkpoint, never from this ledger.
export function validateClosedLedger(bytes, expected) {
  assert.ok(expected && typeof expected === "object", "reviewed-ledger-policy-required");
  assert.match(expected.sha256, SHA256, "reviewed-ledger-hash-required");
  assert.equal(createHash("sha256").update(bytes).digest("hex"), expected.sha256, "ledger-review-hash-mismatch");
  const ledger = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  assert.equal(ledger.schemaVersion, 9, "ledger-schema-mismatch");
  assert.ok(typeof expected.authorizationId === "string" && expected.authorizationId.length > 0,
    "reviewed-ledger-authorization-required");
  assert.equal(ledger.authorizationId, expected.authorizationId, "ledger-authorization-mismatch");
  for (const key of ["maxStarts", "maxCliLinuxStarts", "reservedIdeWindowsStarts"]) {
    assert.ok(Number.isSafeInteger(expected[key]) && expected[key] >= 0, "reviewed-ledger-limit-invalid");
    assert.equal(ledger[key], expected[key], "ledger-limit-mismatch");
  }
  assert.ok(expected.maxCliLinuxStarts + expected.reservedIdeWindowsStarts <= expected.maxStarts,
    "reviewed-ledger-limits-inconsistent");
  const limits = { "cli-linux": expected.maxCliLinuxStarts, "ide-windows": expected.reservedIdeWindowsStarts };
  const counts = Object.fromEntries(CLIENTS.map(client => [client, 0]));
  assert.ok(expected.counts && typeof expected.counts === "object" && !Array.isArray(expected.counts), "reviewed-ledger-counts-invalid");
  assert.deepEqual(Object.keys(expected.counts).sort(), [...CLIENTS].sort(), "reviewed-ledger-counts-invalid");
  for (const client of CLIENTS) {
    assert.ok(Number.isSafeInteger(expected.counts[client]) && expected.counts[client] >= 0 &&
      expected.counts[client] <= limits[client], "reviewed-ledger-count-invalid");
  }
  assert.ok(Array.isArray(ledger.attempts) && ledger.attempts.length <= expected.maxStarts,
    "ledger-attempt-count-invalid");
  for (const [index, attempt] of ledger.attempts.entries()) {
    assert.ok(attempt && typeof attempt === "object", "ledger-attempt-invalid");
    assert.equal(attempt.sequence, index + 1, "ledger-sequence-gap-or-duplicate");
    assert.ok(CLIENTS.includes(attempt.client), "ledger-client-invalid");
    counts[attempt.client] += 1;
    assert.ok(SETTLED.has(attempt.outcome), "ledger-outcome-not-settled");
    for (const key of ["startedAtUtc", "endedAtUtc"]) {
      assert.match(attempt[key], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u, "ledger-time-invalid");
      assert.equal(new Date(attempt[key]).toISOString(), attempt[key].replace("Z", ".000Z"), "ledger-time-invalid");
    }
    assert.ok(Date.parse(attempt.endedAtUtc) >= Date.parse(attempt.startedAtUtc), "ledger-time-order-invalid");
    assert.ok(Number.isInteger(attempt.processExit) && attempt.processExit >= 0 && attempt.processExit <= 255,
      "ledger-process-exit-invalid");
  }
  assert.deepEqual(counts, expected.counts, "ledger-client-count-mismatch");
  if (expected.lastAttempt !== null) {
    assert.ok(expected.lastAttempt && typeof expected.lastAttempt === "object", "reviewed-last-attempt-required");
    const last = ledger.attempts.at(-1);
    assert.ok(last, "ledger-last-attempt-missing");
    for (const key of ["sequence", "client", "outcome"]) {
      assert.equal(last[key], expected.lastAttempt[key], "ledger-last-attempt-mismatch");
    }
  } else assert.equal(ledger.attempts.length, 0, "reviewed-last-attempt-required");
  for (const [key, value] of Object.entries(ledger)) {
    if (key.endsWith("Sha256")) assert.match(value, SHA256, "ledger-provenance-hash-invalid");
  }
  return Object.freeze({ sha256: expected.sha256, total: ledger.attempts.length, counts: Object.freeze(counts), active: false });
}
