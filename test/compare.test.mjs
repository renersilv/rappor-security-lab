import assert from "node:assert/strict";
import test from "node:test";

import { compare, toMarkdown } from "../src/compare.mjs";

const digest = `sha256:${"a".repeat(64)}`;

function fixture(control = "controlled") {
  const cases = [
    ["tp", true],
    ["fp", false],
    ["tn", false],
    ["fn", true],
  ].map(([id, expectedPresence]) => ({
    id,
    targetId: "target",
    targetRevision: "commit-1",
    state: expectedPresence ? "vulnerable" : "fixed",
    scanner: "semgrep",
    capability: "code-analysis",
    ruleFamily: "injection",
    expectedPresence,
    expectedSeverity: expectedPresence ? "high" : null,
    groupingKey: expectedPresence ? "injection" : null,
    safeEvidence: "Synthetic source pattern only.",
    fixedCaseId: expectedPresence ? "tn" : id,
    functionalAssertion: "The fixture returns a deterministic response.",
    scannerProfile: "semgrep-default@1",
    rulesetDigest: digest,
  }));
  return {
    benchmarkVersion: "1.0.0",
    targets: [{ id: "target", control, layer: "code", revision: "commit-1" }],
    cases,
  };
}

const observations = [
  { caseId: "tp", present: true, evidence: "must-not-leak" },
  { caseId: "fp", present: true },
  { caseId: "tn", present: false },
  { caseId: "fn", present: false },
];

test("classifies TP, FP, TN and FN and sanitizes output", () => {
  const report = compare(fixture(), { status: "completed", observations });
  assert.deepEqual(report.counts, {
    "true-positive": 1,
    "false-positive": 1,
    "true-negative": 1,
    "false-negative": 1,
    inconclusive: 0,
  });
  assert.equal(report.verdict, "blocked");
  assert.equal(report.clean, false);
  assert.doesNotMatch(JSON.stringify(report), /must-not-leak/);
  assert.doesNotMatch(toMarkdown(report), /must-not-leak/);
});

test("partial and failed controlled runs are never clean", () => {
  for (const status of ["partial", "failed"]) {
    const report = compare(fixture(), { status, observations: [] });
    assert.equal(report.clean, false);
    assert.equal(report.verdict, "blocked");
    assert.equal(report.counts.inconclusive, 4);
  }
});

test("external mismatches and incomplete runs remain informational", () => {
  const mismatch = compare(fixture("external"), { status: "completed", observations });
  assert.equal(mismatch.verdict, "informational");
  assert.equal(mismatch.clean, false);
  assert.ok(mismatch.cases.every((item) => item.disposition === "informational"));

  const partial = compare(fixture("external"), { status: "partial", observations: [] });
  assert.equal(partial.verdict, "informational");
  assert.equal(partial.clean, false);
});

test("rejects missing essential fields and unknown observations", () => {
  const manifest = fixture();
  delete manifest.cases[0].safeEvidence;
  assert.throws(
    () => compare(manifest, { status: "completed", observations }),
    /safeEvidence is required/,
  );

  assert.throws(
    () => compare(fixture(), { status: "completed", observations: [{ caseId: "unknown", present: true }] }),
    /caseId is unknown/,
  );
});
