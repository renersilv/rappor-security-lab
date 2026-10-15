#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { evaluateLifecycle, summarizeOutcomes } from "./run-connected-service-lifecycle.mjs";
import { STATE_ORDER } from "../targets/connected/provider-configuration/lib/states.mjs";

const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/iu;
const FORBIDDEN_KEYS = new Set([
  "accountId", "accessToken", "assessmentId", "connectionId", "cookie", "email", "password",
  "fingerprint", "issueId", "location", "maskedEvidence", "occurrenceId", "productId", "projectId",
  "projectRef", "rawResponse", "requestId", "resourceId", "scannerRunId", "secret", "token", "url",
]);
const FORBIDDEN_MATERIAL = [
  UUID,
  /https?:\/\//iu,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
  /\b(?:sb_|prj_|team_)[A-Za-z0-9._-]+/u,
  /postgres(?:ql)?:\/\//iu,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/u,
];

function exactKeys(value, keys, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true, `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} fields changed`);
}

function inspectKeys(value, path = "report") {
  if (Array.isArray(value)) return value.forEach((item, index) => inspectKeys(item, `${path}[${index}]`));
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert.equal(FORBIDDEN_KEYS.has(key), false, `${path}.${key} retains forbidden material`);
    inspectKeys(child, `${path}.${key}`);
  }
}

export function verifyConnectedServiceLifecycleReport(report) {
  exactKeys(report, [
    "$schema", "schemaVersion", "recordedAt", "laboratory", "application", "provider", "execution",
    "setup", "summary", "states", "lifecycle", "presentation", "cleanup", "sanitization",
  ], "report");
  assert.equal(report.$schema, "../../schemas/connected-service-lifecycle-report.schema.json");
  assert.equal(report.schemaVersion, "1.1.0");
  assert.match(report.recordedAt, UTC_INSTANT);
  assert.equal(Number.isNaN(Date.parse(report.recordedAt)), false);
  assert.deepEqual(Object.keys(report.laboratory).sort(), ["sourceCommit", "version"]);
  assert.equal(report.laboratory.version, "0.0.0");
  assert.match(report.laboratory.sourceCommit, /^[a-f0-9]{40}$/u);
  exactKeys(report.application, ["selectedVisibleVersion", "observedVisibleVersion", "visibleVersionMatches"], "application");
  assert.match(report.application.selectedVisibleVersion, /^v\d+\.\d+\.\d+$/u);
  assert.match(report.application.observedVisibleVersion, /^v\d+\.\d+\.\d+$/u);
  assert.equal(report.application.visibleVersionMatches, report.application.selectedVisibleVersion === report.application.observedVisibleVersion);
  assert.ok(new Set(["supabase", "vercel"]).has(report.provider));
  assert.deepEqual(report.execution, {
    interface: "public-web-and-api",
    pollingBounded: true,
    rawResponsesRetained: false,
    resumed: report.execution.resumed,
  });
  assert.equal(typeof report.execution.resumed, "boolean");
  assert.ok(new Set(["Active", "Unavailable"]).has(report.setup.connectionState));
  assert.equal(Number.isSafeInteger(report.setup.authorizedResourceCount) && report.setup.authorizedResourceCount >= 0, true);
  assert.deepEqual(report.states.map((item) => item.state), STATE_ORDER.slice(0, report.states.length));

  const allowedOutcomes = new Set(["Passed", "Failed", "BlockedByConsent", "Inconclusive"]);
  for (const [index, state] of report.states.entries()) {
    exactKeys(state, [
      "state", "outcome", "assessmentState", "scannerState", "scannerKey", "scannerVersion", "profile",
      "profileVersion", "coverageStatus", "resultContractVersion", "rulesVersion", "coverageVersion",
      "expectedRuleCount", "coveredRuleCount", "manifestCaseCount", "measuredManifestCaseCount",
      "unmeasuredCaseIds", "unmeasuredRuleIds", "expectedFindingCount", "findingCount",
      "expectedAffectedItemCount", "affectedItemCount", "findingGroups", "expectedFindingRuleIds",
      "findingRuleIds", "severities", "duplicateFindings", "unmappedFindingCount",
      "coverageFindingMismatches", "severityMismatches", "expectedMeasuredFinding",
      "observedMeasuredFinding", "expectationMatched", "failureCode", "score", "evolution", "polls",
    ], `states[${index}]`);
    assert.equal(allowedOutcomes.has(state.outcome), true);
    assert.equal(typeof state.expectationMatched, "boolean");
    assert.equal(Number.isSafeInteger(state.expectedRuleCount) && state.expectedRuleCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.coveredRuleCount) && state.coveredRuleCount >= 0 && state.coveredRuleCount <= state.expectedRuleCount, true);
    assert.equal(Number.isSafeInteger(state.manifestCaseCount) && state.manifestCaseCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.measuredManifestCaseCount) && state.measuredManifestCaseCount >= 0, true);
    assert.equal(state.measuredManifestCaseCount + state.unmeasuredCaseIds.length, state.manifestCaseCount);
    assert.equal(new Set(state.unmeasuredCaseIds).size, state.unmeasuredCaseIds.length);
    assert.equal(new Set(state.unmeasuredRuleIds).size, state.unmeasuredRuleIds.length);
    assert.equal(Number.isSafeInteger(state.expectedFindingCount) && state.expectedFindingCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.findingCount) && state.findingCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.expectedAffectedItemCount) && state.expectedAffectedItemCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.affectedItemCount) && state.affectedItemCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.duplicateFindings) && state.duplicateFindings >= 0, true);
    assert.equal(Number.isSafeInteger(state.unmappedFindingCount) && state.unmappedFindingCount >= 0, true);
    assert.equal(Number.isSafeInteger(state.coverageFindingMismatches) && state.coverageFindingMismatches >= 0, true);
    assert.equal(Number.isSafeInteger(state.severityMismatches) && state.severityMismatches >= 0, true);
    assert.equal(Number.isSafeInteger(state.polls) && state.polls >= 0, true);
    assert.equal(new Set(state.expectedFindingRuleIds).size, state.expectedFindingRuleIds.length, `states[${index}] expected rule IDs are duplicated`);
    assert.equal(new Set(state.findingRuleIds).size, state.findingRuleIds.length, `states[${index}] rule IDs are duplicated`);
    assert.equal(new Set(state.findingGroups.map((group) => group.ruleId)).size, state.findingGroups.length);
    for (const [groupIndex, group] of state.findingGroups.entries()) {
      exactKeys(group, [
        "ruleId", "expectedSeverity", "observedSeverities", "expectedAffectedItems", "observedAffectedItems",
        "expectedAffectedItemCount", "observedAffectedItemCount",
      ], `states[${index}].findingGroups[${groupIndex}]`);
      assert.equal(new Set(group.expectedAffectedItems).size, group.expectedAffectedItems.length);
      assert.equal(new Set(group.observedAffectedItems).size, group.observedAffectedItems.length);
      assert.equal(new Set(group.observedSeverities).size, group.observedSeverities.length);
      assert.equal(group.expectedAffectedItemCount, group.expectedAffectedItems.length);
      assert.equal(group.observedAffectedItemCount, group.observedAffectedItems.length);
    }
    assert.equal(
      state.expectedFindingCount,
      state.findingGroups.reduce((total, group) => total + group.expectedAffectedItemCount, 0),
    );
    assert.equal(
      state.findingGroups.reduce((total, group) => total + group.observedAffectedItemCount, 0) <= state.findingCount,
      true,
    );
    assert.equal(state.duplicateFindings <= state.findingCount, true);
    assert.equal(state.unmappedFindingCount <= state.findingCount, true);
    const expectedItems = new Set(state.findingGroups.flatMap((group) => group.expectedAffectedItems));
    const observedItems = new Set(state.findingGroups.flatMap((group) => group.observedAffectedItems));
    assert.equal(state.expectedAffectedItemCount, expectedItems.size);
    assert.equal(state.affectedItemCount, observedItems.size);
    if (state.score !== null) {
      assert.deepEqual(
        Object.keys(state.score).sort(),
        Object.keys(state.score).filter((key) => new Set(["score", "presentation", "classification", "coveragePercentage"]).has(key)).sort(),
      );
    }
  }

  exactKeys(report.lifecycle, [
    "manifestCoverage", "measuredFindingTransitions", "scoreProgression", "measuredResolution",
    "measuredReintroduction", "history", "duplicateFree",
  ], "lifecycle");
  assert.deepEqual(report.lifecycle, evaluateLifecycle(report.provider, report.states));
  const expectedSummary = summarizeOutcomes(report.states, report.cleanup, report.lifecycle);
  assert.deepEqual(report.summary, expectedSummary);
  if (report.summary.clean) assert.equal(report.cleanup.verified, true);
  assert.equal(Number.isSafeInteger(report.cleanup.resourcesRestored) && report.cleanup.resourcesRestored >= 0, true);
  const locales = new Set(report.presentation.map((item) => item.locale));
  if (report.summary.clean) {
    assert.deepEqual(locales, new Set(["pt-BR", "en-US"]));
    assert.equal(report.presentation.every((item) => item.rendered && item.navigable), true);
  }
  assert.deepEqual(report.sanitization.excluded, [
    "credentials", "cookies", "provider-resource-ids", "product-ids", "execution-ids", "finding-fingerprints",
    "finding-issue-ids", "finding-occurrence-ids", "locations", "users", "urls", "raw-responses", "evidence",
  ]);
  inspectKeys(report);
  const serialized = JSON.stringify(report);
  for (const pattern of FORBIDDEN_MATERIAL) assert.doesNotMatch(serialized, pattern);
  return { provider: report.provider, outcome: report.summary.outcome, states: report.states.length, clean: report.summary.clean };
}

async function main() {
  const [path] = process.argv.slice(2);
  if (!path) throw new Error("usage: verify-connected-service-lifecycle-report.mjs REPORT.json");
  const report = JSON.parse(await readFile(resolve(process.cwd(), path), "utf8"));
  process.stdout.write(`${JSON.stringify(verifyConnectedServiceLifecycleReport(report), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Connected service lifecycle report verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
