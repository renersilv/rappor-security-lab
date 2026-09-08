#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const RECORD_PATH = "observations/public-controlled/2026-09-08T181522Z-v0.10.0.json";
const REPORT_PATH = "observations/public-controlled/2026-09-08T181522Z-v0.10.0.md";
const MANIFEST_PATH = "manifests/public-vibe-coding.json";
const PROFILE_PATH = "scanner-profiles/rappor-public-black-box.json";
const STATES = ["vulnerable", "partially-fixed", "fixed", "reintroduced"];
const CLASSIFICATIONS = ["true-positive", "false-positive", "true-negative", "false-negative", "inconclusive"];
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = new Set([
  "accessToken",
  "statusUrl",
  "scanId",
  "failureReason",
  "maskedEvidence",
  "remediation",
  "evidence",
  "title",
]);
const FORBIDDEN_MATERIAL = [
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_[A-Z0-9]+/,
  /\b(?:authorization|password|secret|token)\s*[:=]\s*\S+/i,
  /\b(?:scan|trace|correlation)[_-]?id\b/i,
];

function digest(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function assertUtc(value, label) {
  assert.match(value, UTC_INSTANT, `${label} must be a UTC instant`);
  assert.equal(Number.isNaN(Date.parse(value)), false, `${label} must be a valid instant`);
}

function inspectKeys(value, path = "report") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspectKeys(item, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert.equal(FORBIDDEN_KEYS.has(key), false, `${path}.${key} retains forbidden raw response material`);
    inspectKeys(child, `${path}.${key}`);
  }
}

function countsFor(scans) {
  return Object.fromEntries(CLASSIFICATIONS.map((classification) => [
    classification,
    scans.flatMap((scan) => scan.observations).filter((item) => item.classification === classification).length,
  ]));
}

export async function verifyPublicBlackBoxReport(repositoryRoot = REPOSITORY_ROOT) {
  const [recordContent, markdown, manifestContent, profileContent, schemaContent] = await Promise.all([
    readFile(resolve(repositoryRoot, RECORD_PATH), "utf8"),
    readFile(resolve(repositoryRoot, REPORT_PATH), "utf8"),
    readFile(resolve(repositoryRoot, MANIFEST_PATH), "utf8"),
    readFile(resolve(repositoryRoot, PROFILE_PATH), "utf8"),
    readFile(resolve(repositoryRoot, "schemas/public-black-box-report.schema.json"), "utf8"),
  ]);
  const report = JSON.parse(recordContent);
  const manifest = JSON.parse(manifestContent);
  const profile = JSON.parse(profileContent);
  const schema = JSON.parse(schemaContent);

  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual(profile.application, {
    baseUrl: "https://linux-ai2.taile60a95.ts.net:8443",
    publicFlow: "/",
    selectedVisibleVersion: "v0.9.0",
    createPath: "/api/public/v1/scans",
    contractVersion: "v1",
    responsibleUseTermsVersion: "2026-08-20.v1",
  });
  assert.equal(profile.targetSourceCommit, "71b2e58eba0c5c4f0a1facf4497ed6f494d4fc0b");
  assert.deepEqual(profile.targets, {
    vulnerable: "https://rappor-lab-vulnerable.vercel.app",
    "partially-fixed": "https://rappor-lab-partially-fixed.vercel.app",
    fixed: "https://rappor-lab-fixed.vercel.app",
    reintroduced: "https://rappor-lab-reintroduced.vercel.app",
  });
  assert.deepEqual(
    new Set(profile.mappings.map((item) => item.ruleFamily)),
    new Set(manifest.cases.map((item) => item.ruleFamily)),
  );
  assert.equal(report.$schema, "../../schemas/public-black-box-report.schema.json");
  assert.equal(report.schemaVersion, "1.0.0");
  assert.equal(report.benchmarkVersion, manifest.benchmarkVersion);
  assertUtc(report.recordedAt, "report.recordedAt");
  assert.deepEqual(report.laboratory, {
    version: "0.0.0",
    targetSourceCommit: profile.targetSourceCommit,
  });
  assert.match(report.laboratory.targetSourceCommit, /^[a-f0-9]{40}$/);

  assert.deepEqual(report.application, {
    baseUrl: profile.application.baseUrl,
    publicFlow: profile.application.publicFlow,
    selectedVisibleVersion: "v0.9.0",
    observedVisibleVersion: "v0.10.0",
    visibleVersionMatches: false,
    createPath: "/api/public/v1/scans",
    createMethod: "POST",
    contractVersion: "v1",
    responsibleUseTermsVersion: "2026-08-20.v1",
    clientContractExposed: true,
  });
  assert.deepEqual(report.execution, {
    interface: "public-http-contract",
    scope: "passive",
    authenticated: false,
    activeTesting: false,
    groundTruthProfile: "public-passive@2",
    groundTruthRulesetDigest: manifest.cases[0].rulesetDigest,
    mappingProfile: `${profile.id}@${profile.version}`,
    mappingProfileDigest: digest(profileContent),
  });
  assert.match(report.execution.groundTruthRulesetDigest, DIGEST);
  assert.match(report.execution.mappingProfileDigest, DIGEST);

  assert.equal(report.scans.length, 4);
  assert.deepEqual(report.scans.map((scan) => scan.state), STATES);
  const targetById = new Map(manifest.targets.map((target) => [target.id, target]));
  const caseById = new Map(manifest.cases.map((item) => [item.id, item]));
  const observedCaseIds = new Set();
  const expectedFindingCounts = new Map([
    ["vulnerable", 5],
    ["partially-fixed", 2],
    ["fixed", 0],
    ["reintroduced", 5],
  ]);
  for (const scan of report.scans) {
    const target = targetById.get(scan.targetId);
    assert.ok(target, `${scan.state} target is not in the manifest`);
    assert.equal(target.id, `public-vibe-coding-${scan.state}`);
    assert.equal(scan.targetRevision, target.revision);
    assert.equal(scan.url, profile.targets[scan.state]);
    assertUtc(scan.observedAt, `${scan.state}.observedAt`);
    assert.ok(Date.parse(scan.observedAt) <= Date.parse(report.recordedAt));
    assert.equal(scan.productStatus, "completed");
    assert.equal(scan.coverageStatus, "partial");
    assert.equal(scan.runStatus, "partial");
    assert.equal(scan.findingCount, expectedFindingCounts.get(scan.state));
    assert.equal(scan.signalCount, 10);
    assert.equal(scan.uniqueSignalCount, 4);
    assert.deepEqual(scan.score, { exposed: false, value: null, status: "not-exposed" });
    assert.equal(scan.observations.length, 10);
    for (const observation of scan.observations) {
      const expected = caseById.get(observation.caseId);
      assert.ok(expected, `${observation.caseId} is not in the manifest`);
      assert.equal(expected.targetId, scan.targetId);
      assert.equal(observation.ruleFamily, expected.ruleFamily);
      assert.equal(observation.expectedPresence, expected.expectedPresence);
      assert.equal(observation.expectedSeverity, expected.expectedSeverity);
      assert.equal(observation.expectedGroupingKey, expected.groupingKey);
      assert.equal(observation.classification, "inconclusive");
      assert.equal(observedCaseIds.has(observation.caseId), false, `${observation.caseId} is duplicated`);
      observedCaseIds.add(observation.caseId);
    }
    for (const item of scan.unmappedProductItems) {
      assert.match(item.identifier, /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/);
      assert.equal(["finding", "signal"].includes(item.channel), true);
    }
  }
  assert.equal(observedCaseIds.size, manifest.cases.length);

  const calculatedCounts = countsFor(report.scans);
  assert.deepEqual(report.summary, {
    runStatus: "partial",
    verdict: "blocked",
    clean: false,
    counts: calculatedCounts,
    discrepancyCount: report.discrepancies.length,
  });
  assert.deepEqual(calculatedCounts, {
    "true-positive": 0,
    "false-positive": 0,
    "true-negative": 0,
    "false-negative": 0,
    inconclusive: 40,
  });
  assert.deepEqual(report.dimensions, {
    detection: { status: "inconclusive", counts: calculatedCounts },
    normalization: { status: "mismatch", evaluated: 26, mismatches: 5 },
    grouping: { status: "not-exposed", expected: 26, exposed: 0 },
    score: { status: "not-exposed", exposed: 0, total: 4 },
    lifecycle: { status: "inconclusive", matched: 0, mismatches: 0, inconclusive: 10 },
    presentation: { status: "passed", available: 26, complete: 26 },
  });
  assert.equal(report.lifecycle.length, 10);
  assert.ok(report.lifecycle.every((item) => item.status === "inconclusive"));
  assert.ok(report.lifecycle.every((item) => item.states.map((state) => state.state).join(",") === STATES.join(",")));

  const discrepancyIds = new Set(report.discrepancies.map((item) => item.id));
  assert.equal(discrepancyIds.size, report.discrepancies.length);
  for (const id of [
    "deployment-visible-version",
    "coverage-vulnerable",
    "coverage-partially-fixed",
    "coverage-fixed",
    "coverage-reintroduced",
    "lifecycle-not-proven",
    "grouping-not-exposed",
    "score-not-exposed",
  ]) {
    assert.equal(discrepancyIds.has(id), true, `missing discrepancy ${id}`);
  }
  assert.equal(report.discrepancies.filter((item) => item.dimension === "normalization").length, 5);
  for (const discrepancy of report.discrepancies) {
    assert.ok(discrepancy.reproductionSteps.length >= 3);
    assert.ok(discrepancy.expected.length > 0);
    assert.ok(discrepancy.observed.length > 0);
    assert.ok(discrepancy.sanitizedEvidence.length > 0);
    for (const caseId of discrepancy.caseIds) assert.equal(caseById.has(caseId), true, `${caseId} is not a manifest case`);
  }

  inspectKeys(report);
  const serialized = `${recordContent}\n${markdown}`;
  for (const pattern of FORBIDDEN_MATERIAL) {
    assert.doesNotMatch(serialized, pattern, `report contains forbidden sensitive or internal material: ${pattern}`);
  }
  assert.match(markdown, /Selected visible version: `v0\.9\.0`/);
  assert.match(markdown, /Observed visible version: `v0\.10\.0`/);
  assert.match(markdown, /Overall status: \*\*partial\*\*/);
  assert.match(markdown, /Verdict: \*\*blocked\*\*/);
  for (const state of STATES) assert.match(markdown, new RegExp(`\\| ${state.replace("-", "\\-")} \\|`));
  assert.match(markdown, /Raw response bodies.*were discarded/);

  return {
    recordPath: RECORD_PATH,
    status: report.summary.runStatus,
    verdict: report.summary.verdict,
    scans: report.scans.length,
    cases: observedCaseIds.size,
    discrepancies: report.discrepancies.length,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyPublicBlackBoxReport()
    .then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`Public black-box report verification failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
