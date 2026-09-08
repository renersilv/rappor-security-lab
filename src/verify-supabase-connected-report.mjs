#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { compare } from "./compare.mjs";
import {
  OPERATIONS,
  STATE_ORDER,
  STATES,
} from "../targets/connected/supabase-authorization/lib/states.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const RECORD_PATH = "observations/supabase-connected/2026-09-08T184515Z.json";
const REPORT_PATH = "observations/supabase-connected/2026-09-08T184515Z.md";
const SCHEMA_PATH = "schemas/supabase-connected-report.schema.json";
const MANIFEST_PATH = "manifests/supabase-authorization.json";
const PROFILE_PATH = "scanner-profiles/supabase-connected.json";
const TOP_LEVEL_KEYS = [
  "$schema",
  "benchmarkVersion",
  "cleanup",
  "execution",
  "laboratory",
  "recordedAt",
  "sanitization",
  "schemaVersion",
  "states",
  "summary",
  "target",
];
const STATE_KEYS = ["access", "cases", "runStatus", "state", "targetId", "targetRevision"];
const CASE_KEYS = ["caseId", "classification", "present"];
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const FORBIDDEN_KEYS = new Set([
  "accessToken",
  "email",
  "password",
  "pgService",
  "projectId",
  "projectRef",
  "projectReference",
  "projectUrl",
  "publishableKey",
  "responseBody",
  "row",
  "rowContent",
  "rowIdentifier",
  "rows",
  "secretKey",
  "serviceRoleKey",
  "url",
]);
const FORBIDDEN_MATERIAL = [
  /https:\/\/[a-z0-9-]+\.supabase\.co/i,
  /\bsb_(?:publishable|secret)_[A-Za-z0-9._-]+/,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /postgres(?:ql)?:\/\//i,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /\b(?:password|secret|token)\s*[:=]\s*\S+/i,
];

function digest(content) {
  return "sha256:" + createHash("sha256").update(content).digest("hex");
}

function assertExactKeys(value, expected, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true, label + " must be an object");
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), label + " has unexpected or missing fields");
}

function inspectKeys(value, path = "report") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspectKeys(item, path + "[" + index + "]"));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert.equal(FORBIDDEN_KEYS.has(key), false, path + "." + key + " retains forbidden sensitive material");
    inspectKeys(child, path + "." + key);
  }
}

export async function verifySupabaseConnectedReport(repositoryRoot = REPOSITORY_ROOT) {
  const [recordContent, markdown, schemaContent, manifestContent, profileContent] = await Promise.all([
    readFile(resolve(repositoryRoot, RECORD_PATH), "utf8"),
    readFile(resolve(repositoryRoot, REPORT_PATH), "utf8"),
    readFile(resolve(repositoryRoot, SCHEMA_PATH), "utf8"),
    readFile(resolve(repositoryRoot, MANIFEST_PATH), "utf8"),
    readFile(resolve(repositoryRoot, PROFILE_PATH), "utf8"),
  ]);
  const report = JSON.parse(recordContent);
  const schema = JSON.parse(schemaContent);
  const manifest = JSON.parse(manifestContent);
  const profile = JSON.parse(profileContent);

  assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(schema.additionalProperties, false);
  assertExactKeys(report, TOP_LEVEL_KEYS, "report");
  assert.equal(report.$schema, "../../schemas/supabase-connected-report.schema.json");
  assert.equal(report.schemaVersion, "1.0.0");
  assert.equal(report.benchmarkVersion, manifest.benchmarkVersion);
  assert.match(report.recordedAt, UTC_INSTANT);
  assert.equal(Number.isNaN(Date.parse(report.recordedAt)), false);
  assert.deepEqual(report.laboratory, {
    version: "0.0.0",
    sourceCommit: "00f02b4885b09101de39b327c55a57138ea3773e",
  });
  assert.match(report.laboratory.sourceCommit, /^[a-f0-9]{40}$/);

  assert.deepEqual(report.target, {
    control: "controlled",
    layer: "connected",
    provider: "supabase",
    resource: "disposable-laboratory-project",
    relation: "public.rappor_lab_documents",
    data: "generated-dummy-only",
  });
  assert.deepEqual(report.execution, {
    interface: "data-api-and-postgresql",
    scope: "active-owner-authorized",
    authenticated: true,
    activeTesting: true,
    profile: profile.id + "@" + profile.version,
    rulesetDigest: digest(profileContent),
    actors: profile.actors,
    operations: profile.operations.map((operation) => operation.name),
  });
  assert.match(report.execution.rulesetDigest, DIGEST);
  assert.deepEqual(profile.credentials, {
    client: "publishable-key",
    administrative: "external-pg-service",
  });
  assert.equal(profile.report.responseBodies, false);
  assert.equal(profile.report.credentials, false);
  assert.equal(profile.report.rowIdentifiers, false);

  assert.equal(report.states.length, STATE_ORDER.length);
  assert.deepEqual(report.states.map((state) => state.state), STATE_ORDER);
  const targets = new Map(manifest.targets.map((target) => [target.id, target]));
  const manifestCases = new Map(manifest.cases.map((benchmarkCase) => [benchmarkCase.id, benchmarkCase]));
  const observations = [];
  const observedCaseIds = new Set();

  for (const [stateIndex, state] of report.states.entries()) {
    const stateLabel = "report.states[" + stateIndex + "]";
    assertExactKeys(state, STATE_KEYS, stateLabel);
    assert.equal(state.targetId, "supabase-authorization-" + state.state);
    const target = targets.get(state.targetId);
    assert.ok(target, stateLabel + ".targetId is not in the manifest");
    assert.equal(state.targetRevision, target.revision);
    assert.match(state.targetRevision, DIGEST);
    assert.equal(state.runStatus, "completed");
    assert.deepEqual(target.accessControl, STATES[state.state].accessControl);
    assert.equal(state.cases.length, Object.keys(OPERATIONS).length);

    const observedAccess = {
      anon: { read: false, write: false },
      authenticated: { read: false, write: false },
    };
    for (const [caseIndex, observedCase] of state.cases.entries()) {
      const caseLabel = stateLabel + ".cases[" + caseIndex + "]";
      assertExactKeys(observedCase, CASE_KEYS, caseLabel);
      assert.equal(observedCaseIds.has(observedCase.caseId), false, observedCase.caseId + " is duplicated");
      observedCaseIds.add(observedCase.caseId);
      const benchmarkCase = manifestCases.get(observedCase.caseId);
      assert.ok(benchmarkCase, observedCase.caseId + " is not in the manifest");
      assert.equal(benchmarkCase.state, state.state);
      const operation = Object.values(OPERATIONS).find(
        (candidate) => observedCase.caseId === "supabase-" + candidate.id + "-" + state.state,
      );
      assert.ok(operation, observedCase.caseId + " does not map to a declared operation");
      observedAccess[operation.actor][operation.operation] = operation.presentWhenAllowed
        ? observedCase.present
        : !observedCase.present;
      observations.push({ caseId: observedCase.caseId, present: observedCase.present });
    }
    assert.deepEqual(state.access, observedAccess);
    assert.deepEqual(state.access, STATES[state.state].expectedAccess);
  }

  assert.equal(observedCaseIds.size, manifest.cases.length);
  const comparison = compare(manifest, {
    status: report.summary.runStatus,
    observations,
  });
  for (const state of report.states) {
    for (const observedCase of state.cases) {
      const comparedCase = comparison.cases.find((item) => item.caseId === observedCase.caseId);
      assert.equal(observedCase.classification, comparedCase.classification);
    }
  }
  assert.deepEqual(report.summary, {
    runStatus: comparison.runStatus,
    verdict: comparison.verdict,
    clean: comparison.clean,
    counts: comparison.counts,
  });
  assert.deepEqual(report.summary.counts, {
    "true-positive": 5,
    "false-positive": 0,
    "true-negative": 11,
    "false-negative": 0,
    inconclusive: 0,
  });

  assert.deepEqual(report.cleanup, {
    status: "completed",
    reset: true,
    relation: "public.rappor_lab_documents",
    relationAbsent: true,
    projectDisposition: "retained-empty-per-owner-authorization",
  });
  assert.deepEqual(report.sanitization, {
    retained: [
      "state-revisions",
      "boolean-access-results",
      "case-classifications",
      "aggregate-counts",
      "reset-confirmation",
    ],
    excluded: [
      "project-url",
      "project-reference",
      "credentials",
      "user-identifier",
      "row-content",
      "row-identifier",
      "response-body",
    ],
  });

  inspectKeys(report);
  const serialized = recordContent + "\n" + markdown;
  for (const pattern of FORBIDDEN_MATERIAL) {
    assert.doesNotMatch(serialized, pattern, "report contains forbidden sensitive material: " + pattern);
  }
  assert.match(markdown, /Run status: \*\*completed\*\*/);
  assert.match(markdown, /Verdict: \*\*passed\*\*/);
  assert.match(markdown, /Clean: \*\*yes\*\*/);
  assert.match(markdown, /5 true positives, 11 true negatives, 0 false positives/);
  assert.match(markdown, /independent idempotent reset/);
  assert.match(markdown, /retained empty rather than deleted/);
  for (const stateName of STATE_ORDER) {
    assert.match(markdown, new RegExp("\\| " + stateName.replace("-", "\\-") + " \\|"));
  }

  return {
    recordPath: RECORD_PATH,
    status: report.summary.runStatus,
    verdict: report.summary.verdict,
    states: report.states.length,
    cases: observedCaseIds.size,
    reset: report.cleanup.relationAbsent,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifySupabaseConnectedReport()
    .then((result) => process.stdout.write(JSON.stringify(result, null, 2) + "\n"))
    .catch((error) => {
      process.stderr.write("Connected Supabase report verification failed: " + error.message + "\n");
      process.exitCode = 1;
    });
}
