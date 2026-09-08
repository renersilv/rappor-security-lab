#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const RECORD_PATH = "observations/public-external/2026-09-07T235826Z-v0.9.0.json";
const REPORT_PATH = "observations/public-external/2026-09-07T235826Z-v0.9.0.md";
const PROFILE_PATH = "scanner-profiles/public-external-passive.json";

const EXPECTED_APPLICATION = {
  baseUrl: "https://linux-ai2.taile60a95.ts.net:8443",
  publicFlow: "/",
  selectedVisibleVersion: "v0.9.0",
};

const EXPECTED_TARGETS = new Map([
  ["mixed-content", {
    sourceId: "google-firing-range",
    url: "https://public-firing-range.appspot.com/mixedcontent/index.html",
  }],
  ["missing-hsts", {
    sourceId: "google-firing-range",
    url: "https://public-firing-range.appspot.com/stricttransportsecurity/hsts_missing",
  }],
  ["insecure-cookie", {
    sourceId: "google-firing-range",
    url: "https://public-firing-range.appspot.com/leakedcookie/leakedcookie",
  }],
  ["expired-certificate", {
    sourceId: "badssl",
    url: "https://expired.badssl.com/",
  }],
]);

const TOP_LEVEL_KEYS = [
  "$schema",
  "application",
  "benchmarkVersion",
  "disposition",
  "execution",
  "observations",
  "recordedAt",
  "schemaVersion",
  "sources",
];
const APPLICATION_KEYS = ["baseUrl", "publicFlow", "selectedVisibleVersion"];
const EXECUTION_KEYS = ["activeTesting", "authenticated", "interface", "profile", "rulesetDigest", "scope"];
const SOURCE_KEYS = ["evidenceRevision", "evidenceUrl", "id", "operator", "purpose"];
const OBSERVATION_KEYS = [
  "externalObservation",
  "externalState",
  "findingCount",
  "findings",
  "highOrCriticalCount",
  "id",
  "observedAt",
  "operatorSourceId",
  "scenario",
  "status",
  "summary",
  "url",
  "visibleVersion",
];
const FINDING_KEYS = ["category", "confidence", "severity", "title"];
const SEMANTIC_VERSION = /^\d+\.\d+\.\d+$/;
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const REVISION = /^[a-f0-9]{40}$/;
const IDENTIFIER = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const CONFIDENCES = new Set(["low", "moderate", "high"]);
const STATUSES = new Set(["completed", "partial", "failed"]);
const EXTERNAL_STATES = new Set(["available", "changed", "unavailable"]);
const SECRET_MATERIAL = [
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
  /\b(?:authorization|password|secret|token)\s*[:=]\s*\S+/i,
  /\bmy_secret_cookie\b/i,
  /\b(?:scan|trace|correlation)[_-]?id\b/i,
];

function assertExactKeys(value, expected, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true, `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} has unexpected or missing fields`);
}

function assertString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.notEqual(value.length, 0, `${label} must not be empty`);
}

function assertUtc(value, label) {
  assert.match(value, UTC_INSTANT, `${label} must be a UTC instant`);
  assert.equal(Number.isNaN(Date.parse(value)), false, `${label} must be a valid instant`);
}

function countHighOrCritical(findings) {
  return findings.filter((finding) => ["high", "critical"].includes(finding.severity)).length;
}

export async function verifyExternalPublicBaseline(repositoryRoot = REPOSITORY_ROOT) {
  const [recordContent, report, profile] = await Promise.all([
    readFile(resolve(repositoryRoot, RECORD_PATH), "utf8"),
    readFile(resolve(repositoryRoot, REPORT_PATH), "utf8"),
    readFile(resolve(repositoryRoot, PROFILE_PATH)),
  ]);
  const record = JSON.parse(recordContent);
  const profileConfig = JSON.parse(profile);
  const expectedDigest = `sha256:${createHash("sha256").update(profile).digest("hex")}`;

  assertExactKeys(record, TOP_LEVEL_KEYS, "record");
  assert.equal(record.$schema, "../../schemas/public-external-baseline.schema.json");
  assert.match(record.schemaVersion, SEMANTIC_VERSION);
  assert.match(record.benchmarkVersion, SEMANTIC_VERSION);
  assertUtc(record.recordedAt, "record.recordedAt");
  assert.equal(record.disposition, "informational", "external observations must remain informational");

  assertExactKeys(record.application, APPLICATION_KEYS, "record.application");
  assert.deepEqual(record.application, EXPECTED_APPLICATION);

  assertExactKeys(record.execution, EXECUTION_KEYS, "record.execution");
  assert.deepEqual(record.execution, {
    interface: "public-browser-form",
    scope: "passive",
    authenticated: false,
    activeTesting: false,
    profile: "public-external-passive@1",
    rulesetDigest: expectedDigest,
  });
  assert.match(record.execution.rulesetDigest, DIGEST);
  assert.deepEqual(profileConfig, {
    id: "public-external-passive",
    version: 1,
    disposition: "informational",
    execution: {
      interface: "public-browser-form",
      scope: "passive",
      authenticated: false,
      activeTesting: false,
      maxTargets: 4,
    },
    exactUrls: [...EXPECTED_TARGETS.values()].map(({ url }) => url),
  });

  assert.equal(Array.isArray(record.sources), true, "record.sources must be an array");
  const sourceIds = new Set();
  for (const [index, source] of record.sources.entries()) {
    assertExactKeys(source, SOURCE_KEYS, `record.sources[${index}]`);
    assert.match(source.id, IDENTIFIER);
    assert.equal(sourceIds.has(source.id), false, `record.sources[${index}].id is duplicated`);
    sourceIds.add(source.id);
    assertString(source.operator, `record.sources[${index}].operator`);
    assertString(source.purpose, `record.sources[${index}].purpose`);
    assert.equal(new URL(source.evidenceUrl).hostname, "github.com");
    assert.match(source.evidenceRevision, REVISION);
    assert.equal(source.evidenceUrl.includes(source.evidenceRevision), true, "source evidence must pin its revision");
  }

  assert.equal(Array.isArray(record.observations), true, "record.observations must be an array");
  assert.equal(record.observations.length, EXPECTED_TARGETS.size, "the approved four-page set must be captured once");
  assert.ok(record.observations.length <= 4, "external observations must not exceed four exact pages");
  const scenarios = new Set();
  for (const [index, observation] of record.observations.entries()) {
    const label = `record.observations[${index}]`;
    assertExactKeys(observation, OBSERVATION_KEYS, label);
    assert.match(observation.id, IDENTIFIER);
    assert.equal(scenarios.has(observation.scenario), false, `${label}.scenario is duplicated`);
    scenarios.add(observation.scenario);
    const expected = EXPECTED_TARGETS.get(observation.scenario);
    assert.ok(expected, `${label}.scenario is not approved`);
    assert.equal(observation.operatorSourceId, expected.sourceId);
    assert.equal(sourceIds.has(observation.operatorSourceId), true, `${label}.operatorSourceId is unknown`);
    assert.equal(observation.url, expected.url);
    const parsedUrl = new URL(observation.url);
    assert.equal(parsedUrl.search, "", `${label}.url must not contain a query`);
    assert.equal(parsedUrl.hash, "", `${label}.url must not contain a fragment`);
    assertUtc(observation.observedAt, `${label}.observedAt`);
    assert.ok(Date.parse(observation.observedAt) <= Date.parse(record.recordedAt), `${label}.observedAt follows recordedAt`);
    assert.equal(observation.visibleVersion, record.application.selectedVisibleVersion);
    assert.equal(EXTERNAL_STATES.has(observation.externalState), true, `${label}.externalState is invalid`);
    assert.equal(STATUSES.has(observation.status), true, `${label}.status is invalid`);
    assertString(observation.summary, `${label}.summary`);
    assert.equal(Number.isInteger(observation.findingCount) && observation.findingCount >= 0, true);
    assert.equal(Number.isInteger(observation.highOrCriticalCount) && observation.highOrCriticalCount >= 0, true);
    assert.equal(Array.isArray(observation.findings), true, `${label}.findings must be an array`);
    assert.equal(observation.findingCount, observation.findings.length, `${label}.findingCount does not match findings`);
    assert.equal(observation.highOrCriticalCount, countHighOrCritical(observation.findings));
    for (const [findingIndex, finding] of observation.findings.entries()) {
      assertExactKeys(finding, FINDING_KEYS, `${label}.findings[${findingIndex}]`);
      assertString(finding.title, `${label}.findings[${findingIndex}].title`);
      assertString(finding.category, `${label}.findings[${findingIndex}].category`);
      assert.equal(SEVERITIES.has(finding.severity), true, `${label}.findings[${findingIndex}].severity is invalid`);
      assert.equal(CONFIDENCES.has(finding.confidence), true, `${label}.findings[${findingIndex}].confidence is invalid`);
    }
    if (observation.externalState === "available" && observation.status === "completed") {
      assert.equal(observation.externalObservation, null);
    } else {
      assertString(observation.externalObservation, `${label}.externalObservation`);
    }
  }
  assert.deepEqual(scenarios, new Set(EXPECTED_TARGETS.keys()));

  const serialized = `${JSON.stringify(record)}\n${report}`;
  for (const pattern of SECRET_MATERIAL) {
    assert.doesNotMatch(serialized, pattern, `record contains forbidden sensitive or internal material: ${pattern}`);
  }
  assert.doesNotMatch(serialized, /"(?:expectedPresence|classification|verdict|clean|gate)"\s*:/i);
  assert.match(report, /Disposition: \*\*informational only\*\*/);
  assert.match(report, /Visible version: `v0\.9\.0`/);
  assert.match(report, /\| partial \|/);
  for (const { url } of EXPECTED_TARGETS.values()) assert.match(report, new RegExp(url.replaceAll(".", "\\.")));

  return {
    recordPath: RECORD_PATH,
    disposition: record.disposition,
    observations: record.observations.length,
    completed: record.observations.filter((item) => item.status === "completed").length,
    partial: record.observations.filter((item) => item.status === "partial").length,
    failed: record.observations.filter((item) => item.status === "failed").length,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyExternalPublicBaseline()
    .then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`External public baseline verification failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
