#!/usr/bin/env node

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { compare } from "./compare.mjs";
import { buildProviderConfigurationManifest } from "./generate-provider-configuration-manifest.mjs";
import { STATE_ORDER } from "../targets/connected/provider-configuration/lib/states.mjs";

const IDENTIFIER = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const FORBIDDEN_KEYS = new Set([
  "accountId", "accessToken", "email", "password", "projectId", "projectRef", "projectUrl",
  "publishableKey", "rawResponse", "responseBody", "row", "rows", "secret", "token", "url",
]);
const FORBIDDEN_MATERIAL = [
  /https:\/\/[a-z0-9-]+\.supabase\.co/i,
  /\bsb_(?:publishable|secret)_[A-Za-z0-9._-]+/,
  /\bprj_[A-Za-z0-9_-]+/,
  /\bteam_[A-Za-z0-9_-]+/,
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /postgres(?:ql)?:\/\//i,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
];

function assertExactKeys(value, keys, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true, `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label} fields changed`);
}

function inspectKeys(value, path = "report") {
  if (Array.isArray(value)) return value.forEach((item, index) => inspectKeys(item, `${path}[${index}]`));
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert.equal(FORBIDDEN_KEYS.has(key), false, `${path}.${key} retains forbidden provider material`);
    inspectKeys(child, `${path}.${key}`);
  }
}

export async function verifyProviderConfigurationReport(report, markdown = "", repositoryRoot) {
  const manifest = await buildProviderConfigurationManifest(repositoryRoot);
  assertExactKeys(report, [
    "$schema", "schemaVersion", "benchmarkVersion", "recordedAt", "laboratory", "provider",
    "execution", "summary", "states", "cleanup", "sanitization",
  ], "report");
  assert.equal(report.$schema, "../../schemas/provider-configuration-report.schema.json");
  assert.equal(report.schemaVersion, "1.0.0");
  assert.equal(report.benchmarkVersion, manifest.benchmarkVersion);
  assert.match(report.recordedAt, UTC_INSTANT);
  assert.equal(Number.isNaN(Date.parse(report.recordedAt)), false);
  assert.match(report.laboratory.sourceCommit, /^[a-f0-9]{40}$/);
  assert.equal(report.laboratory.version, "0.0.0");
  assert.ok(new Set(["supabase", "vercel"]).has(report.provider));
  assert.deepEqual(report.states.map((state) => state.state), STATE_ORDER);
  assert.equal(report.execution.rawProviderResponseRetained, false);
  assert.equal(report.execution.scope, "active-owner-authorized");
  assert.equal(report.execution.interface, report.provider === "supabase" ? "postgresql-catalog-and-data-api" : "vercel-rest-api-v9");

  const prefix = `${report.provider}-`;
  const selectedCases = manifest.cases.filter((item) => item.id.startsWith(prefix));
  const selectedTargetIds = new Set(selectedCases.map((item) => item.targetId));
  const selectedManifest = {
    benchmarkVersion: manifest.benchmarkVersion,
    targets: manifest.targets.filter((item) => selectedTargetIds.has(item.id)),
    cases: selectedCases,
  };
  const expectedCases = new Map(selectedCases.map((item) => [item.id, item]));
  const observed = [];
  for (const state of report.states) {
    assert.match(state.targetRevision, DIGEST);
    if (report.provider === "supabase") assert.equal(state.authorizationChecks, 4);
    else assert.equal("authorizationChecks" in state, false);
    for (const item of state.cases) {
      assert.match(item.caseId, IDENTIFIER);
      assert.equal(expectedCases.get(item.caseId)?.state, state.state);
      assert.equal(typeof item.present, "boolean");
      assert.ok(new Set(["true-positive", "true-negative"]).has(item.classification));
      observed.push({ caseId: item.caseId, present: item.present });
    }
  }
  assert.equal(observed.length, selectedCases.length);
  const comparison = compare(selectedManifest, { status: "completed", observations: observed });
  assert.deepEqual(report.summary, {
    runStatus: comparison.runStatus,
    verdict: comparison.verdict,
    clean: comparison.clean,
    counts: comparison.counts,
  });
  assert.equal(report.summary.clean, true);

  if (report.provider === "supabase") {
    assert.deepEqual(report.cleanup, {
      authorizationRelationAbsent: true,
      configurationObjectsAbsent: true,
      bucketAbsent: true,
      bucketPolicyAbsent: true,
    });
  } else {
    assert.deepEqual(report.cleanup, {
      gitForkProtection: true,
      projectsRestored: 4,
      verified: true,
    });
  }
  assert.deepEqual(report.sanitization.excluded, [
    "credentials", "provider-resource-ids", "project-references", "users", "rows", "logs", "source-code", "raw-responses",
  ]);
  inspectKeys(report);
  const serialized = `${JSON.stringify(report)}\n${markdown}`;
  for (const pattern of FORBIDDEN_MATERIAL) assert.doesNotMatch(serialized, pattern);
  if (markdown) {
    assert.match(markdown, /Run status: \*\*completed\*\*/);
    assert.match(markdown, /Verdict: \*\*passed\*\*/);
    assert.match(markdown, /Cleanup verified: \*\*yes\*\*/);
  }
  return { provider: report.provider, states: report.states.length, cases: observed.length, clean: true };
}

async function main() {
  const [jsonPath, markdownPath] = process.argv.slice(2);
  if (jsonPath) {
    const report = JSON.parse(await readFile(resolve(process.cwd(), jsonPath), "utf8"));
    const markdown = markdownPath ? await readFile(resolve(process.cwd(), markdownPath), "utf8") : "";
    process.stdout.write(`${JSON.stringify(await verifyProviderConfigurationReport(report, markdown), null, 2)}\n`);
    return;
  }
  const directory = resolve(process.cwd(), "observations", "provider-configuration");
  const files = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
  if (files.length === 0) throw new Error("no provider configuration observations were found");
  const results = [];
  for (const name of files) {
    const base = name.slice(0, -5);
    const [record, markdown] = await Promise.all([
      readFile(resolve(directory, name), "utf8"),
      readFile(resolve(directory, `${base}.md`), "utf8"),
    ]);
    results.push(await verifyProviderConfigurationReport(JSON.parse(record), markdown));
  }
  process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Provider configuration report verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
