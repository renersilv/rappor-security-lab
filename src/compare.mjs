#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const REQUIRED_CASE_FIELDS = [
  "id",
  "targetId",
  "targetRevision",
  "state",
  "scanner",
  "capability",
  "ruleFamily",
  "expectedPresence",
  "expectedSeverity",
  "groupingKey",
  "safeEvidence",
  "fixedCaseId",
  "functionalAssertion",
  "scannerProfile",
  "rulesetDigest",
];

const STATES = new Set(["vulnerable", "partially-fixed", "fixed", "reintroduced"]);
const CONTROLS = new Set(["controlled", "external"]);
const LAYERS = new Set(["code", "public", "connected"]);
const SCANNERS = new Set(["semgrep", "gitleaks", "trivy", "public-scan", "connected-scan"]);
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const RUN_STATUSES = new Set(["completed", "partial", "failed"]);
const IDENTIFIER = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const PRIVILEGES = new Set(["select", "insert", "update", "delete"]);
const POLICY_COMMANDS = new Set(PRIVILEGES);
const POLICY_ROLES = new Set(["anon", "authenticated"]);

function assertObject(value, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
}

function validateAccessControl(accessControl, path) {
  assertObject(accessControl, path);
  if (typeof accessControl.relation !== "string" || !/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/.test(accessControl.relation)) {
    throw new Error(`${path}.relation is invalid`);
  }
  if (typeof accessControl.rlsEnabled !== "boolean") {
    throw new Error(`${path}.rlsEnabled must be boolean`);
  }
  assertObject(accessControl.grants, `${path}.grants`);
  for (const role of POLICY_ROLES) {
    const privileges = accessControl.grants[role];
    if (!Array.isArray(privileges) || new Set(privileges).size !== privileges.length || privileges.some((item) => !PRIVILEGES.has(item))) {
      throw new Error(`${path}.grants.${role} is invalid`);
    }
  }
  if (!Array.isArray(accessControl.policies)) throw new Error(`${path}.policies must be an array`);
  const policyNames = new Set();
  for (const [index, policy] of accessControl.policies.entries()) {
    const policyPath = `${path}.policies[${index}]`;
    assertObject(policy, policyPath);
    if (typeof policy.name !== "string" || !IDENTIFIER.test(policy.name) || policyNames.has(policy.name)) {
      throw new Error(`${policyPath}.name must be unique`);
    }
    if (!POLICY_COMMANDS.has(policy.command)) throw new Error(`${policyPath}.command is invalid`);
    if (!Array.isArray(policy.roles) || policy.roles.length === 0 || new Set(policy.roles).size !== policy.roles.length || policy.roles.some((role) => !POLICY_ROLES.has(role))) {
      throw new Error(`${policyPath}.roles is invalid`);
    }
    for (const field of ["using", "withCheck"]) {
      if (policy[field] !== null && (typeof policy[field] !== "string" || policy[field].length === 0)) {
        throw new Error(`${policyPath}.${field} is invalid`);
      }
    }
    policyNames.add(policy.name);
  }
}

export function validateInputs(manifest, run) {
  assertObject(manifest, "manifest");
  assertObject(run, "run");
  if (typeof manifest.benchmarkVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(manifest.benchmarkVersion)) {
    throw new Error("manifest.benchmarkVersion must be a semantic version");
  }
  if (!Array.isArray(manifest.targets) || manifest.targets.length === 0) {
    throw new Error("manifest.targets must be a non-empty array");
  }
  const targets = new Map();
  for (const [index, target] of manifest.targets.entries()) {
    assertObject(target, `manifest.targets[${index}]`);
    if (typeof target.id !== "string" || !IDENTIFIER.test(target.id) || targets.has(target.id)) {
      throw new Error(`manifest.targets[${index}].id must be unique`);
    }
    if (!CONTROLS.has(target.control)) {
      throw new Error(`manifest.targets[${index}].control is invalid`);
    }
    if (!LAYERS.has(target.layer)) {
      throw new Error(`manifest.targets[${index}].layer is invalid`);
    }
    if (typeof target.revision !== "string" || target.revision.length === 0) {
      throw new Error(`manifest.targets[${index}].revision is required`);
    }
    if ("accessControl" in target) {
      if (target.layer !== "connected") {
        throw new Error(`manifest.targets[${index}].accessControl requires the connected layer`);
      }
      validateAccessControl(target.accessControl, `manifest.targets[${index}].accessControl`);
    }
    targets.set(target.id, target);
  }
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) {
    throw new Error("manifest.cases must be a non-empty array");
  }
  const caseIds = new Set();
  for (const [index, benchmarkCase] of manifest.cases.entries()) {
    assertObject(benchmarkCase, `manifest.cases[${index}]`);
    for (const field of REQUIRED_CASE_FIELDS) {
      if (!(field in benchmarkCase)) {
        throw new Error(`manifest.cases[${index}].${field} is required`);
      }
    }
    if (typeof benchmarkCase.id !== "string" || !IDENTIFIER.test(benchmarkCase.id) || caseIds.has(benchmarkCase.id)) {
      throw new Error(`manifest.cases[${index}].id must be unique`);
    }
    if (!targets.has(benchmarkCase.targetId)) {
      throw new Error(`manifest.cases[${index}].targetId is unknown`);
    }
    if (benchmarkCase.targetRevision !== targets.get(benchmarkCase.targetId).revision) {
      throw new Error(`manifest.cases[${index}].targetRevision must match its target`);
    }
    if (!STATES.has(benchmarkCase.state)) {
      throw new Error(`manifest.cases[${index}].state is invalid`);
    }
    if (!SCANNERS.has(benchmarkCase.scanner)) {
      throw new Error(`manifest.cases[${index}].scanner is invalid`);
    }
    if (typeof benchmarkCase.expectedPresence !== "boolean") {
      throw new Error(`manifest.cases[${index}].expectedPresence must be boolean`);
    }
    if (
      benchmarkCase.expectedSeverity !== null &&
      !SEVERITIES.has(benchmarkCase.expectedSeverity)
    ) {
      throw new Error(`manifest.cases[${index}].expectedSeverity is invalid`);
    }
    if (
      benchmarkCase.groupingKey !== null &&
      (typeof benchmarkCase.groupingKey !== "string" || benchmarkCase.groupingKey.length === 0)
    ) {
      throw new Error(`manifest.cases[${index}].groupingKey is invalid`);
    }
    for (const field of ["capability", "ruleFamily", "safeEvidence", "fixedCaseId", "functionalAssertion", "scannerProfile"]) {
      if (typeof benchmarkCase[field] !== "string" || benchmarkCase[field].length === 0) {
        throw new Error(`manifest.cases[${index}].${field} must be a non-empty string`);
      }
    }
    if (!DIGEST.test(benchmarkCase.rulesetDigest)) {
      throw new Error(`manifest.cases[${index}].rulesetDigest is invalid`);
    }
    caseIds.add(benchmarkCase.id);
  }
  for (const [index, benchmarkCase] of manifest.cases.entries()) {
    if (!caseIds.has(benchmarkCase.fixedCaseId)) {
      throw new Error(`manifest.cases[${index}].fixedCaseId is unknown`);
    }
  }
  if (!RUN_STATUSES.has(run.status)) {
    throw new Error("run.status must be completed, partial or failed");
  }
  if (!Array.isArray(run.observations)) {
    throw new Error("run.observations must be an array");
  }
  const observedCases = new Set();
  for (const [index, observation] of run.observations.entries()) {
    assertObject(observation, `run.observations[${index}]`);
    if (!caseIds.has(observation.caseId)) {
      throw new Error(`run.observations[${index}].caseId is unknown`);
    }
    if (observedCases.has(observation.caseId)) {
      throw new Error(`run.observations[${index}].caseId is duplicated`);
    }
    if (typeof observation.present !== "boolean") {
      throw new Error(`run.observations[${index}].present must be boolean`);
    }
    observedCases.add(observation.caseId);
  }
}

export function compare(manifest, run) {
  validateInputs(manifest, run);
  const targets = new Map(manifest.targets.map((target) => [target.id, target]));
  const observations = new Map(run.observations.map((observation) => [observation.caseId, observation]));
  const complete = run.status === "completed";

  const cases = manifest.cases.map((benchmarkCase) => {
    const target = targets.get(benchmarkCase.targetId);
    const observation = observations.get(benchmarkCase.id);
    let classification = "inconclusive";
    if (complete && observation) {
      if (benchmarkCase.expectedPresence) {
        classification = observation.present ? "true-positive" : "false-negative";
      } else {
        classification = observation.present ? "false-positive" : "true-negative";
      }
    }
    const mismatch = classification === "false-positive" || classification === "false-negative";
    return {
      caseId: benchmarkCase.id,
      targetId: benchmarkCase.targetId,
      targetControl: target.control,
      layer: target.layer,
      scanner: benchmarkCase.scanner,
      state: benchmarkCase.state,
      classification,
      disposition: target.control === "controlled" && (!complete || !observation || mismatch) ? "blocking" : "informational",
    };
  });

  const counts = Object.fromEntries(
    ["true-positive", "false-positive", "true-negative", "false-negative", "inconclusive"].map((name) => [
      name,
      cases.filter((item) => item.classification === name).length,
    ]),
  );
  const blocking = cases.some((item) => item.disposition === "blocking");
  const mismatch = counts["false-positive"] > 0 || counts["false-negative"] > 0;

  return {
    benchmarkVersion: manifest.benchmarkVersion,
    runStatus: run.status,
    verdict: blocking ? "blocked" : complete && !mismatch ? "passed" : "informational",
    clean:
      complete &&
      !blocking &&
      counts["false-positive"] === 0 &&
      counts["false-negative"] === 0 &&
      counts.inconclusive === 0,
    counts,
    cases,
  };
}

export function toMarkdown(report) {
  const lines = [
    "# Benchmark comparison",
    "",
    `- Benchmark version: \`${report.benchmarkVersion}\``,
    `- Run status: \`${report.runStatus}\``,
    `- Verdict: **${report.verdict}**`,
    `- Clean: **${report.clean ? "yes" : "no"}**`,
    "",
    "| Case | Target | Layer | Scanner | State | Classification | Effect |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const item of report.cases) {
    lines.push(`| ${item.caseId} | ${item.targetControl} | ${item.layer} | ${item.scanner} | ${item.state} | ${item.classification} | ${item.disposition} |`);
  }
  lines.push("");
  return lines.join("\n");
}

function parseArguments(arguments_) {
  const [manifestPath, ...remaining] = arguments_;
  if (!manifestPath) {
    throw new Error("usage: compare.mjs <manifest.json> [run.json] [--json path] [--markdown path]");
  }
  const runPath = remaining[0] && !remaining[0].startsWith("--") ? remaining.shift() : undefined;
  const options = remaining;
  const outputs = {};
  for (let index = 0; index < options.length; index += 2) {
    if (!["--json", "--markdown"].includes(options[index]) || !options[index + 1]) {
      throw new Error("output options require --json or --markdown followed by a path");
    }
    outputs[options[index].slice(2)] = options[index + 1];
  }
  return { manifestPath, runPath, outputs };
}

async function main() {
  const { manifestPath, runPath, outputs } = parseArguments(process.argv.slice(2));
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const run = runPath ? JSON.parse(await readFile(runPath, "utf8")) : manifest.exampleRun;
  if (!run) {
    throw new Error("a run file or manifest.exampleRun is required");
  }
  const report = compare(manifest, run);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  const markdown = toMarkdown(report);
  if (outputs.json) await writeFile(outputs.json, json, "utf8");
  if (outputs.markdown) await writeFile(outputs.markdown, markdown, "utf8");
  if (!outputs.json && !outputs.markdown) process.stdout.write(json);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Comparison failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
