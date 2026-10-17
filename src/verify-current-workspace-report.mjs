#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const COMMIT = /^[a-f0-9]{40}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u;
const FORBIDDEN_KEYS = new Set([
  "agentId", "authorizationId", "computerId", "credential", "email", "operationId", "password",
  "path", "productId", "requestId", "token", "url",
]);
const FORBIDDEN_MATERIAL = [
  /(?:^|[\s"'])\/home\//iu,
  /[A-Z]:\\Users\\/iu,
  /@[A-Z0-9.-]+\.[A-Z]{2,}/iu,
  /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/iu,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/u,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/u,
  /taile[0-9a-f]+\.ts\.net/iu,
];

function exactKeys(value, keys, label) {
  assert.equal(value !== null && typeof value === "object" && !Array.isArray(value), true,
    `${label} must be an object`);
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

export function verifyCurrentWorkspaceReport(report, markdown = "") {
  exactKeys(report, ["$schema", "schemaVersion", "recordedAt", "issue", "status", "verdict", "candidate",
    "authorization", "preparation", "execution", "analysis", "workspace", "acceptance", "unmetCriteria",
    "sanitization"], "report");
  assert.equal(report.$schema, "../../schemas/current-workspace-report.schema.json");
  assert.equal(report.schemaVersion, "1.0.0");
  assert.match(report.recordedAt, UTC_INSTANT);
  assert.equal(Number.isNaN(Date.parse(report.recordedAt)), false);
  assert.equal(report.issue, 19);
  assert.equal(report.status, "partial");
  assert.equal(report.verdict, "inconclusive");

  exactKeys(report.candidate, ["visibleVersion", "publicClientSourceRevision", "linuxClientProtocolVersion",
    "linuxClientArchiveSha256", "agentProtocolVersion"], "candidate");
  assert.equal(report.candidate.visibleVersion, "v0.79.0");
  assert.match(report.candidate.publicClientSourceRevision, COMMIT);
  assert.equal(report.candidate.publicClientSourceRevision, "1c6412c0e813f4a3f95b125871b4338b6f168356");
  assert.equal(report.candidate.linuxClientProtocolVersion, 1);
  assert.match(report.candidate.linuxClientArchiveSha256, HASH);
  assert.equal(report.candidate.linuxClientArchiveSha256,
    "9fd7775aacb84fcfd9d638a61397119389757fce1b4e7b02502476054b2f0ed5");
  assert.equal(report.candidate.agentProtocolVersion, 7);

  assert.deepEqual(report.authorization, {
    originalMaximumStarts: 4,
    extensionMaximumStarts: 5,
    maximumCliLinuxStarts: 3,
    reservedIdeWindowsStarts: 2,
    consumedStarts: 3,
    cliLinuxStarts: 3,
    ideWindowsStarts: 0,
    active: false,
    extensionActivated: true,
    limitSeconds: 600,
    priorOutcomes: ["needs-owner-action", "needs-owner-action"],
    currentOutcome: "needs-owner-action",
  });
  assert.deepEqual(report.preparation, {
    kind: "assisted",
    inferenceStarts: 0,
    clientInstalled: true,
    computerApproved: true,
    computerOnline: true,
    scannerCount: 3,
    capabilities: ["source.current-workspace.v1", "source.local-folder.v1"],
    initiallyRegisteredWorkspaceCount: 0,
    folderConsentGrantedBeforeRun: false,
    oauthRefreshPersistenceVerified: true,
  });

  exactKeys(report.execution, ["clientPath", "attemptSequence", "durationMs", "shortNaturalPrompt",
    "preflightToolCount", "automaticReviewCount", "automaticReviewsApproved", "rawOutputRetained", "outcome",
    "stopCategory", "modelObservedFirstUse"], "execution");
  assert.equal(report.execution.clientPath, "host-codex-linux-client");
  assert.equal(report.execution.attemptSequence, 3);
  assert.equal(Number.isInteger(report.execution.durationMs) && report.execution.durationMs >= 0 &&
    report.execution.durationMs <= 600000, true);
  assert.equal(report.execution.durationMs, 141841);
  assert.equal(report.execution.shortNaturalPrompt, true);
  assert.equal(report.execution.preflightToolCount, 32);
  assert.equal(report.execution.automaticReviewCount, 10);
  assert.equal(report.execution.automaticReviewsApproved, true);
  assert.equal(report.execution.rawOutputRetained, false);
  assert.equal(report.execution.outcome, "needs-owner-action");
  assert.equal(report.execution.stopCategory, "native-folder-consent-required");
  assert.deepEqual(report.execution.modelObservedFirstUse, {
    catalogInitiallyEmpty: false,
    productReused: true,
    clientDiscovered: true,
    clientInstalled: true,
    computerApproved: true,
    exactComputerSelected: true,
    folderConsented: false,
    typedRecoveryObserved: false,
    noSecretExposed: true,
  });

  exactKeys(report.analysis, ["baseline", "guidanceRead", "remediationApplied",
    "functionalTestsAfterRemediationPassed", "rerun", "webComparison", "scanners"], "analysis");
  assert.deepEqual(report.analysis.baseline, {
    completed: false, scoreAvailable: false, findingCount: 0, coverageComplete: false, historyObserved: false,
  });
  assert.equal(report.analysis.guidanceRead, false);
  assert.equal(report.analysis.remediationApplied, false);
  assert.equal(report.analysis.functionalTestsAfterRemediationPassed, false);
  assert.deepEqual(report.analysis.rerun, {
    completed: false, scoreAvailable: false, findingCount: null, coverageComplete: false, historyObserved: false,
  });
  assert.deepEqual(report.analysis.webComparison, {
    rendered: false, scoreMatched: false, findingsMatched: false, coverageMatched: false, historyMatched: false,
  });
  assert.deepEqual(report.analysis.scanners, []);

  exactKeys(report.workspace, ["beforeRevision", "afterRevision", "functionalAssertionPassed", "detections"],
    "workspace");
  assert.match(report.workspace.beforeRevision, DIGEST);
  assert.equal(report.workspace.beforeRevision,
    "sha256:c840f07f3271d47515b8677ce1efcb1ba3e962b7e27bac9cde3c11ac0443bae4");
  assert.equal(report.workspace.afterRevision, report.workspace.beforeRevision);
  assert.equal(report.workspace.functionalAssertionPassed, true);
  assert.deepEqual(report.workspace.detections, { semgrep: true, gitleaks: true, trivy: true });
  assert.deepEqual(report.acceptance, {
    assistedPreparationSeparated: true,
    autonomousFirstUseProven: false,
    exactComputerSelectionObserved: true,
    nativeFolderConsentProven: false,
    baselineProven: false,
    remediationProven: false,
    comparableRerunProven: false,
    ideWindowsProven: false,
    partialRunTreatedAsClean: false,
  });
  assert.deepEqual(report.unmetCriteria, [
    "autonomous-first-use", "native-folder-consent", "cli-baseline", "cli-guidance", "cli-remediation",
    "cli-functional-after-remediation", "cli-rerun", "cli-web-comparison", "ide-windows-journey",
  ]);
  assert.deepEqual(report.sanitization, {
    retained: ["candidate-pins", "bounded-consumption-counts", "boolean-outcomes", "duration", "review-count",
      "workspace-revisions", "independent-detections", "unmet-criteria"],
    excluded: ["credentials", "authorization-values", "computer-identifiers", "operation-identifiers",
      "personal-paths", "source-code", "raw-tool-responses", "scanner-output", "setup-logs"],
  });

  inspectKeys(report);
  const serialized = `${JSON.stringify(report)}\n${markdown}`;
  for (const pattern of FORBIDDEN_MATERIAL) assert.doesNotMatch(serialized, pattern);
  if (markdown) {
    assert.match(markdown, /Status: \*\*partial\*\*/u);
    assert.match(markdown, /Verdict: \*\*inconclusive\*\*/u);
    assert.match(markdown, /Bounded attempt: `3\/5` globally and `3\/3` for CLI\/Linux/u);
    assert.match(markdown, /IDE\/Windows starts preserved: \*\*2\*\*/u);
    assert.match(markdown, /stopped for native folder consent/u);
    assert.match(markdown, /No baseline analysis started/u);
    assert.match(markdown, /not clean and cannot\s+support a remediation claim/u);
  }
  return { status: "partial", verdict: "inconclusive", consumedStarts: 3, remainingIdeWindowsStarts: 2,
    clean: false };
}

async function main() {
  const [jsonPath, markdownPath] = process.argv.slice(2);
  if (jsonPath) {
    const report = JSON.parse(await readFile(resolve(process.cwd(), jsonPath), "utf8"));
    const markdown = markdownPath ? await readFile(resolve(process.cwd(), markdownPath), "utf8") : "";
    process.stdout.write(`${JSON.stringify(verifyCurrentWorkspaceReport(report, markdown), null, 2)}\n`);
    return;
  }
  const directory = resolve(process.cwd(), "observations", "current-workspace");
  const names = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
  if (names.length === 0) throw new Error("no current workspace observations were found");
  const results = [];
  for (const name of names) {
    const base = name.slice(0, -5);
    const [json, markdown] = await Promise.all([
      readFile(resolve(directory, name), "utf8"),
      readFile(resolve(directory, `${base}.md`), "utf8"),
    ]);
    results.push(verifyCurrentWorkspaceReport(JSON.parse(json), markdown));
  }
  process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Current workspace report verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
