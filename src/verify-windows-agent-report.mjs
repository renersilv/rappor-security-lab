#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const COMMIT = /^[a-f0-9]{40}$/u;
const HASH = /^[a-f0-9]{64}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;
const UTC_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u;
const FORBIDDEN_KEYS = new Set([
  "agentId", "computerId", "credential", "email", "operationId", "password", "path", "requestId", "token", "url",
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

function passedStep(value, label) {
  exactKeys(value, ["passed", "durationMs"], label);
  assert.equal(value.passed, true);
  assert.equal(Number.isInteger(value.durationMs) && value.durationMs >= 0, true);
}

export async function verifyWindowsAgentReport(report, markdown = "") {
  exactKeys(report, [
    "$schema", "schemaVersion", "recordedAt", "laboratory", "execution", "delivery", "runtimeDelivery", "aiEvidence", "environment",
    "preflight", "lifecycle", "failures", "analyses", "cleanup", "sanitization",
  ], "report");
  assert.equal(report.$schema, "../../schemas/windows-agent-report.schema.json");
  assert.equal(report.schemaVersion, "2.0.0");
  assert.match(report.recordedAt, UTC_INSTANT);
  assert.equal(Number.isNaN(Date.parse(report.recordedAt)), false);

  exactKeys(report.laboratory, ["version", "sourceCommit", "profileVersion"], "laboratory");
  assert.equal(report.laboratory.version, "0.0.0");
  assert.equal(report.laboratory.profileVersion, "2.0.0");
  assert.match(report.laboratory.sourceCommit, COMMIT);
  assert.deepEqual(report.execution, {
    scope: "active-owner-authorized",
    interface: "host-codex-mcp-ssh-windows-app",
    rawOutputRetained: false,
    graphicalSessionUsed: true,
    aiAttemptLimitSeconds: 600,
    resumedAfterTechnicalFailure: report.execution.resumedAfterTechnicalFailure,
    aiEvidenceMode: "verified-consumed-attempt",
    aiInferenceStartedInRun: false,
  });
  assert.equal(typeof report.execution.resumedAfterTechnicalFailure, "boolean");

  exactKeys(report.delivery, [
    "kind", "identity", "version", "architecture", "sha256", "signatureStatus", "sourceRevision",
    "embeddedSourceRevision", "sourceArchiveSha256", "packageLength", "sourceInputsMatchCurrent",
    "installedBaselinePreserved", "installedBaselineVersion",
    "labVersionOverrideOnly", "laboratoryOnly", "semanticProductVersionChanged",
    "workspaceProtocolVersion", "computerAvailable", "cleanMachineProven", "microsoftStoreCertified",
    "microsoftStoreSigned", "nativeArm64Proven", "buildContractSha256", "requiredPayloadSha256",
    "requiredPayloadCount",
  ], "delivery");
  assert.equal(report.delivery.kind, "msix");
  assert.equal(report.delivery.identity, "Rappor.RapporSecurity");
  assert.match(report.delivery.version, /^\d+\.\d+\.\d+\.\d+$/u);
  assert.equal(report.delivery.architecture, "x64");
  assert.match(report.delivery.sha256, HASH);
  assert.equal(report.delivery.signatureStatus, "Valid");
  assert.match(report.delivery.sourceRevision, COMMIT);
  assert.equal(report.delivery.embeddedSourceRevision, report.delivery.sourceRevision);
  assert.match(report.delivery.sourceArchiveSha256, HASH);
  assert.equal(Number.isSafeInteger(report.delivery.packageLength) && report.delivery.packageLength > 0, true);
  assert.equal(report.delivery.sourceInputsMatchCurrent, true);
  assert.equal(report.delivery.installedBaselinePreserved, true);
  assert.match(report.delivery.installedBaselineVersion, /^\d+\.\d+\.\d+\.\d+$/u);
  assert.equal(report.delivery.installedBaselineVersion, report.environment.baselineApplicationVersion);
  assert.equal(report.delivery.labVersionOverrideOnly, true);
  assert.equal(report.delivery.laboratoryOnly, true);
  assert.equal(report.delivery.semanticProductVersionChanged, false);
  assert.equal(report.delivery.workspaceProtocolVersion, 1);
  assert.equal(report.delivery.computerAvailable, true);
  for (const key of ["cleanMachineProven", "microsoftStoreCertified", "microsoftStoreSigned", "nativeArm64Proven"]) {
    assert.equal(report.delivery[key], false);
  }
  assert.match(report.delivery.buildContractSha256, HASH);
  assert.match(report.delivery.requiredPayloadSha256, HASH);
  assert.equal(Number.isSafeInteger(report.delivery.requiredPayloadCount) && report.delivery.requiredPayloadCount > 0, true);

  exactKeys(report.runtimeDelivery,
    ["protocolVersion", "sourceRevision", "imageDigest", "currentWorkspaceReady"], "runtimeDelivery");
  assert.equal(report.runtimeDelivery.protocolVersion, 7);
  assert.match(report.runtimeDelivery.sourceRevision, COMMIT);
  assert.match(report.runtimeDelivery.imageDigest, DIGEST);
  assert.equal(report.runtimeDelivery.currentWorkspaceReady, true);

  exactKeys(report.aiEvidence, [
    "authorization", "resultSha256", "verificationSha256", "completedAt", "durationMs", "findingCount",
    "securityScore", "scorePresentation", "scoreClassification", "originalCleanupConfirmed",
    "finalCleanupVerified", "automaticReviewerApproved",
  ], "aiEvidence");
  assert.equal(report.aiEvidence.authorization, "issue-18-verified-flow-20261014");
  assert.match(report.aiEvidence.resultSha256, HASH);
  assert.match(report.aiEvidence.verificationSha256, HASH);
  assert.match(report.aiEvidence.completedAt, UTC_INSTANT);
  assert.equal(report.aiEvidence.durationMs, 198000);
  assert.equal(report.aiEvidence.findingCount, 70);
  assert.equal(Number.isFinite(report.aiEvidence.securityScore) && report.aiEvidence.securityScore >= 0 &&
    report.aiEvidence.securityScore <= 100, true);
  assert.equal(report.aiEvidence.scorePresentation, "PreciseDecimal");
  assert.equal(report.aiEvidence.scoreClassification, "Critical");
  assert.equal(report.aiEvidence.originalCleanupConfirmed, false);
  assert.equal(report.aiEvidence.finalCleanupVerified, true);
  assert.equal(report.aiEvidence.automaticReviewerApproved, true);

  exactKeys(report.environment, [
    "hostArchitecture", "guestArchitecture", "baselineApplicationVersion", "candidateApplicationVersion",
    "powershellVersion", "wsl2",
    "dockerDesktopVersion", "dockerVersion", "linuxContainers",
  ], "environment");
  assert.ok(["x64", "arm64"].includes(report.environment.hostArchitecture));
  assert.ok(["x64", "arm64"].includes(report.environment.guestArchitecture));
  assert.match(report.environment.baselineApplicationVersion, /^\d+\.\d+\.\d+\.\d+$/u);
  assert.match(report.environment.candidateApplicationVersion, /^\d+\.\d+\.\d+\.\d+$/u);
  assert.notEqual(report.environment.baselineApplicationVersion, report.environment.candidateApplicationVersion);
  assert.equal(report.environment.candidateApplicationVersion, report.delivery.version);
  assert.match(report.environment.powershellVersion, VERSION);
  assert.match(report.environment.dockerDesktopVersion, VERSION);
  assert.match(report.environment.dockerVersion, VERSION);
  assert.equal(report.environment.wsl2, true);
  assert.equal(report.environment.linuxContainers, true);

  exactKeys(report.preflight, [
    "vmAutostart", "headlessControl", "hostFreeGiB", "guestFreeGiB", "minimumHostFreeGiB",
    "minimumGuestFreeGiB", "overlayGiB", "maximumOverlayGiB", "maximumOverlayGrowthGiB",
    "capacityFailureProved",
  ], "preflight");
  assert.equal(report.preflight.vmAutostart, true);
  assert.equal(report.preflight.headlessControl, true);
  assert.equal(report.preflight.capacityFailureProved, true);
  for (const key of [
    "hostFreeGiB", "guestFreeGiB", "minimumHostFreeGiB", "minimumGuestFreeGiB", "overlayGiB",
    "maximumOverlayGiB", "maximumOverlayGrowthGiB",
  ]) {
    assert.equal(Number.isFinite(report.preflight[key]) && report.preflight[key] >= 0, true, `${key} is invalid`);
  }
  assert.ok(report.preflight.hostFreeGiB >= report.preflight.minimumHostFreeGiB);
  assert.ok(report.preflight.guestFreeGiB >= report.preflight.minimumGuestFreeGiB);
  assert.equal(report.preflight.maximumOverlayGiB, 55);
  assert.equal(report.preflight.maximumOverlayGrowthGiB, 2);
  assert.ok(report.preflight.overlayGiB <= report.preflight.maximumOverlayGiB);

  exactKeys(report.lifecycle, [
    "upgrade", "idempotentReinstall", "cleanInstall", "sameComputerReused", "shutdownAndBoot",
    "suspendAndResume", "heartbeatOfflineOnline", "credentialRotation", "credentialRevocationRecovery",
    "invalidConfigurationRecovery",
  ], "lifecycle");
  for (const key of [
    "upgrade", "idempotentReinstall", "cleanInstall", "shutdownAndBoot", "suspendAndResume",
    "heartbeatOfflineOnline", "credentialRotation", "credentialRevocationRecovery", "invalidConfigurationRecovery",
  ]) passedStep(report.lifecycle[key], `lifecycle.${key}`);
  assert.equal(report.lifecycle.sameComputerReused, true);

  const expectedFailures = [
    ["docker-stopped", "docker-not-ready", "start-docker-and-retry"],
    ["incompatible-architecture", "unsupported-architecture", "use-supported-64-bit-windows"],
    ["missing-image", "image-unavailable", "publish-exact-image-and-retry"],
    ["invalid-local-configuration", "configuration-invalid", "restore-valid-configuration-and-retry"],
    ["expired-token", "credential-rejected", "rotate-credential-and-retry"],
  ];
  assert.equal(report.failures.length, expectedFailures.length);
  for (let index = 0; index < expectedFailures.length; index += 1) {
    const item = report.failures[index];
    exactKeys(item, ["caseId", "failureClass", "guidanceClass", "recovered", "durationMs"], `failures[${index}]`);
    assert.deepEqual([item.caseId, item.failureClass, item.guidanceClass], expectedFailures[index]);
    assert.equal(item.recovered, true);
    assert.equal(Number.isInteger(item.durationMs) && item.durationMs >= 0, true);
  }

  assert.deepEqual(report.analyses.map((item) => item.source), ["public-repository", "local-synthetic-folder"]);
  for (const [index, analysis] of report.analyses.entries()) {
    exactKeys(analysis, ["source", "status", "sourceRevision", "clientPath", "scanners", "durationMs"], `analyses[${index}]`);
    assert.equal(analysis.status, "completed");
    assert.match(analysis.sourceRevision, index === 0 ? COMMIT : DIGEST);
    assert.equal(analysis.clientPath, index === 0 ? "managed-hml" : "host-codex-ssh-windows-app");
    assert.deepEqual(analysis.scanners.map((scanner) => scanner.key), ["semgrep", "gitleaks", "trivy"]);
    for (const scanner of analysis.scanners) {
      exactKeys(scanner, ["key", "version", "state", "databaseState"], `analyses[${index}].scanner`);
      assert.match(scanner.version, VERSION);
      assert.equal(scanner.state, "completed");
      assert.equal(scanner.databaseState, scanner.key === "trivy" ? "approved-offline-stale" : null);
    }
    assert.equal(Number.isInteger(analysis.durationMs) && analysis.durationMs >= 0, true);
  }

  exactKeys(report.cleanup, [
    "computerRetained", "remoteRecordsArchived", "transientFilesRemoved", "controlledStatePreserved",
    "hostFreeGiB", "guestFreeGiB", "overlayGiB", "overlayGrowthGiB", "diskWithinLimits",
  ], "cleanup");
  for (const key of ["computerRetained", "remoteRecordsArchived", "transientFilesRemoved", "controlledStatePreserved", "diskWithinLimits"]) {
    assert.equal(report.cleanup[key], true, `cleanup.${key} was not proven`);
  }
  for (const key of ["hostFreeGiB", "guestFreeGiB", "overlayGiB", "overlayGrowthGiB"]) {
    assert.equal(Number.isFinite(report.cleanup[key]) && report.cleanup[key] >= 0, true);
  }
  assert.ok(report.cleanup.overlayGiB <= report.preflight.maximumOverlayGiB);
  assert.ok(report.cleanup.overlayGrowthGiB <= report.preflight.maximumOverlayGrowthGiB);
  assert.deepEqual(report.sanitization, {
    retained: ["steps", "failure-classes", "versions", "architectures", "durations", "boolean-outcomes",
      "evidence-hashes", "finding-count", "security-score", "database-freshness"],
    excluded: [
      "credentials", "authorization-values", "computer-identifiers", "operation-identifiers", "personal-paths", "source-code",
      "raw-api-responses", "scanner-output", "setup-logs",
    ],
  });

  inspectKeys(report);
  const serialized = `${JSON.stringify(report)}\n${markdown}`;
  for (const pattern of FORBIDDEN_MATERIAL) assert.doesNotMatch(serialized, pattern);
  if (markdown) {
    assert.match(markdown, /Unattended VM control: \*\*yes\*\*/u);
    assert.match(markdown, /Host Codex → SSH → Windows app path: \*\*yes\*\*/u);
    assert.match(markdown, /AI evidence mode: `verified-consumed-attempt`/u);
    assert.match(markdown, /New AI inference in this reconciliation: \*\*no\*\*/u);
    assert.match(markdown, /Original automatic cleanup confirmed: \*\*no\*\*/u);
    assert.match(markdown, /Assisted final cleanup verified: \*\*yes\*\*/u);
    assert.match(markdown, /trivy [^|]+ \(approved-offline-stale\)/u);
    assert.match(markdown, /Controlled state preserved: \*\*yes\*\*/u);
    assert.match(markdown, /\| public-repository \| completed \|/u);
    assert.match(markdown, /\| local-synthetic-folder \| completed \|/u);
  }
  return { lifecycleSteps: 9, failureCases: 5, analyses: 2, clean: true };
}

async function main() {
  const [jsonPath, markdownPath] = process.argv.slice(2);
  if (jsonPath) {
    const report = JSON.parse(await readFile(resolve(process.cwd(), jsonPath), "utf8"));
    const markdown = markdownPath ? await readFile(resolve(process.cwd(), markdownPath), "utf8") : "";
    process.stdout.write(`${JSON.stringify(await verifyWindowsAgentReport(report, markdown), null, 2)}\n`);
    return;
  }
  const directory = resolve(process.cwd(), "observations", "windows-agent");
  let names = [];
  try {
    names = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (names.length === 0) throw new Error("no Windows agent observations were found");
  const results = [];
  for (const name of names) {
    const base = name.slice(0, -5);
    const [json, markdown] = await Promise.all([
      readFile(resolve(directory, name), "utf8"),
      readFile(resolve(directory, `${base}.md`), "utf8"),
    ]);
    results.push(await verifyWindowsAgentReport(JSON.parse(json), markdown));
  }
  process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Windows agent report verification failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
