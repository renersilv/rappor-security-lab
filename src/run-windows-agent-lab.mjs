#!/usr/bin/env node
import { prepareWindowsWorkspaceUi } from "./prepare-windows-workspace-ui.mjs";

import { execFile as execFileCallback, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, stat, statfs, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const execFile = promisify(execFileCallback);
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const PROFILE_PATH = resolve(REPOSITORY_ROOT, "scanner-profiles", "windows-agent-lab.json");
const GUEST_SCRIPT = resolve(REPOSITORY_ROOT, "ops", "windows-agent-lab", "guest.ps1");
const DOCKER_KEEPALIVE_SCRIPT = resolve(REPOSITORY_ROOT, "ops", "windows-agent-lab", "docker-keepalive.ps1");
const VM_CONTROL = resolve(REPOSITORY_ROOT, "ops", "windows-agent-lab", "vm-control.sh");
const AI_RUNNER = resolve(REPOSITORY_ROOT, "ops", "windows-agent-lab", "run-codex-once.sh");
const TERMINAL_ASSESSMENT_STATES = new Set(["Completed", "PartiallyCompleted", "Failed", "Cancelled"]);
const GIB = 1024 ** 3;

function fail(message) {
  throw new Error(message);
}

function required(value, label) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} is required`);
  return value;
}

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function roundedGiB(bytes) {
  return Math.round((Number(bytes) / GIB) * 10) / 10;
}

function elapsed(startedAt) {
  return Math.max(0, Date.now() - startedAt);
}

function sha256Text(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256Buffer(value) {
  return createHash("sha256").update(value).digest("hex");
}

function normalizedDatabaseState(value) {
  if (value === null || value === undefined) return null;
  if (value === "ApprovedOfflineStale" || value === "approved-offline-stale") return "approved-offline-stale";
  fail("the scanner database state is not an approved laboratory value");
}

function verifyPublishedRuntimeDelivery(value, profile) {
  if (value?.schemaVersion !== 1 || value.protocolVersion !== profile.runtimeDelivery.protocolVersion ||
    value.revision !== profile.runtimeDelivery.sourceRevision ||
    value.imageDigest !== profile.runtimeDelivery.imageDigest ||
    value.runtimePlatform !== "linux/amd64" ||
    !Array.isArray(value.supportedHostArchitectures) ||
    !value.supportedHostArchitectures.includes("x64")) {
    fail("the published Windows runtime delivery does not match the pinned recovery baseline");
  }
  return value;
}

export function evaluateCapacity({ hostFreeBytes, guestFreeBytes, minimumHostFreeGiB, minimumGuestFreeGiB }) {
  const values = [hostFreeBytes, guestFreeBytes, minimumHostFreeGiB, minimumGuestFreeGiB];
  if (!values.every((value) => Number.isFinite(value) && value >= 0)) fail("capacity inputs must be non-negative numbers");
  if (hostFreeBytes < minimumHostFreeGiB * GIB) {
    return { passed: false, failureClass: "host-free-space-below-threshold" };
  }
  if (guestFreeBytes < minimumGuestFreeGiB * GIB) {
    return { passed: false, failureClass: "guest-free-space-below-threshold" };
  }
  return { passed: true, failureClass: null };
}

export function evaluateOverlayCapacity({
  initialOverlayBytes,
  currentOverlayBytes,
  maximumOverlayGiB,
  maximumOverlayGrowthGiB,
}) {
  const values = [initialOverlayBytes, currentOverlayBytes, maximumOverlayGiB, maximumOverlayGrowthGiB];
  if (!values.every((value) => Number.isFinite(value) && value >= 0)) {
    fail("overlay capacity inputs must be non-negative numbers");
  }
  if (currentOverlayBytes > maximumOverlayGiB * GIB) {
    return { passed: false, failureClass: "overlay-above-absolute-limit" };
  }
  if (currentOverlayBytes - initialOverlayBytes > maximumOverlayGrowthGiB * GIB) {
    return { passed: false, failureClass: "overlay-growth-above-run-limit" };
  }
  return { passed: true, failureClass: null };
}

export function evaluatePreparationCapacityReserve({
  hostFreeBytes,
  guestFreeBytes,
  currentOverlayBytes,
  minimumHostFreeGiB,
  minimumGuestFreeGiB,
  maximumOverlayGiB,
  reserveGiB,
}) {
  const values = [hostFreeBytes, guestFreeBytes, currentOverlayBytes, minimumHostFreeGiB,
    minimumGuestFreeGiB, maximumOverlayGiB, reserveGiB];
  if (!values.every((value) => Number.isFinite(value) && value >= 0)) {
    fail("preparation capacity inputs must be non-negative numbers");
  }
  if (hostFreeBytes < (minimumHostFreeGiB + reserveGiB) * GIB) {
    return { passed: false, failureClass: "host-preparation-reserve-unavailable" };
  }
  if (guestFreeBytes < (minimumGuestFreeGiB + reserveGiB) * GIB) {
    return { passed: false, failureClass: "guest-preparation-reserve-unavailable" };
  }
  if (currentOverlayBytes > (maximumOverlayGiB - reserveGiB) * GIB) {
    return { passed: false, failureClass: "overlay-preparation-reserve-unavailable" };
  }
  return { passed: true, failureClass: null };
}

function preparationActionCapacityMonitor(monitorCapacity, profile) {
  return async () => {
    const capacity = await monitorCapacity();
    const reserve = evaluatePreparationCapacityReserve({
      hostFreeBytes: capacity.hostFreeBytes,
      guestFreeBytes: capacity.guest.guestFreeBytes,
      currentOverlayBytes: capacity.currentOverlayBytes,
      minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
      minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
      maximumOverlayGiB: profile.vm.maximumOverlayGiB,
      reserveGiB: profile.vm.maximumOverlayGrowthGiB,
    });
    if (!reserve.passed) fail(reserve.failureClass);
    return capacity;
  };
}

function capacityFailurePathsProved(profile) {
  const hostThreshold = profile.vm.minimumHostFreeGiB * GIB;
  const guestThreshold = profile.vm.minimumGuestFreeGiB * GIB;
  return evaluateCapacity({
    hostFreeBytes: hostThreshold - 1,
    guestFreeBytes: guestThreshold,
    minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
    minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
  }).failureClass === "host-free-space-below-threshold" && evaluateCapacity({
    hostFreeBytes: hostThreshold,
    guestFreeBytes: guestThreshold - 1,
    minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
    minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
  }).failureClass === "guest-free-space-below-threshold" && evaluateOverlayCapacity({
    initialOverlayBytes: 0,
    currentOverlayBytes: profile.vm.maximumOverlayGiB * GIB + 1,
    maximumOverlayGiB: profile.vm.maximumOverlayGiB,
    maximumOverlayGrowthGiB: profile.vm.maximumOverlayGrowthGiB,
  }).failureClass === "overlay-above-absolute-limit" && evaluateOverlayCapacity({
    initialOverlayBytes: 1,
    currentOverlayBytes: profile.vm.maximumOverlayGrowthGiB * GIB + 2,
    maximumOverlayGiB: profile.vm.maximumOverlayGiB,
    maximumOverlayGrowthGiB: profile.vm.maximumOverlayGrowthGiB,
  }).failureClass === "overlay-growth-above-run-limit";
}

function parseOverlayBytes(output) {
  const match = /^overlay_bytes=(\d+)$/mu.exec(output);
  if (!match) fail("the writable overlay size was not available");
  return Number(match[1]);
}

export async function requireDiskWithinLimits(adapter, profile, initialOverlayBytes, { allowDockerTransition = false } = {}) {
  const [hostFreeBytes, guest, vmPreflight] = await Promise.all([
    adapter.hostFreeBytes(),
    adapter.guest("Preflight"),
    adapter.vm("preflight"),
  ]);
  if (!guest.passed && !(allowDockerTransition && guest.failureClass === "docker-not-ready")) {
    fail(`disk capacity check could not run (${guest.failureClass ?? "guest-preflight-failed"})`);
  }
  const capacity = evaluateCapacity({
    hostFreeBytes,
    guestFreeBytes: guest.guestFreeBytes,
    minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
    minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
  });
  if (!capacity.passed) fail(capacity.failureClass);
  const currentOverlayBytes = parseOverlayBytes(vmPreflight.stdout);
  const overlay = evaluateOverlayCapacity({
    initialOverlayBytes,
    currentOverlayBytes,
    maximumOverlayGiB: profile.vm.maximumOverlayGiB,
    maximumOverlayGrowthGiB: profile.vm.maximumOverlayGrowthGiB,
  });
  if (!overlay.passed) fail(overlay.failureClass);
  return { hostFreeBytes, guest, currentOverlayBytes };
}

function parseEnvironmentFile(content) {
  const result = {};
  for (const rawLine of content.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (!match) fail("the HML credentials file has an invalid entry");
    let value = match[2];
    if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) {
      value = value.slice(1, -1);
    }
    result[match[1]] = value;
  }
  return result;
}

async function loadCredentialFile(path) {
  const metadata = await stat(path);
  if ((metadata.mode & 0o077) !== 0) fail("the HML credentials file must have mode 0600");
  let result;
  try {
    result = await execFile("/bin/bash", [
      "-c",
      "set -a\nsource \"$1\"\nset +a\nprintf '%s\\0%s' \"$RAPPOR_HML_EMAIL\" \"$RAPPOR_HML_PASSWORD\"",
      "rappor-hml-credential-loader",
      path,
    ], { encoding: "buffer", maxBuffer: 64 * 1024, timeout: 10_000 });
  } catch {
    fail("the HML credentials file could not be loaded safely");
  }
  const separator = result.stdout.indexOf(0);
  if (separator <= 0 || separator === result.stdout.length - 1 || result.stdout.indexOf(0, separator + 1) !== -1) {
    fail("the HML credentials file did not provide exactly two values");
  }
  return {
    RAPPOR_HML_EMAIL: result.stdout.subarray(0, separator).toString("utf8"),
    RAPPOR_HML_PASSWORD: result.stdout.subarray(separator + 1).toString("utf8"),
  };
}

function commandResultMarker(output) {
  const matches = [...output.matchAll(/^RAPPOR_LAB_RESULT=(\{.*\})\r?$/gmu)];
  if (matches.length === 0) fail("the guest probe did not return a structured result");
  try {
    return JSON.parse(matches.at(-1)[1]);
  } catch {
    fail("the guest probe returned invalid structured output");
  }
}

function quotePowerShell(value) {
  const text = String(value);
  if (!/^[A-Za-z0-9:/.\\_-]+$/u.test(text)) {
    fail("a guest probe argument contains unsupported characters");
  }
  return text;
}

function normalizeBaseUrl(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    fail("RAPPOR_WINDOWS_HML_BASE_URL must be a credential-free HTTPS origin");
  }
  return url.origin;
}

async function sanitizedValidationDetails(response) {
  if (response.status !== 422 || !(response.headers.get("content-type") ?? "").includes("application/json")) return "";
  try {
    const body = await response.json();
    const details = Array.isArray(body?.detail) ? body.detail : [];
    const labels = details.slice(0, 8).flatMap((item) => {
      const location = Array.isArray(item?.loc)
        ? item.loc.filter((part) => typeof part === "string" && /^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(part)).join(".")
        : "";
      const type = typeof item?.type === "string" && /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(item.type)
        ? item.type
        : "";
      return location && type ? [`${location}:${type}`] : [];
    });
    return labels.length > 0 ? ` (${labels.join(",")})` : "";
  } catch {
    return "";
  }
}

function validateProfile(profile) {
  if (profile.profileVersion !== "2.0.0") fail("the Windows agent profile version changed");
  if (profile.vm?.name !== "joao-windows-x64") fail("the Windows VM name changed");
  if (profile.vm.minimumHostFreeGiB !== 20 || profile.vm.minimumGuestFreeGiB !== 10 ||
    profile.vm.maximumOverlayGiB !== 55 || profile.vm.maximumOverlayGrowthGiB !== 2) {
    fail("the owner-authorized disk capacity boundary changed");
  }
  if (profile.delivery?.kind !== "msix" || profile.delivery?.identity !== "Rappor.RapporSecurity") {
    fail("the official Windows package identity changed");
  }
  if (!/^\d+\.\d+\.\d+\.\d+$/u.test(profile.delivery?.baselineVersion ?? "") ||
    !/^\d+\.\d+\.\d+\.\d+$/u.test(profile.delivery?.candidateVersion ?? "") ||
    profile.delivery.baselineVersion === profile.delivery.candidateVersion) {
    fail("the Windows package versions are not pinned for upgrade validation");
  }
  if (profile.delivery?.candidateArchitecture !== "x64" ||
    !/^[a-f0-9]{64}$/u.test(profile.delivery?.candidateSha256 ?? "") ||
    !Number.isSafeInteger(profile.delivery?.packageLength) || profile.delivery.packageLength <= 0 ||
    profile.delivery?.signatureStatus !== "Valid" ||
    !/^[a-f0-9]{40}$/u.test(profile.delivery?.sourceRevision ?? "") ||
    profile.delivery?.embeddedSourceRevision !== profile.delivery.sourceRevision ||
    !/^[a-f0-9]{64}$/u.test(profile.delivery?.sourceArchiveSha256 ?? "") ||
    !/^[a-f0-9]{64}$/u.test(profile.delivery?.buildContractSha256 ?? "") ||
    !/^[a-f0-9]{64}$/u.test(profile.delivery?.requiredPayloadSha256 ?? "") ||
    !Number.isSafeInteger(profile.delivery?.requiredPayloadCount) || profile.delivery.requiredPayloadCount <= 0 ||
    profile.delivery?.workspaceProtocolVersion !== 1 ||
    profile.delivery?.sourceInputsMatchCurrent !== true ||
    profile.delivery?.installedBaselinePreserved !== true ||
    profile.delivery?.labVersionOverrideOnly !== true || profile.delivery?.laboratoryOnly !== true ||
    profile.delivery?.semanticProductVersionChanged !== false || profile.delivery?.computerAvailable !== true ||
    profile.delivery?.cleanMachineProven !== false || profile.delivery?.microsoftStoreCertified !== false ||
    profile.delivery?.microsoftStoreSigned !== false || profile.delivery?.nativeArm64Proven !== false) {
    fail("the official Windows candidate provenance changed");
  }
  if (profile.runtimeDelivery?.protocolVersion !== 7 ||
    !/^[a-f0-9]{40}$/u.test(profile.runtimeDelivery?.sourceRevision ?? "") ||
    !/^sha256:[a-f0-9]{64}$/u.test(profile.runtimeDelivery?.imageDigest ?? "")) {
    fail("the published Windows runtime recovery baseline changed");
  }
  if (profile.ai?.clientPath !== "host-codex-ssh-windows-app" ||
    profile.ai?.totalTimeoutSeconds !== 600 || profile.ai?.mcpServerName !== "rapporLabIssue18" ||
    profile.ai?.lifecycleCheckpoint !== `/home/linux/.local/state/rappor-security-lab/joao/tmp/issue-18-windows-upgrade-${profile.delivery.candidateVersion}.json` ||
    profile.ai?.lifecycleCheckpointEvidence?.baselineVersion !== profile.delivery.baselineVersion ||
    profile.ai?.lifecycleCheckpointEvidence?.candidateVersion !== profile.delivery.candidateVersion ||
    profile.ai?.lifecycleCheckpointEvidence?.candidateSha256 !== profile.delivery.candidateSha256 ||
    profile.ai?.verifiedEvidence?.directory !== "/home/linux/.local/state/rappor-security-lab/joao/tmp/issue-18-verified-flow-20261014" ||
    profile.ai?.verifiedEvidence?.authorization !== "issue-18-verified-flow-20261014" ||
    !/^[a-f0-9]{64}$/u.test(profile.ai?.verifiedEvidence?.resultSha256 ?? "") ||
    !/^[a-f0-9]{64}$/u.test(profile.ai?.verifiedEvidence?.verificationSha256 ?? "")) {
    fail("the owner-authorized AI execution boundary changed");
  }
  if (!/^[a-f0-9]{40}$/u.test(profile.publicRepository?.commit ?? "")) fail("the public repository commit is not pinned");
  if (!/^sha256:[a-f0-9]{64}$/u.test(profile.localCorpus?.digest ?? "")) fail("the local corpus digest is not pinned");
  if (JSON.stringify(profile.expectedScanners) !== JSON.stringify(["semgrep", "gitleaks", "trivy"])) {
    fail("the expected scanner set changed");
  }
  for (const key of ["sshReady", "dockerReady", "heartbeat", "assessment", "shutdown"]) {
    if (!Number.isInteger(profile.timeoutsSeconds?.[key]) || profile.timeoutsSeconds[key] <= 0) {
      fail(`the ${key} timeout must be a positive integer`);
    }
  }
  return profile;
}

export async function loadVerifiedAiEvidence(profile) {
  const expected = profile.ai.verifiedEvidence;
  const directoryMetadata = await lstat(expected.directory);
  if (!directoryMetadata.isDirectory() || (directoryMetadata.mode & 0o077) !== 0) {
    fail("the verified AI evidence directory must be private");
  }
  const paths = {
    result: resolve(expected.directory, "result.json"),
    verified: resolve(expected.directory, "verified.json"),
    index: resolve(expected.directory, "index.json"),
  };
  const contents = {};
  for (const [key, path] of Object.entries(paths)) {
    const metadata = await lstat(path);
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) fail("the verified AI evidence files must be private");
    contents[key] = await readFile(path);
  }
  if (sha256Buffer(contents.result) !== expected.resultSha256 ||
    sha256Buffer(contents.verified) !== expected.verificationSha256) {
    fail("the verified AI evidence hashes changed");
  }
  const index = JSON.parse(contents.index);
  if (index?.hashes?.["result.json"] !== expected.resultSha256) fail("the verified AI evidence index changed");
  const result = JSON.parse(contents.result);
  const verified = JSON.parse(contents.verified);
  const execution = Array.isArray(result.executions) && result.executions.length === 1 ? result.executions[0] : null;
  const resultTools = new Map((execution?.tools ?? []).map((tool) => [tool.key, tool]));
  const verifiedTools = new Map((verified.scanners ?? []).map((tool) => [tool.key, tool]));
  const scanners = ["semgrep", "gitleaks", "trivy"].map((key) => {
    const ai = result.aiResult?.scanners?.find((scanner) => scanner.key === key);
    const observed = resultTools.get(key);
    const final = verifiedTools.get(key);
    if (!ai || ai.state !== "completed" || observed?.state !== "Completed" || final?.state !== "Completed" ||
      ai.version !== observed.version || ai.version !== final.version) {
      fail(`the verified ${key} evidence changed`);
    }
    const databaseState = normalizedDatabaseState(observed.databaseState);
    if (databaseState !== normalizedDatabaseState(final.databaseState) ||
      (key === "trivy" ? databaseState !== "approved-offline-stale" : databaseState !== null)) {
      fail(`the verified ${key} database state changed`);
    }
    return { key, version: ai.version, state: "completed", databaseState };
  });
  const requiredFinalization = [
    "cleanup", "productArchived", "emptySourceRestored", "uiScopeRemoved", "corpusRemoved",
    "temporaryMcpRemoved", "temporaryOAuthRevoked", "automaticReviewerApproved", "vmShutOff",
  ];
  if (result.authorization !== expected.authorization || result.aiStarted !== true || result.aiCompleted !== true ||
    result.processExit !== 0 || result.durationSeconds !== 198 || result.revision !== profile.delivery.sourceRevision ||
    result.cleanup !== false || result.aiResult?.outcome !== "completed" ||
    result.aiResult?.clientPath !== profile.ai.clientPath || result.aiResult?.operationContinued !== true ||
    result.aiResult?.analysisCompleted !== true || result.aiResult?.summaryCode !== "analysis-completed" ||
    execution?.state !== "Completed" || execution.findings !== 70 ||
    execution.score?.score !== verified.score || verified.findings !== execution.findings ||
    verified.aiCompleted !== true || verified.durationSeconds !== result.durationSeconds ||
    verified.revision !== profile.delivery.sourceRevision || verified.installedVersion !== profile.delivery.candidateVersion ||
    requiredFinalization.some((key) => verified[key] !== true)) {
    fail("the verified AI execution or finalization evidence changed");
  }
  const marker = await lstat(profile.ai.persistentMarker);
  if (!marker.isFile() || (marker.mode & 0o077) !== 0) fail("the consumed AI marker is unavailable");
  return {
    authorization: expected.authorization,
    resultSha256: expected.resultSha256,
    verificationSha256: expected.verificationSha256,
    completedAt: new Date(result.finishedAt).toISOString(),
    durationMs: result.durationSeconds * 1000,
    findingCount: execution.findings,
    securityScore: verified.score,
    scorePresentation: execution.score.presentation,
    scoreClassification: execution.score.classification,
    originalCleanupConfirmed: false,
    finalCleanupVerified: true,
    automaticReviewerApproved: true,
    scanners,
  };
}

export async function loadUpgradeCheckpoint(path, profile) {
  let metadata;
  try {
    metadata = await stat(path);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) fail("the private upgrade checkpoint must have mode 0600");
  const checkpoint = JSON.parse(await readFile(path, "utf8"));
  const expected = {
    schema: "issue-18-windows-upgrade.v1",
    baselineVersion: profile.delivery.baselineVersion,
    candidateVersion: profile.delivery.candidateVersion,
    candidateSha256: profile.delivery.candidateSha256,
    sameComputerReused: true,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (checkpoint[key] !== value) fail("the private upgrade checkpoint does not match the selected candidate");
  }
  if (!Number.isInteger(checkpoint.durationMs) || checkpoint.durationMs < 0 ||
    !["live-lifecycle", "pre-ai-technical-failure"].includes(checkpoint.sourceAttempt)) {
    fail("the private upgrade checkpoint is invalid");
  }
  return checkpoint;
}

export function parseCandidateProvenance(content) {
  if (typeof content !== "string") fail("the official MSIX provenance must be text");
  const normalized = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  return JSON.parse(normalized);
}

async function loadCandidate(msixPath, profile) {
  const metadata = await stat(msixPath);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) fail("the official MSIX must be a protected mode-0600 file");
  if (metadata.size !== profile.delivery.packageLength) fail("the official MSIX length changed");
  const hashResult = await execFile("sha256sum", [msixPath], { timeout: 120_000, maxBuffer: 4096 });
  const sha256 = hashResult.stdout.trim().split(/\s+/u)[0];
  if (sha256 !== profile.delivery.candidateSha256) fail("the official MSIX SHA-256 changed");
  const manifestResult = await execFile("unzip", ["-p", msixPath, "AppxManifest.xml"], {
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  const manifest = manifestResult.stdout;
  if (!manifest.includes(`Name="${profile.delivery.identity}"`) ||
    !manifest.includes(`Version="${profile.delivery.candidateVersion}"`) ||
    !manifest.includes('ProcessorArchitecture="x64"')) {
    fail("the official MSIX manifest does not match the pinned identity, version and architecture");
  }
  const entries = await execFile("unzip", ["-Z1", msixPath], { timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
  if (!entries.stdout.split(/\r?\n/u).includes("AppxSignature.p7x")) fail("the official MSIX signature entry is absent");

  let provenance;
  for (const name of await readdir(dirname(msixPath))) {
    if (!name.endsWith(".json")) continue;
    try {
      const candidate = parseCandidateProvenance(await readFile(resolve(dirname(msixPath), name), "utf8"));
      if (candidate.packageSha256 === sha256) {
        provenance = candidate;
        break;
      }
    } catch { }
  }
  if (!provenance || provenance.schema !== "rappor-windows-lab-candidate.v1" ||
    provenance.identityName !== profile.delivery.identity ||
    provenance.version !== profile.delivery.candidateVersion || provenance.architecture !== "x64" ||
    provenance.signatureStatus !== profile.delivery.signatureStatus ||
    provenance.sourceRevision !== profile.delivery.sourceRevision ||
    provenance.embeddedSourceRevision !== profile.delivery.embeddedSourceRevision ||
    provenance.sourceArchiveSha256 !== profile.delivery.sourceArchiveSha256 ||
    provenance.packageLength !== profile.delivery.packageLength ||
    provenance.sourceInputsMatchCurrent !== profile.delivery.sourceInputsMatchCurrent ||
    provenance.installedBaselinePreserved !== profile.delivery.installedBaselinePreserved ||
    provenance.installedBaselineVersion !== profile.delivery.baselineVersion ||
    provenance.labVersionOverrideOnly !== profile.delivery.labVersionOverrideOnly ||
    provenance.laboratoryOnly !== profile.delivery.laboratoryOnly ||
    provenance.semanticProductVersionChanged !== profile.delivery.semanticProductVersionChanged ||
    provenance.workspaceProtocolVersion !== profile.delivery.workspaceProtocolVersion ||
    provenance.computerAvailable !== profile.delivery.computerAvailable ||
    provenance.cleanMachineProven !== profile.delivery.cleanMachineProven ||
    provenance.microsoftStoreCertified !== profile.delivery.microsoftStoreCertified ||
    provenance.microsoftStoreSigned !== profile.delivery.microsoftStoreSigned ||
    provenance.nativeArm64Proven !== profile.delivery.nativeArm64Proven ||
    typeof provenance.buildContract !== "string" ||
    sha256Text(provenance.buildContract) !== profile.delivery.buildContractSha256 ||
    !Array.isArray(provenance.requiredPayload) ||
    provenance.requiredPayload.length !== profile.delivery.requiredPayloadCount ||
    sha256Text(JSON.stringify(provenance.requiredPayload)) !== profile.delivery.requiredPayloadSha256) {
    fail("the official MSIX provenance does not match the pinned laboratory candidate");
  }
  return {
    kind: "msix",
    identity: profile.delivery.identity,
    version: profile.delivery.candidateVersion,
    architecture: profile.delivery.candidateArchitecture,
    sha256,
    signatureStatus: profile.delivery.signatureStatus,
    sourceRevision: profile.delivery.sourceRevision,
    embeddedSourceRevision: profile.delivery.embeddedSourceRevision,
    sourceArchiveSha256: profile.delivery.sourceArchiveSha256,
    packageLength: profile.delivery.packageLength,
    sourceInputsMatchCurrent: profile.delivery.sourceInputsMatchCurrent,
    installedBaselinePreserved: profile.delivery.installedBaselinePreserved,
    installedBaselineVersion: profile.delivery.baselineVersion,
    labVersionOverrideOnly: profile.delivery.labVersionOverrideOnly,
    laboratoryOnly: profile.delivery.laboratoryOnly,
    semanticProductVersionChanged: profile.delivery.semanticProductVersionChanged,
    workspaceProtocolVersion: profile.delivery.workspaceProtocolVersion,
    computerAvailable: profile.delivery.computerAvailable,
    cleanMachineProven: profile.delivery.cleanMachineProven,
    microsoftStoreCertified: profile.delivery.microsoftStoreCertified,
    microsoftStoreSigned: profile.delivery.microsoftStoreSigned,
    nativeArm64Proven: profile.delivery.nativeArm64Proven,
    buildContractSha256: profile.delivery.buildContractSha256,
    requiredPayloadSha256: profile.delivery.requiredPayloadSha256,
    requiredPayloadCount: profile.delivery.requiredPayloadCount,
  };
}

class CookieJar {
  #cookies = new Map();

  capture(headers) {
    const values = typeof headers.getSetCookie === "function"
      ? headers.getSetCookie()
      : [headers.get("set-cookie")].filter(Boolean);
    for (const value of values) {
      const pair = value.split(";", 1)[0];
      const separator = pair.indexOf("=");
      if (separator > 0) this.#cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  }

  header() {
    return [...this.#cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

export class HmlClient {
  constructor(baseUrl, fetchImplementation = fetch) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.fetch = fetchImplementation;
    this.cookies = new CookieJar();
  }

  async request(path, { method = "GET", body, csrf = false, operation = "request" } = {}) {
    const headers = { Accept: "application/json" };
    const cookie = this.cookies.header();
    if (cookie) headers.Cookie = cookie;
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) {
      const response = await this.request("/api/auth/csrf");
      if (typeof response?.token !== "string" || response.token.length < 16) fail("HML did not provide a CSRF token");
      headers["X-CSRF-TOKEN"] = response.token;
      const refreshedCookie = this.cookies.header();
      if (refreshedCookie) headers.Cookie = refreshedCookie;
    }
    const response = await this.fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
    });
    this.cookies.capture(response.headers);
    if (!response.ok) {
      const validationDetails = await sanitizedValidationDetails(response);
      fail(`HML ${operation} failed with status ${response.status}${validationDetails}`);
    }
    if (response.status === 204) return undefined;
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) fail("HML returned an unexpected response type");
    return response.json();
  }

  async login(email, password) {
    await this.request("/api/auth/login", { method: "POST", csrf: true, body: { email, password } });
    const session = await this.request("/api/auth/session");
    if (session?.authenticated !== true || session.activeTenant === null) fail("the dedicated HML session is unavailable");
  }

  agents() {
    return this.request("/api/agents/");
  }

  reviewConnection(requestId) {
    return this.request(`/api/agents/connection-requests/${encodeURIComponent(requestId)}`);
  }

  decideConnection(requestId, name) {
    return this.request(`/api/agents/connection-requests/${encodeURIComponent(requestId)}/decision`, {
      method: "POST",
      csrf: true,
      body: { approve: true, name },
    });
  }

  rotate(agentId) {
    return this.request(`/api/agents/${encodeURIComponent(agentId)}/rotate`, { method: "POST", csrf: true, body: {} });
  }

  revoke(agentId) {
    return this.request(`/api/agents/${encodeURIComponent(agentId)}`, { method: "DELETE", csrf: true });
  }

  createProduct(name, description) {
    return this.request("/api/products", {
      method: "POST", csrf: true, body: { name, description }, operation: "create-product",
    });
  }

  archiveProduct(product) {
    return this.request(`/api/products/${encodeURIComponent(product.id)}?version=${encodeURIComponent(product.version)}`, {
      method: "DELETE",
      csrf: true,
      operation: "archive-product",
    });
  }

  createDefinition(productId, definition) {
    return this.request(`/api/products/${encodeURIComponent(productId)}/analysis-definitions`, {
      method: "POST",
      csrf: true,
      body: definition,
      operation: "create-definition",
    });
  }

  archiveDefinition(definition) {
    return this.request(`/api/analysis-definitions/${encodeURIComponent(definition.id)}?version=${encodeURIComponent(definition.version)}`, {
      method: "DELETE",
      csrf: true,
      operation: "archive-definition",
    });
  }

  runDefinition(definition) {
    return this.request(`/api/analysis-definitions/${encodeURIComponent(definition.id)}/assessments`, {
      method: "POST",
      csrf: true,
      operation: "run-definition",
      body: {
        contractVersion: "analysis-definition-execution.v1",
        analysisDefinitionRevisionId: definition.currentRevisionId,
        idempotencyKey: crypto.randomUUID(),
      },
    });
  }

  assessment(assessmentId) {
    return this.request(`/api/assessments/${encodeURIComponent(assessmentId)}?findingsPage=1`, {
      operation: "read-assessment",
    });
  }
}

export class LiveWindowsAdapter {
  constructor({ profile, sshKey }) {
    this.profile = profile;
    this.sshKey = sshKey;
    this.sshTarget = `${profile.vm.sshUser}@${profile.vm.sshHost}`;
    this.sshArguments = [
      "-F", "/dev/null",
      "-p", String(profile.vm.sshPort),
      "-i", sshKey,
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=15",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
    ];
  }

  async execute(file, arguments_, { input, timeout = 300_000, acceptedExitCodes = [0], environment } = {}) {
    if (input !== undefined) {
      return new Promise((resolvePromise, rejectPromise) => {
        const child = spawn(file, arguments_, { stdio: ["pipe", "pipe", "pipe"], env: environment ?? process.env });
        let stdout = "";
        let stderr = "";
        let timedOut = false;
        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.stderr.on("data", (chunk) => { stderr += chunk; });
        const timer = setTimeout(() => {
          timedOut = true;
          child.kill("SIGTERM");
        }, timeout);
        child.once("error", () => {
          clearTimeout(timer);
          rejectPromise(new Error(`a bounded laboratory command could not start (${file})`));
        });
        child.once("close", (code) => {
          clearTimeout(timer);
          if (!timedOut && acceptedExitCodes.includes(code)) {
            resolvePromise({ stdout, stderr, exitCode: code });
          } else {
            rejectPromise(new Error(`a bounded laboratory command failed (${file}, exit ${code ?? -1})`));
          }
        });
        child.stdin.end(input);
      });
    }
    try {
      const result = await execFile(file, arguments_, {
        timeout,
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
        env: environment ?? process.env,
      });
      return { stdout: result.stdout, stderr: result.stderr, exitCode: 0 };
    } catch (error) {
      const exitCode = typeof error.code === "number" ? error.code : -1;
      if (acceptedExitCodes.includes(exitCode)) {
        return { stdout: error.stdout ?? "", stderr: error.stderr ?? "", exitCode };
      }
      const phases = [...(error.stdout ?? "").matchAll(/^RAPPOR_LAB_PHASE=(processor|wsl-status|wsl-version|docker-info|compose-version|docker-version|package)\r?$/gmu)];
      const phase = phases.at(-1)?.[1];
      const failure = new Error(`a bounded laboratory command failed (${file}, exit ${exitCode})`);
      failure.laboratoryPhase = phase;
      failure.laboratoryExitCode = exitCode;
      throw failure;
    }
  }

  async vm(action) {
    try {
      return await this.execute(VM_CONTROL, [action], { timeout: 360_000 });
    } catch {
      fail(`the sanitized VM ${action} action failed`);
    }
  }

  async shutdownGuest() {
    try {
      await this.execute("ssh", [
        ...this.sshArguments,
        this.sshTarget,
        "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Stop-Computer -Force\"",
      ], { timeout: 30_000, acceptedExitCodes: [0, 255] });
    } catch { }
    await this.vm("shutdown");
  }

  async hostFreeBytes() {
    const stats = await statfs(REPOSITORY_ROOT, { bigint: true });
    return Number(stats.bavail * stats.bsize);
  }

  async installGuestProbe() {
    await this.execute("ssh", [
      ...this.sshArguments,
      this.sshTarget,
      "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"[IO.Directory]::CreateDirectory('C:\\RapporLab') | Out-Null\"",
    ]);
    await this.execute("scp", [
      "-F", "/dev/null",
      "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey,
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      GUEST_SCRIPT,
      `${this.sshTarget}:C:/RapporLab/guest.ps1`,
    ]);
    await this.execute("scp", [
      "-F", "/dev/null",
      "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey,
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      DOCKER_KEEPALIVE_SCRIPT,
      `${this.sshTarget}:C:/RapporLab/docker-keepalive.ps1`,
    ]);
    await this.execute("scp", ["-F", "/dev/null", "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null", resolve(REPOSITORY_ROOT, "ops/windows-agent-lab/workspace-interactive.ps1"),
      `${this.sshTarget}:C:/RapporLab/runtime/workspace-interactive.ps1`]);
    await this.execute("scp", ["-F", "/dev/null", "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null", resolve(REPOSITORY_ROOT, "ops/windows-agent-lab/package-interactive.ps1"),
      `${this.sshTarget}:C:/RapporLab/runtime/package-interactive.ps1`]);
    await this.guest("ProvisionDockerStart");
    await this.guest("DockerStart", {}, { timeout: this.profile.timeoutsSeconds.dockerReady * 1000 });
  }

  async setupUi(action, baseUrl) {
    if (!["Open", "Inspect", "Refresh", "DownloadAgent", "PrepareAgent", "StartAgent"].includes(action)) {
      fail("unsupported official setup UI action");
    }
    const origin = normalizeBaseUrl(baseUrl) + "/";
    const script = resolve(REPOSITORY_ROOT, "ops/windows-agent-lab/official-setup.ps1");
    await this.execute("scp", ["-F", "/dev/null", "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null", script,
      `${this.sshTarget}:C:/RapporLab/runtime/official-setup.ps1`]);
    const command = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
      "-File C:/RapporLab/runtime/official-setup.ps1 -Action " + action + " -Origin " + quotePowerShell(origin);
    const result = await this.execute("ssh", [...this.sshArguments, this.sshTarget, command], { timeout: 55_000 });
    return commandResultMarker(result.stdout);
  }

  async stageCandidate(msixPath) {
    await this.execute("ssh", [
      ...this.sshArguments,
      this.sshTarget,
      "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"[IO.Directory]::CreateDirectory('C:\\RapporLab\\runtime') | Out-Null\"",
    ]);
    await this.execute("scp", [
      "-F", "/dev/null",
      "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey,
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      msixPath,
      `${this.sshTarget}:C:/RapporLab/runtime/candidate.msix`,
    ], { timeout: 300_000 });
  }

  guestCommand(action, parameters = {}) {
    const parts = [
      "powershell.exe", "-NoLogo", "-NoProfile",
    ];
    parts.push("-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "C:\\RapporLab\\guest.ps1", "-Action", quotePowerShell(action));
    for (const [name, value] of Object.entries(parameters)) {
      parts.push(`-${name}`, quotePowerShell(value));
    }
    return parts.join(" ");
  }

  async guest(action, parameters = {}, options = {}) {
    let result;
    try {
      result = await this.execute("ssh", [
        ...this.sshArguments,
        this.sshTarget,
        this.guestCommand(action, parameters),
      ], options);
    } catch (error) {
      const phase = error.laboratoryPhase ? ` during ${error.laboratoryPhase}` : "";
      const exit = Number.isInteger(error.laboratoryExitCode) ? ` (exit ${error.laboratoryExitCode})` : "";
      fail(`the sanitized ${action} guest action failed${phase}${exit}`);
    }
    return options.raw ? result : commandResultMarker(result.stdout);
  }

  async waitForSsh(timeoutSeconds) {
    const deadline = Date.now() + timeoutSeconds * 1000;
    while (Date.now() < deadline) {
      try {
        await this.execute("ssh", [
          ...this.sshArguments,
          this.sshTarget,
          "powershell.exe -NoLogo -NoProfile -NonInteractive -Command \"Write-Output ready\"",
        ], { timeout: 25_000 });
        return;
      } catch { }
      await delay(3_000);
    }
    fail("the Windows VM did not become reachable over loopback SSH");
  }

  async copyCorpus() {
    await this.guest("CleanupWorkspace");
    await this.execute("scp", [
      "-F", "/dev/null",
      "-P", String(this.profile.vm.sshPort),
      "-i", this.sshKey,
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      "-r",
      resolve(REPOSITORY_ROOT, this.profile.localCorpus.path),
      `${this.sshTarget}:C:/RapporLab/corpus`,
    ], { timeout: 180_000 });
  }

  async gitCommit() {
    const { stdout } = await this.execute("git", ["rev-parse", "HEAD"]);
    return stdout.trim();
  }

  async publicHeadCommit() {
    const { stdout } = await this.execute("git", [
      "ls-remote", `${this.profile.publicRepository.url}.git`, `refs/heads/${this.profile.publicRepository.branch}`,
    ], { timeout: 30_000 });
    return stdout.trim().split(/\s+/u)[0];
  }

  async runAiAnalysis(environment) {
    const credentials = await loadCredentialFile(environment.RAPPOR_WINDOWS_HML_CREDENTIALS_FILE);
    const ui = await prepareWindowsWorkspaceUi({ adapter: this,
      baseUrl: environment.RAPPOR_WINDOWS_HML_BASE_URL,
      computerId: environment.RAPPOR_LAB_COMPUTER_ID, credentials });
    try {
      const { stdout } = await this.execute(AI_RUNNER, ["--run"], {
        timeout: this.profile.ai.totalTimeoutSeconds * 1000 + 30_000,
        input: "", acceptedExitCodes: [0],
        environment: { ...environment, RAPPOR_LAB_ATTEMPT_DEADLINE: String(ui.deadlineUnix) },
      });
      try { return JSON.parse(stdout.trim()); }
      catch { fail("the sanitized one-shot AI result was invalid"); }
    } finally { await ui.cleanup(); }
  }
}

export function evaluateCurrentWorkspaceComputer(agent, protocolVersion) {
  if (!Number.isInteger(protocolVersion) || protocolVersion < 1) fail("invalid published agent protocol");
  if (agent?.state !== "Active") return { ready: false, failureClass: "computer-not-active" };
  if (agent.protocolVersion !== protocolVersion) return { ready: false, failureClass: "computer-protocol-update-required" };
  if (!Array.isArray(agent.capabilities) || !agent.capabilities.includes("source.current-workspace.v1")) {
    return { ready: false, failureClass: "current-workspace-capability-missing" };
  }
  if (agent.online !== true) return { ready: false, failureClass: "computer-offline" };
  return { ready: true, failureClass: null };
}

export async function requireCurrentWorkspaceComputer(client, computerId, protocolVersion) {
  const computers = activeWindowsAgents(await client.agents());
  if (computers.length !== 1 || computers[0].id !== computerId) fail("the controlled computer identity changed");
  const readiness = evaluateCurrentWorkspaceComputer(computers[0], protocolVersion);
  if (!readiness.ready) fail(readiness.failureClass);
  return computers[0];
}

export async function prepareOfficialWindowsRuntime({ adapter, client, computerId, protocolVersion,
  baseUrl, monitorCapacity, monitorActionCapacity = monitorCapacity,
  timeoutSeconds = 900, pause = delay, now = Date.now }) {
  const startedAt = now();
  const deadline = startedAt + timeoutSeconds * 1000;
  const performed = new Set();
  await monitorCapacity();
  const opened = await adapter.setupUi("Open", baseUrl);
  if (opened.state !== "opened") fail(opened.failureClass ?? "official-setup-open-failed");
  await pause(2000);
  let lastFailure = "official-setup-readiness-timed-out";
  while (now() < deadline) {
    await monitorCapacity();
    const ui = await adapter.setupUi("Inspect", baseUrl);
    if (ui.state !== "inspected") fail(ui.failureClass ?? "official-setup-inspection-failed");
    if (ui.repairRequired === true) fail("official-setup-would-replace-preserved-connection");
    if (ui.connected === true) {
      const computers = activeWindowsAgents(await client.agents());
      if (computers.length !== 1 || computers[0].id !== computerId) fail("the controlled computer identity changed");
      const readiness = evaluateCurrentWorkspaceComputer(computers[0], protocolVersion);
      if (readiness.ready) return { computer: computers[0], durationMs: Math.max(0, now() - startedAt), actions: [...performed] };
      lastFailure = readiness.failureClass;
      await pause(2000);
      continue;
    }
    const action = ["DownloadAgent", "PrepareAgent", "StartAgent"].find((value) => ui.actions?.includes(value));
    if (action && !performed.has(action)) {
      await monitorActionCapacity();
      const result = await adapter.setupUi(action, baseUrl);
      if (result.state !== "invoked" || result.action !== action) fail("official-setup-action-failed");
      performed.add(action);
    } else if (action && performed.has(action) && ui.checking !== true) {
      fail("official-setup-action-did-not-recover");
    } else if (ui.checking !== true && !action) {
      if (!ui.actions?.includes("Refresh")) fail("official-setup-requires-unavailable-action");
      if (performed.has("Refresh")) fail("official-setup-refresh-did-not-recover");
      // A completed update can leave a transient readiness result on the public screen.
      // Recheck once through its public action; never repeat preparation or replace identity.
      await monitorCapacity();
      const result = await adapter.setupUi("Refresh", baseUrl);
      if (result.state !== "invoked" || result.action !== "Refresh") fail("official-setup-action-failed");
      performed.add("Refresh");
    }
    await pause(2000);
  }
  fail(lastFailure);
}

function activeWindowsAgents(response) {
  if (!Array.isArray(response?.agents)) fail("HML returned an invalid computer catalog");
  return response.agents.filter((agent) =>
    agent.hostPlatform === "WindowsDockerDesktopWsl2" && agent.state !== "Revoked");
}

async function waitForAgent(client, predicate, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const agents = activeWindowsAgents(await client.agents());
    const match = agents.find(predicate);
    if (match) return match;
    await delay(2_000);
  }
  fail("the expected sanitized computer state did not arrive before the deadline");
}

async function waitForNoOnlineAgent(client, agentId, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const response = await client.agents();
    const agent = response.agents?.find((item) => item.id === agentId);
    if (!agent || agent.online === false || agent.state === "Revoked") return;
    await delay(3_000);
  }
  fail("the computer did not transition offline before the deadline");
}

export async function waitForCredentialRejection(adapter, timeoutSeconds, delayImplementation = delay) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    const result = await adapter.guest("DiagnoseExpiredConfig");
    if (result.category === "credential-rejected") return;
    if (result.category !== "ready") {
      fail(`the expired credential diagnosis returned sanitized category ${result.category}`);
    }
    await delayImplementation(2_000);
  }
  fail("the expired credential remained accepted beyond the bounded recovery interval");
}

export async function prepareWindowsRuntimeOnly({ adapter, client, profile, baseUrl, msixPath, delivery }) {
  const vmPreflight = await adapter.vm("preflight");
  const initialOverlayBytes = parseOverlayBytes(vmPreflight.stdout);
  if (!/autostart=enable/u.test(vmPreflight.stdout)) fail("the persistent VM does not have libvirt autostart enabled");
  const initialOverlay = evaluateOverlayCapacity({
    initialOverlayBytes,
    currentOverlayBytes: initialOverlayBytes,
    maximumOverlayGiB: profile.vm.maximumOverlayGiB,
    maximumOverlayGrowthGiB: profile.vm.maximumOverlayGrowthGiB,
  });
  if (!initialOverlay.passed) fail(initialOverlay.failureClass);
  await adapter.vm("start");
  await adapter.waitForSsh(profile.timeoutsSeconds.sshReady);
  const monitorCapacity = () => requireDiskWithinLimits(adapter, profile, initialOverlayBytes);
  await requireDiskWithinLimits(adapter, profile, initialOverlayBytes, { allowDockerTransition: true });
  await adapter.installGuestProbe();
  const capacity = await monitorCapacity();
  if (!capacity.guest.passed || capacity.guest.wsl2 !== true || capacity.guest.dockerDesktop !== true ||
    capacity.guest.composeV2 !== true || capacity.guest.linuxContainers !== true ||
    capacity.guest.installedVersion !== profile.delivery.candidateVersion || capacity.guest.packageStatus !== "Ok") {
    fail("the current official Windows candidate is not ready for runtime preparation");
  }
  const stagingReserve = evaluatePreparationCapacityReserve({
    hostFreeBytes: capacity.hostFreeBytes,
    guestFreeBytes: capacity.guest.guestFreeBytes,
    currentOverlayBytes: capacity.currentOverlayBytes,
    minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
    minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
    maximumOverlayGiB: profile.vm.maximumOverlayGiB,
    reserveGiB: profile.delivery.packageLength / GIB,
  });
  if (!stagingReserve.passed) fail(stagingReserve.failureClass);
  await adapter.stageCandidate(msixPath);
  try {
    await monitorCapacity();
    const inspectedCandidate = await adapter.guest("InspectCandidate", {
      CandidateSha256: profile.delivery.candidateSha256,
    });
    if (inspectedCandidate.candidateSha256 !== delivery.sha256 ||
      inspectedCandidate.signatureStatus !== delivery.signatureStatus) {
      fail("the staged official MSIX did not match the protected candidate");
    }
    const runtimeDelivery = verifyPublishedRuntimeDelivery(
      await client.request("/downloads/rappor-windows-delivery.json"), profile);
    const computers = activeWindowsAgents(await client.agents());
    if (computers.length !== 1 || computers[0].state !== "Active") {
      fail("the dedicated HML baseline must contain exactly one active Windows computer");
    }
    const prepared = await prepareOfficialWindowsRuntime({
      adapter,
      client,
      computerId: computers[0].id,
      protocolVersion: runtimeDelivery.protocolVersion,
      baseUrl,
      monitorCapacity: () => requireDiskWithinLimits(adapter, profile, initialOverlayBytes, { allowDockerTransition: true }),
      monitorActionCapacity: preparationActionCapacityMonitor(monitorCapacity, profile),
    });
    await monitorCapacity();
    return {
      prepared: true,
      installedVersion: profile.delivery.candidateVersion,
      signatureVerified: true,
      protocolVersion: runtimeDelivery.protocolVersion,
      graphicalSessionUsed: true,
      currentWorkspaceReady: true,
      runtimeSourceRevision: runtimeDelivery.revision,
      runtimeImageDigest: runtimeDelivery.imageDigest,
      actions: prepared.actions,
    };
  } finally {
    await adapter.guest("CleanupWorkspace");
    await monitorCapacity();
  }
}

async function waitForAssessment(client, assessmentId, expectedScanners, timeoutSeconds, capacityMonitor) {
  const startedAt = Date.now();
  const deadline = Date.now() + timeoutSeconds * 1000;
  let nextCapacityCheck = 0;
  while (Date.now() < deadline) {
    if (capacityMonitor && Date.now() >= nextCapacityCheck) {
      await capacityMonitor();
      nextCapacityCheck = Date.now() + 30_000;
    }
    const detail = await client.assessment(assessmentId);
    const state = detail?.assessment?.state;
    if (TERMINAL_ASSESSMENT_STATES.has(state)) {
      if (state !== "Completed") fail(`the agent assessment ended in sanitized state ${state}`);
      const scannerMap = new Map((detail.runs ?? []).map((run) => [run.scannerKey, run]));
      const scanners = expectedScanners.map((key) => {
        const run = scannerMap.get(key);
        if (!run || run.state !== "Completed" || typeof run.scannerVersion !== "string") {
          fail(`the ${key} scanner did not complete`);
        }
        return { key, version: run.scannerVersion, state: "completed",
          databaseState: normalizedDatabaseState(run.databaseState) };
      });
      return { detail, scanners, durationMs: elapsed(startedAt) };
    }
    await delay(2_000);
  }
  fail("the agent assessment exceeded its bounded timeout");
}

async function createAndRunAnalysis(
  client,
  product,
  definitionInput,
  expectedScanners,
  timeoutSeconds,
  capacityMonitor,
) {
  const definition = await client.createDefinition(product.id, definitionInput);
  if (!definition?.id || !definition.currentRevisionId) fail("HML did not create the analysis definition");
  const execution = await client.runDefinition(definition);
  if (!execution?.id) fail("HML did not start the agent assessment");
  const completed = await waitForAssessment(
    client,
    execution.id,
    expectedScanners,
    timeoutSeconds,
    capacityMonitor,
  );
  return { definition, ...completed };
}

function failure(caseId, failureClass, guidanceClass, startedAt) {
  return { caseId, failureClass, guidanceClass, recovered: true, durationMs: elapsed(startedAt) };
}

export const runWindowsAgentLifecycle = runWindowsAgentLifecycleV2;

export async function runWindowsAgentLifecycleV2({
  adapter,
  client,
  profile,
  baseUrl,
  msixPath,
  delivery,
  upgradeCheckpoint,
  verifiedAiEvidence,
}) {
  const definitions = [];
  let product;
  let configBackupActive = false;
  let lifecycleError;
  let transientFilesRemoved = false;
  let lifecycleStage = "admission";
  try {
    const sourceCommit = await adapter.gitCommit();
    const hostFreeBytes = await adapter.hostFreeBytes();
    const vmPreflight = await adapter.vm("preflight");
    const initialOverlayBytes = parseOverlayBytes(vmPreflight.stdout);
    if (!/autostart=enable/u.test(vmPreflight.stdout)) fail("the persistent VM does not have libvirt autostart enabled");
    await adapter.vm("start");
    await adapter.waitForSsh(profile.timeoutsSeconds.sshReady);
    await adapter.installGuestProbe();

    const baseline = await adapter.guest("Preflight");
    if (!baseline.passed || baseline.wsl2 !== true || baseline.dockerDesktop !== true ||
      baseline.composeV2 !== true || baseline.linuxContainers !== true) {
      fail("the Windows guest preflight failed");
    }
    const capacity = evaluateCapacity({
      hostFreeBytes,
      guestFreeBytes: baseline.guestFreeBytes,
      minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
      minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
    });
    if (!capacity.passed) fail(capacity.failureClass);
    const initialOverlay = evaluateOverlayCapacity({
      initialOverlayBytes,
      currentOverlayBytes: initialOverlayBytes,
      maximumOverlayGiB: profile.vm.maximumOverlayGiB,
      maximumOverlayGrowthGiB: profile.vm.maximumOverlayGrowthGiB,
    });
    if (!initialOverlay.passed) fail(initialOverlay.failureClass);
    const capacityFailureProved = capacityFailurePathsProved(profile);
    const monitorCapacity = () => requireDiskWithinLimits(adapter, profile, initialOverlayBytes);
    const resumedAfterTechnicalFailure = baseline.installedVersion === profile.delivery.candidateVersion;
    if (![profile.delivery.baselineVersion, profile.delivery.candidateVersion].includes(baseline.installedVersion) ||
      baseline.packageStatus !== "Ok" || (resumedAfterTechnicalFailure && !upgradeCheckpoint)) {
      fail("the preserved official application baseline or upgrade checkpoint is unavailable");
    }

    const publicHeadBefore = await adapter.publicHeadCommit();
    if (publicHeadBefore !== profile.publicRepository.commit) fail("the pinned public repository branch changed before the run");

    let activeAgents = activeWindowsAgents(await client.agents());
    if (activeAgents.length !== 1 || activeAgents[0].online !== true) {
      fail("the dedicated HML baseline must contain exactly one online Windows computer");
    }
    let currentAgent = activeAgents[0];
    const retainedAgentId = currentAgent.id;

    lifecycleStage = "candidate-staging";
    await adapter.stageCandidate(msixPath);
    await monitorCapacity();
    lifecycleStage = "candidate-inspection";
    const inspectedCandidate = await adapter.guest("InspectCandidate", {
      CandidateSha256: profile.delivery.candidateSha256,
    });
    if (inspectedCandidate.candidateSha256 !== delivery.sha256 ||
      inspectedCandidate.signatureStatus !== delivery.signatureStatus) {
      fail("the staged official MSIX did not match the protected candidate");
    }

    const runtimeDelivery = verifyPublishedRuntimeDelivery(
      await client.request("/downloads/rappor-windows-delivery.json"), profile);
    const prepareRuntime = () => prepareOfficialWindowsRuntime({ adapter, client, computerId: retainedAgentId,
      protocolVersion: runtimeDelivery.protocolVersion, baseUrl,
      monitorCapacity: () => requireDiskWithinLimits(adapter, profile, initialOverlayBytes, { allowDockerTransition: true }),
      monitorActionCapacity: preparationActionCapacityMonitor(monitorCapacity, profile) });
    let startedAt;
    let upgrade;
    lifecycleStage = "runtime-preparation";
    if (resumedAfterTechnicalFailure) {
      const prepared = await prepareRuntime();
      currentAgent = prepared.computer;
      upgrade = { passed: true, durationMs: upgradeCheckpoint.durationMs + prepared.durationMs };
    } else {
      startedAt = Date.now();
      await adapter.guest("InstallCandidate", {
        CandidateSha256: profile.delivery.candidateSha256,
        CandidateVersion: profile.delivery.candidateVersion,
      }, { timeout: 300_000 });
      const upgraded = await adapter.guest("Preflight");
      if (upgraded.installedVersion !== profile.delivery.candidateVersion || upgraded.packageStatus !== "Ok") {
        fail("the official MSIX update did not install the selected candidate");
      }
      currentAgent = (await prepareRuntime()).computer;
      upgrade = { passed: true, durationMs: elapsed(startedAt) };
      const checkpoint = {
        schema: "issue-18-windows-upgrade.v1",
        baselineVersion: profile.delivery.baselineVersion,
        candidateVersion: profile.delivery.candidateVersion,
        candidateSha256: profile.delivery.candidateSha256,
        sameComputerReused: true,
        durationMs: upgrade.durationMs,
        sourceAttempt: "live-lifecycle",
      };
      await writeFile(profile.ai.lifecycleCheckpoint, JSON.stringify(checkpoint, null, 2) + "\n", {
        mode: 0o600,
        flag: "wx",
      });
    }
    await monitorCapacity();

    lifecycleStage = "idempotent-reinstall";
    startedAt = Date.now();
    const countBeforeReinstall = activeWindowsAgents(await client.agents()).length;
    await adapter.guest("InstallCandidate", {
      CandidateSha256: profile.delivery.candidateSha256,
      CandidateVersion: profile.delivery.candidateVersion,
    }, { timeout: 300_000 });
    currentAgent = (await prepareRuntime()).computer;
    activeAgents = activeWindowsAgents(await client.agents());
    const sameComputerReused = activeAgents.length === countBeforeReinstall &&
      activeAgents.some((item) => item.id === retainedAgentId && item.online === true);
    if (!sameComputerReused) fail("the idempotent MSIX reinstall duplicated or replaced the computer");
    const idempotentReinstall = { passed: true, durationMs: elapsed(startedAt) };
    await monitorCapacity();

    lifecycleStage = "clean-install";
    startedAt = Date.now();
    await adapter.guest("RemoveCandidate", {}, { timeout: 180_000 });
    await adapter.guest("InstallCandidate", {
      CandidateSha256: profile.delivery.candidateSha256,
      CandidateVersion: profile.delivery.candidateVersion,
    }, { timeout: 300_000 });
    currentAgent = await waitForAgent(client, (item) =>
      item.id === retainedAgentId && item.online === true, profile.timeoutsSeconds.heartbeat);
    currentAgent = (await prepareRuntime()).computer;
    const cleanInstall = { passed: true, durationMs: elapsed(startedAt) };
    await monitorCapacity();

    const failures = [];
    lifecycleStage = "docker-recovery";
    startedAt = Date.now();
    await adapter.guest("DockerStop", {}, { timeout: 180_000 });
    const dockerStopped = await adapter.guest("Preflight", {}, { timeout: 60_000 });
    if (dockerStopped.failureClass !== "docker-not-ready") fail("the Docker stopped case was not classified");
    await adapter.guest("DockerStart", {}, { timeout: profile.timeoutsSeconds.dockerReady * 1000 });
    if (!(await adapter.guest("Preflight")).passed) fail("Docker recovery did not pass preflight");
    failures.push(failure("docker-stopped", "docker-not-ready", "start-docker-and-retry", startedAt));

    lifecycleStage = "architecture-failure";
    startedAt = Date.now();
    const incompatible = await adapter.guest("Preflight", { ArchitectureOverride: "x86" });
    if (incompatible.failureClass !== "unsupported-architecture") fail("the simulated architecture case was not classified");
    if (!(await adapter.guest("Preflight")).passed) fail("the architecture simulation changed the guest");
    failures.push(failure("incompatible-architecture", "unsupported-architecture", "use-supported-64-bit-windows", startedAt));

    lifecycleStage = "missing-image";
    startedAt = Date.now();
    const missingImage = await adapter.guest("MissingImage");
    if (missingImage.failureClass !== "image-unavailable") fail("the missing image case was not classified");
    failures.push(failure("missing-image", "image-unavailable", "publish-exact-image-and-retry", startedAt));

    lifecycleStage = "configuration-recovery";
    startedAt = Date.now();
    await adapter.guest("BackupConfig");
    configBackupActive = true;
    await adapter.guest("CorruptConfig");
    const invalid = await adapter.guest("DiagnoseConfig");
    if (invalid.category !== "configuration-invalid") fail("the invalid configuration was not diagnosed");
    await adapter.guest("RestoreConfig");
    configBackupActive = false;
    currentAgent = await waitForAgent(client, (item) =>
      item.id === retainedAgentId && item.online === true, profile.timeoutsSeconds.heartbeat);
    const invalidConfigurationRecovery = { passed: true, durationMs: elapsed(startedAt) };
    failures.push(failure("invalid-local-configuration", "configuration-invalid", "restore-valid-configuration-and-retry", startedAt));

    lifecycleStage = "credential-rotation";
    startedAt = Date.now();
    await adapter.guest("CloneExpiredConfig");
    const cloneFidelity = await adapter.guest("CompareExpiredConfig");
    if (Object.values(cloneFidelity).some((value) => value !== true)) fail("the controlled expired credential clone changed");
    const preRotationDiagnosis = await adapter.guest("DiagnoseExpiredConfig");
    if (preRotationDiagnosis.category !== "ready") fail("the pre-rotation credential clone was not ready");
    const rotation = await client.rotate(currentAgent.id);
    if (typeof rotation?.credential !== "string" || rotation.credential.length < 16) {
      fail("HML did not return a replacement credential");
    }
    await adapter.guest("StoreCredential", {}, { input: rotation.credential + "\n", timeout: 180_000 });
    rotation.credential = "";
    currentAgent = await waitForAgent(client, (item) =>
      item.id === retainedAgentId && item.online === true, profile.timeoutsSeconds.heartbeat);
    await waitForCredentialRejection(adapter, profile.timeoutsSeconds.heartbeat);
    const credentialRotation = { passed: true, durationMs: elapsed(startedAt) };
    const credentialRevocationRecovery = { passed: true, durationMs: elapsed(startedAt) };
    failures.push(failure("expired-token", "credential-rejected", "rotate-credential-and-retry", startedAt));

    lifecycleStage = "suspend-resume";
    startedAt = Date.now();
    await adapter.vm("suspend");
    await adapter.vm("resume");
    await adapter.waitForSsh(profile.timeoutsSeconds.sshReady);
    const suspendAndResume = { passed: true, durationMs: elapsed(startedAt) };

    lifecycleStage = "shutdown-boot";
    startedAt = Date.now();
    await adapter.shutdownGuest();
    await waitForNoOnlineAgent(client, retainedAgentId, profile.timeoutsSeconds.heartbeat);
    await adapter.vm("start");
    await adapter.waitForSsh(profile.timeoutsSeconds.sshReady);
    await adapter.installGuestProbe();
    currentAgent = await waitForAgent(client, (item) =>
      item.id === retainedAgentId && item.online === true, profile.timeoutsSeconds.heartbeat);
    const shutdownAndBoot = { passed: true, durationMs: elapsed(startedAt) };
    const heartbeatOfflineOnline = { passed: true, durationMs: elapsed(startedAt) };
    await monitorCapacity();

    lifecycleStage = "public-analysis";
    product = await client.createProduct("Windows Agent Laboratory", "Disposable synthetic Windows application validation");
    if (!product?.id || typeof product.version !== "number") fail("HML did not create the disposable product");

    const publicAnalysis = await createAndRunAnalysis(client, product, {
      environment: "Development",
      executionMode: "Managed",
      name: "Pinned public synthetic corpus",
      origin: profile.publicRepository.url,
      sourceKind: "PublicGitHub",
      type: "SourceCode",
    }, profile.expectedScanners, profile.timeoutsSeconds.assessment, monitorCapacity);
    definitions.push(publicAnalysis.definition);
    if (publicAnalysis.detail?.sourceSnapshot?.commit !== profile.publicRepository.commit) {
      fail("the public repository assessment did not use the pinned commit");
    }
    await monitorCapacity();

    lifecycleStage = "local-evidence-reconciliation";
    await adapter.copyCorpus();
    await monitorCapacity();
    await requireCurrentWorkspaceComputer(client, retainedAgentId, runtimeDelivery.protocolVersion);
    if (!verifiedAiEvidence) fail("the consumed real AI evidence is required for lifecycle reconciliation");
    const localAnalysis = {
      scanners: verifiedAiEvidence.scanners,
      durationMs: verifiedAiEvidence.durationMs,
    };
    await monitorCapacity();

    const publicHeadAfter = await adapter.publicHeadCommit();
    if (publicHeadAfter !== profile.publicRepository.commit) fail("the pinned public repository branch changed during the run");

    lifecycleStage = "cleanup";
    for (const definition of definitions.reverse()) await client.archiveDefinition(definition);
    definitions.length = 0;
    await client.archiveProduct(product);
    product = undefined;
    await adapter.guest("CleanupWorkspace");
    transientFilesRemoved = true;

    const cleanupCapacity = await monitorCapacity();
    const cleanupGuest = cleanupCapacity.guest;
    const cleanupHostFreeBytes = cleanupCapacity.hostFreeBytes;
    const cleanupHostFreeGiB = roundedGiB(cleanupHostFreeBytes);
    const cleanupGuestFreeGiB = roundedGiB(cleanupGuest.guestFreeBytes);
    const overlayGiB = roundedGiB(cleanupCapacity.currentOverlayBytes);
    const overlayGrowthGiB = roundedGiB(Math.max(0, cleanupCapacity.currentOverlayBytes - initialOverlayBytes));
    const diskWithinLimits = cleanupHostFreeGiB >= profile.vm.minimumHostFreeGiB &&
      cleanupGuestFreeGiB >= profile.vm.minimumGuestFreeGiB &&
      overlayGiB <= profile.vm.maximumOverlayGiB &&
      overlayGrowthGiB <= profile.vm.maximumOverlayGrowthGiB;
    if (!diskWithinLimits) fail("the retained controlled VM is outside the pinned disk limits");
    try {
      await unlink(profile.ai.lifecycleCheckpoint);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }

    return {
      $schema: "../../schemas/windows-agent-report.schema.json",
      schemaVersion: "2.0.0",
      recordedAt: new Date().toISOString(),
      laboratory: { version: "0.0.0", sourceCommit, profileVersion: profile.profileVersion },
      execution: {
        scope: "active-owner-authorized",
        interface: "host-codex-mcp-ssh-windows-app",
        rawOutputRetained: false,
        graphicalSessionUsed: true,
        aiAttemptLimitSeconds: profile.ai.totalTimeoutSeconds,
        resumedAfterTechnicalFailure,
        aiEvidenceMode: "verified-consumed-attempt",
        aiInferenceStartedInRun: false,
      },
      delivery,
      runtimeDelivery: {
        protocolVersion: runtimeDelivery.protocolVersion,
        sourceRevision: runtimeDelivery.revision,
        imageDigest: runtimeDelivery.imageDigest,
        currentWorkspaceReady: true,
      },
      aiEvidence: {
        authorization: verifiedAiEvidence.authorization,
        resultSha256: verifiedAiEvidence.resultSha256,
        verificationSha256: verifiedAiEvidence.verificationSha256,
        completedAt: verifiedAiEvidence.completedAt,
        durationMs: verifiedAiEvidence.durationMs,
        findingCount: verifiedAiEvidence.findingCount,
        securityScore: verifiedAiEvidence.securityScore,
        scorePresentation: verifiedAiEvidence.scorePresentation,
        scoreClassification: verifiedAiEvidence.scoreClassification,
        originalCleanupConfirmed: verifiedAiEvidence.originalCleanupConfirmed,
        finalCleanupVerified: verifiedAiEvidence.finalCleanupVerified,
        automaticReviewerApproved: verifiedAiEvidence.automaticReviewerApproved,
      },
      environment: {
        hostArchitecture: process.arch === "arm64" ? "arm64" : "x64",
        guestArchitecture: baseline.observedArchitecture,
        baselineApplicationVersion: profile.delivery.baselineVersion,
        candidateApplicationVersion: cleanupGuest.installedVersion,
        powershellVersion: cleanupGuest.powershellVersion,
        wsl2: cleanupGuest.wsl2,
        dockerDesktopVersion: cleanupGuest.dockerDesktopVersion,
        dockerVersion: cleanupGuest.dockerVersion,
        linuxContainers: cleanupGuest.linuxContainers,
      },
      preflight: {
        vmAutostart: true,
        headlessControl: true,
        hostFreeGiB: roundedGiB(hostFreeBytes),
        guestFreeGiB: roundedGiB(baseline.guestFreeBytes),
        minimumHostFreeGiB: profile.vm.minimumHostFreeGiB,
        minimumGuestFreeGiB: profile.vm.minimumGuestFreeGiB,
        overlayGiB: roundedGiB(initialOverlayBytes),
        maximumOverlayGiB: profile.vm.maximumOverlayGiB,
        maximumOverlayGrowthGiB: profile.vm.maximumOverlayGrowthGiB,
        capacityFailureProved,
      },
      lifecycle: {
        upgrade,
        idempotentReinstall,
        cleanInstall,
        sameComputerReused,
        shutdownAndBoot,
        suspendAndResume,
        heartbeatOfflineOnline,
        credentialRotation,
        credentialRevocationRecovery,
        invalidConfigurationRecovery,
      },
      failures,
      analyses: [
        {
          source: "public-repository",
          status: "completed",
          sourceRevision: profile.publicRepository.commit,
          clientPath: "managed-hml",
          scanners: publicAnalysis.scanners,
          durationMs: publicAnalysis.durationMs,
        },
        {
          source: "local-synthetic-folder",
          status: "completed",
          sourceRevision: profile.localCorpus.digest,
          clientPath: profile.ai.clientPath,
          scanners: localAnalysis.scanners,
          durationMs: localAnalysis.durationMs,
        },
      ],
      cleanup: {
        computerRetained: currentAgent.id === retainedAgentId && currentAgent.online === true,
        remoteRecordsArchived: true,
        transientFilesRemoved,
        controlledStatePreserved: true,
        hostFreeGiB: cleanupHostFreeGiB,
        guestFreeGiB: cleanupGuestFreeGiB,
        overlayGiB,
        overlayGrowthGiB,
        diskWithinLimits,
      },
      sanitization: {
        retained: ["steps", "failure-classes", "versions", "architectures", "durations", "boolean-outcomes",
          "evidence-hashes", "finding-count", "security-score", "database-freshness"],
        excluded: [
          "credentials", "authorization-values", "computer-identifiers", "operation-identifiers", "personal-paths",
          "source-code", "raw-api-responses", "scanner-output", "setup-logs",
        ],
      },
    };
  } catch (error) {
    lifecycleError = error;
    error.laboratoryStage = lifecycleStage;
    throw error;
  } finally {
    if (configBackupActive) {
      try { await adapter.guest("RestoreConfig"); } catch { }
    }
    for (const definition of definitions.reverse()) {
      try { await client.archiveDefinition(definition); } catch { }
    }
    if (product) {
      try { await client.archiveProduct(product); } catch { }
    }
    if (!transientFilesRemoved) {
      try { await adapter.guest("CleanupWorkspace"); } catch { }
    }
    if (lifecycleError) {
      try { await adapter.installGuestProbe(); } catch { }
    }
  }
}

export function windowsAgentReportToMarkdown(report) {
  const lifecycle = Object.entries(report.lifecycle)
    .map(([name, value]) => `| ${name} | ${value === true || value.passed ? "passed" : "failed"} | ${value.durationMs ?? "—"} |`)
    .join("\n");
  const failures = report.failures
    .map((item) => `| ${item.caseId} | ${item.failureClass} | ${item.guidanceClass} | ${item.recovered ? "yes" : "no"} |`)
    .join("\n");
  const analyses = report.analyses
    .map((item) => `| ${item.source} | ${item.status} | ${item.scanners.map((scanner) =>
      `${scanner.key} ${scanner.version}${scanner.databaseState ? ` (${scanner.databaseState})` : ""}`).join(", ")} |`)
    .join("\n");
  return `# Persistent Windows agent observation\n\n` +
    `- Recorded at: \`${report.recordedAt}\`\n` +
    `- Official candidate: \`${report.delivery.version} ${report.delivery.architecture}\`\n` +
    `- Candidate SHA-256: \`${report.delivery.sha256}\`\n` +
    `- Guest architecture: \`${report.environment.guestArchitecture}\`\n` +
    `- Unattended VM control: **yes**\n` +
    `- Official application setup UI exercised: **yes**\n` +
    `- Host Codex → SSH → Windows app path: **yes**\n` +
    `- AI evidence mode: \`${report.execution.aiEvidenceMode}\`\n` +
    `- New AI inference in this reconciliation: **${report.execution.aiInferenceStartedInRun ? "yes" : "no"}**\n` +
    `- Verified findings: \`${report.aiEvidence.findingCount}\`\n` +
    `- Verified security score: \`${report.aiEvidence.securityScore}\` (${report.aiEvidence.scoreClassification})\n` +
    `- Original automatic cleanup confirmed: **${report.aiEvidence.originalCleanupConfirmed ? "yes" : "no"}**\n` +
    `- Assisted final cleanup verified: **${report.aiEvidence.finalCleanupVerified ? "yes" : "no"}**\n` +
    `- Published runtime revision: \`${report.runtimeDelivery.sourceRevision}\`\n` +
    `- Published runtime image: \`${report.runtimeDelivery.imageDigest}\`\n` +
    `- Controlled state preserved: **${report.cleanup.controlledStatePreserved ? "yes" : "no"}**\n\n` +
    `## Lifecycle\n\n| Step | Result | Duration (ms) |\n| --- | --- | ---: |\n${lifecycle}\n\n` +
    `## Recoverable failures\n\n| Case | Failure class | Guidance class | Recovered |\n| --- | --- | --- | --- |\n${failures}\n\n` +
    `## Real analyses\n\n| Source | Status | Scanners |\n| --- | --- | --- |\n${analyses}\n\n` +
    `## Bounded cleanup\n\n` +
    `- Computer retained: **${report.cleanup.computerRetained ? "yes" : "no"}**\n` +
    `- Disposable records archived: **${report.cleanup.remoteRecordsArchived ? "yes" : "no"}**\n` +
    `- Host free space: \`${report.cleanup.hostFreeGiB} GiB\`\n` +
    `- Guest free space: \`${report.cleanup.guestFreeGiB} GiB\`\n` +
    `- Writable overlay: \`${report.cleanup.overlayGiB} GiB\`\n` +
    `- Overlay growth during run: \`${report.cleanup.overlayGrowthGiB} GiB\`\n`;
}

function parseArguments(arguments_) {
  const values = { prepareRuntime: false };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--prepare-runtime") values.prepareRuntime = true;
    else if (argument === "--json") values.jsonPath = arguments_[++index];
    else if (argument === "--markdown") values.markdownPath = arguments_[++index];
    else fail(`unknown argument: ${argument}`);
  }
  if (values.prepareRuntime && (values.jsonPath || values.markdownPath)) {
    fail("--prepare-runtime cannot write an observation");
  }
  if (!values.prepareRuntime && (!values.jsonPath || !values.markdownPath)) {
    fail("--json and --markdown are required");
  }
  return values;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const profile = validateProfile(JSON.parse(await readFile(PROFILE_PATH, "utf8")));
  const baseUrl = normalizeBaseUrl(required(process.env.RAPPOR_WINDOWS_HML_BASE_URL, "RAPPOR_WINDOWS_HML_BASE_URL"));
  const credentialsPath = required(process.env.RAPPOR_WINDOWS_HML_CREDENTIALS_FILE, "RAPPOR_WINDOWS_HML_CREDENTIALS_FILE");
  const sshKey = required(process.env.RAPPOR_WINDOWS_SSH_KEY, "RAPPOR_WINDOWS_SSH_KEY");
  const msixPath = required(process.env.RAPPOR_WINDOWS_MSIX_PATH, "RAPPOR_WINDOWS_MSIX_PATH");
  const delivery = await loadCandidate(msixPath, profile);
  const credentials = await loadCredentialFile(credentialsPath);
  const client = new HmlClient(baseUrl);
  await client.login(
    required(credentials.RAPPOR_HML_EMAIL, "RAPPOR_HML_EMAIL"),
    required(credentials.RAPPOR_HML_PASSWORD, "RAPPOR_HML_PASSWORD"),
  );
  const adapter = new LiveWindowsAdapter({ profile, sshKey });
  if (options.prepareRuntime) {
    const prepared = await prepareWindowsRuntimeOnly({ adapter, client, profile, baseUrl, msixPath, delivery });
    process.stdout.write(`Official Windows runtime prepared; candidate ${prepared.installedVersion}, ` +
      `protocol ${prepared.protocolVersion}, graphical session yes, current workspace ready yes.\n`);
    return;
  }
  const upgradeCheckpoint = await loadUpgradeCheckpoint(profile.ai.lifecycleCheckpoint, profile);
  const verifiedAiEvidence = await loadVerifiedAiEvidence(profile);
  const report = await runWindowsAgentLifecycleV2({
    adapter, client, profile, baseUrl, msixPath, delivery, upgradeCheckpoint, verifiedAiEvidence,
  });
  await Promise.all([
    writeFile(resolve(process.cwd(), options.jsonPath), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 }),
    writeFile(resolve(process.cwd(), options.markdownPath), windowsAgentReportToMarkdown(report), { mode: 0o600 }),
  ]);
  process.stdout.write("Windows agent lifecycle completed; sanitized temporary reports were written.\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    const stage = typeof error.laboratoryStage === "string" && /^[a-z]+(?:-[a-z]+)*$/u.test(error.laboratoryStage)
      ? ` during ${error.laboratoryStage}` : "";
    process.stderr.write(`Windows agent lifecycle failed${stage}: ${error.message}\n`);
    process.exitCode = 1;
  });
}
