import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  LiveWindowsAdapter,
  evaluateCapacity,
  evaluateCurrentWorkspaceComputer,
  requireCurrentWorkspaceComputer,
  requireDiskWithinLimits,
  prepareOfficialWindowsRuntime,
  evaluateOverlayCapacity,
  evaluatePreparationCapacityReserve,
  loadUpgradeCheckpoint,
  parseCandidateProvenance,
  prepareWindowsRuntimeOnly,
  runWindowsAgentLifecycle,
  runWindowsAgentLifecycleV2,
  waitForCredentialRejection,
  windowsAgentReportToMarkdown,
} from "../src/run-windows-agent-lab.mjs";
import { verifyWindowsAgentReport } from "../src/verify-windows-agent-report.mjs";

const execFile = promisify(execFileCallback);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function passed(durationMs = 1) {
  return { passed: true, durationMs };
}

function reportFixture() {
  const scanners = ["semgrep", "gitleaks", "trivy"].map((key) => ({
    key,
    version: "1.0.0",
    state: "completed",
    databaseState: key === "trivy" ? "approved-offline-stale" : null,
  }));
  return {
    $schema: "../../schemas/windows-agent-report.schema.json",
    schemaVersion: "2.0.0",
    recordedAt: "2026-10-06T21:00:00.000Z",
    laboratory: {
      version: "0.0.0",
      sourceCommit: "1".repeat(40),
      profileVersion: "2.0.0",
    },
    execution: {
      scope: "active-owner-authorized",
      interface: "host-codex-mcp-ssh-windows-app",
      rawOutputRetained: false,
      graphicalSessionUsed: true,
      aiAttemptLimitSeconds: 600,
      resumedAfterTechnicalFailure: false,
      aiEvidenceMode: "verified-consumed-attempt",
      aiInferenceStartedInRun: false,
    },
    delivery: {
      kind: "msix",
      identity: "Rappor.RapporSecurity",
      version: "1.0.0.16",
      architecture: "x64",
      sha256: "2".repeat(64),
      signatureStatus: "Valid",
      sourceRevision: "3".repeat(40),
      embeddedSourceRevision: "3".repeat(40),
      sourceArchiveSha256: "4".repeat(64),
      packageLength: 104346835,
      sourceInputsMatchCurrent: true,
      installedBaselinePreserved: true,
      installedBaselineVersion: "1.0.0.15",
      labVersionOverrideOnly: true,
      laboratoryOnly: true,
      semanticProductVersionChanged: false,
      workspaceProtocolVersion: 1,
      computerAvailable: true,
      cleanMachineProven: false,
      microsoftStoreCertified: false,
      microsoftStoreSigned: false,
      nativeArm64Proven: false,
      buildContractSha256: "6".repeat(64),
      requiredPayloadSha256: "7".repeat(64),
      requiredPayloadCount: 7,
    },
    runtimeDelivery: {
      protocolVersion: 7,
      sourceRevision: "8".repeat(40),
      imageDigest: "sha256:" + "9".repeat(64),
      currentWorkspaceReady: true,
    },
    aiEvidence: {
      authorization: "issue-18-verified-flow-20261014",
      resultSha256: "a".repeat(64),
      verificationSha256: "b".repeat(64),
      completedAt: "2026-10-14T20:27:08.000Z",
      durationMs: 198000,
      findingCount: 70,
      securityScore: 19.958358398579,
      scorePresentation: "PreciseDecimal",
      scoreClassification: "Critical",
      originalCleanupConfirmed: false,
      finalCleanupVerified: true,
      automaticReviewerApproved: true,
    },
    environment: {
      hostArchitecture: "x64",
      guestArchitecture: "x64",
      baselineApplicationVersion: "1.0.0.15",
      candidateApplicationVersion: "1.0.0.16",
      powershellVersion: "5.1.0",
      wsl2: true,
      dockerDesktopVersion: "4.0.0",
      dockerVersion: "29.8.0",
      linuxContainers: true,
    },
    preflight: {
      vmAutostart: true,
      headlessControl: true,
      hostFreeGiB: 24,
      guestFreeGiB: 12,
      minimumHostFreeGiB: 20,
      minimumGuestFreeGiB: 10,
      overlayGiB: 20,
      maximumOverlayGiB: 55,
      maximumOverlayGrowthGiB: 2,
      capacityFailureProved: true,
    },
    lifecycle: {
      upgrade: passed(),
      idempotentReinstall: passed(),
      cleanInstall: passed(),
      sameComputerReused: true,
      shutdownAndBoot: passed(),
      suspendAndResume: passed(),
      heartbeatOfflineOnline: passed(),
      credentialRotation: passed(),
      credentialRevocationRecovery: passed(),
      invalidConfigurationRecovery: passed(),
    },
    failures: [
      ["docker-stopped", "docker-not-ready", "start-docker-and-retry"],
      ["incompatible-architecture", "unsupported-architecture", "use-supported-64-bit-windows"],
      ["missing-image", "image-unavailable", "publish-exact-image-and-retry"],
      ["invalid-local-configuration", "configuration-invalid", "restore-valid-configuration-and-retry"],
      ["expired-token", "credential-rejected", "rotate-credential-and-retry"],
    ].map(([caseId, failureClass, guidanceClass]) => ({
      caseId,
      failureClass,
      guidanceClass,
      recovered: true,
      durationMs: 1,
    })),
    analyses: [
      {
        source: "public-repository",
        status: "completed",
        sourceRevision: "5".repeat(40),
        clientPath: "managed-hml",
        scanners,
        durationMs: 1,
      },
      {
        source: "local-synthetic-folder",
        status: "completed",
        sourceRevision: "sha256:" + "6".repeat(64),
        clientPath: "host-codex-ssh-windows-app",
        scanners,
        durationMs: 1,
      },
    ],
    cleanup: {
      computerRetained: true,
      remoteRecordsArchived: true,
      transientFilesRemoved: true,
      controlledStatePreserved: true,
      hostFreeGiB: 24,
      guestFreeGiB: 12,
      overlayGiB: 20,
      overlayGrowthGiB: 0,
      diskWithinLimits: true,
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
}

test("capacity admission fails before either filesystem is exhausted", () => {
  assert.deepEqual(evaluateCapacity({
    hostFreeBytes: 19 * 1024 ** 3,
    guestFreeBytes: 12 * 1024 ** 3,
    minimumHostFreeGiB: 20,
    minimumGuestFreeGiB: 10,
  }), { passed: false, failureClass: "host-free-space-below-threshold" });
  assert.deepEqual(evaluateCapacity({
    hostFreeBytes: 24 * 1024 ** 3,
    guestFreeBytes: 9 * 1024 ** 3,
    minimumHostFreeGiB: 20,
    minimumGuestFreeGiB: 10,
  }), { passed: false, failureClass: "guest-free-space-below-threshold" });
});

test("overlay admission enforces the authorized absolute and per-run growth limits", () => {
  assert.deepEqual(evaluateOverlayCapacity({
    initialOverlayBytes: 49 * 1024 ** 3,
    currentOverlayBytes: 51 * 1024 ** 3,
    maximumOverlayGiB: 55,
    maximumOverlayGrowthGiB: 2,
  }), { passed: true, failureClass: null });
  assert.deepEqual(evaluateOverlayCapacity({
    initialOverlayBytes: 49 * 1024 ** 3,
    currentOverlayBytes: 51 * 1024 ** 3 + 1,
    maximumOverlayGiB: 55,
    maximumOverlayGrowthGiB: 2,
  }), { passed: false, failureClass: "overlay-growth-above-run-limit" });
  assert.deepEqual(evaluateOverlayCapacity({
    initialOverlayBytes: 54 * 1024 ** 3,
    currentOverlayBytes: 55 * 1024 ** 3 + 1,
    maximumOverlayGiB: 55,
    maximumOverlayGrowthGiB: 2,
  }), { passed: false, failureClass: "overlay-above-absolute-limit" });
});

test("official UI actions reserve the full authorized growth before changing disk state", async () => {
  const gib = 1024 ** 3;
  assert.deepEqual(evaluatePreparationCapacityReserve({
    hostFreeBytes: 30 * gib,
    guestFreeBytes: 12 * gib,
    currentOverlayBytes: 53 * gib,
    minimumHostFreeGiB: 20,
    minimumGuestFreeGiB: 10,
    maximumOverlayGiB: 55,
    reserveGiB: 2,
  }), { passed: true, failureClass: null });
  assert.equal(evaluatePreparationCapacityReserve({
    hostFreeBytes: 30 * gib,
    guestFreeBytes: 12 * gib - 1,
    currentOverlayBytes: 53 * gib,
    minimumHostFreeGiB: 20,
    minimumGuestFreeGiB: 10,
    maximumOverlayGiB: 55,
    reserveGiB: 2,
  }).failureClass, "guest-preparation-reserve-unavailable");
  assert.equal(evaluatePreparationCapacityReserve({
    hostFreeBytes: 30 * gib,
    guestFreeBytes: 12 * gib,
    currentOverlayBytes: 53 * gib + 1,
    minimumHostFreeGiB: 20,
    minimumGuestFreeGiB: 10,
    maximumOverlayGiB: 55,
    reserveGiB: 2,
  }).failureClass, "overlay-preparation-reserve-unavailable");
});

test("expired credential diagnosis tolerates only bounded ready-to-rejected propagation", async () => {
  const categories = ["ready", "ready", "credential-rejected"];
  const actions = [];
  const adapter = {
    async guest(action) {
      actions.push(action);
      return { category: categories.shift() };
    },
  };
  await waitForCredentialRejection(adapter, 10, async () => {});
  assert.deepEqual(actions, ["DiagnoseExpiredConfig", "DiagnoseExpiredConfig", "DiagnoseExpiredConfig"]);
});

test("the compatibility export uses the current lifecycle", () => {
  assert.equal(runWindowsAgentLifecycle, runWindowsAgentLifecycleV2);
});

test("the sanitized report proves the MSIX, AI client path and retained controlled state", async () => {
  const report = reportFixture();
  const markdown = windowsAgentReportToMarkdown(report);
  const result = await verifyWindowsAgentReport(report, markdown);
  assert.deepEqual(result, { lifecycleSteps: 9, failureCases: 5, analyses: 2, clean: true });
  assert.match(markdown, /Host Codex → SSH → Windows app path: \*\*yes\*\*/u);
  assert.doesNotMatch(JSON.stringify(report), /"(?:operationId|computerId|credential)"/u);
});

test("the profile pins the selected official candidate and one-shot boundary", async () => {
  const profile = JSON.parse(await readFile(resolve(repositoryRoot, "scanner-profiles/windows-agent-lab.json"), "utf8"));
  assert.equal(profile.profileVersion, "2.0.0");
  assert.deepEqual(profile.delivery, {
  "kind": "msix",
  "identity": "Rappor.RapporSecurity",
  "baselineVersion": "1.0.0.17",
  "candidateVersion": "1.0.0.19",
  "candidateArchitecture": "x64",
  "candidateSha256": "e48a765043a7bd1fef77989dc718df684a91acae0262f14fe70bbc04873cdd3a",
  "packageLength": 104441335,
  "signatureStatus": "Valid",
  "sourceRevision": "e12005607d7c13137efd9c1e146d0ec8489ecf0a",
  "embeddedSourceRevision": "e12005607d7c13137efd9c1e146d0ec8489ecf0a",
  "sourceArchiveSha256": "53b75a60bde076af607a36d691f27464745ee6fe9e4e7164c3ceabb3a2afd8a5",
  "sourceInputsMatchCurrent": true,
  "installedBaselinePreserved": true,
  "labVersionOverrideOnly": true,
  "laboratoryOnly": true,
  "semanticProductVersionChanged": false,
  "workspaceProtocolVersion": 1,
  "computerAvailable": true,
  "cleanMachineProven": false,
  "microsoftStoreCertified": false,
  "microsoftStoreSigned": false,
  "nativeArm64Proven": false,
  "buildContractSha256": "d6b9613e639aa7291516ebd33d5bb056b444b4e3133fddf696f512583a1f742f",
  "requiredPayloadSha256": "8ed7e08badb77935b3c481c7e306464cdf3ae9b219d61a91233840434da26c2f",
  "requiredPayloadCount": 7
});
  assert.equal(profile.ai.totalTimeoutSeconds, 600);
  assert.equal(profile.ai.clientPath, "host-codex-ssh-windows-app");
  assert.deepEqual(profile.ai.lifecycleCheckpointEvidence, {
  "baselineVersion": "1.0.0.17",
  "candidateVersion": "1.0.0.19",
  "candidateSha256": "e48a765043a7bd1fef77989dc718df684a91acae0262f14fe70bbc04873cdd3a"
});
  assert.equal(profile.vm.maximumOverlayGiB, 55);
  assert.equal(profile.vm.maximumOverlayGrowthGiB, 2);
  assert.deepEqual(profile.expectedScanners, ["semgrep", "gitleaks", "trivy"]);
  assert.deepEqual(profile.runtimeDelivery, {
    protocolVersion: 7,
    sourceRevision: "e29d96a0b46cd25cde6e3a9b022e177488e869df",
    imageDigest: "sha256:0cf6d1ef378aa8ff72abb04d4f65b35c9ef0b078c04e0501ed701c09762dbce3",
  });
  assert.equal(profile.ai.verifiedEvidence.authorization, "issue-18-verified-flow-20261014");
  assert.match(profile.ai.verifiedEvidence.resultSha256, /^[a-f0-9]{64}$/u);
  assert.match(profile.ai.verifiedEvidence.verificationSha256, /^[a-f0-9]{64}$/u);
});

test("candidate provenance accepts a UTF-8 BOM without weakening JSON parsing", () => {
  assert.deepEqual(parseCandidateProvenance(`\ufeff${JSON.stringify({ schema: "candidate.v1" })}`), {
    schema: "candidate.v1",
  });
  assert.throws(() => parseCandidateProvenance("\ufeffnot-json"), SyntaxError);
});

test("an upgrade checkpoint must match the current candidate and historical evidence cannot substitute", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-upgrade-checkpoint-"));
  const path = resolve(directory, "checkpoint.json");
  const profile = JSON.parse(await readFile(resolve(repositoryRoot, "scanner-profiles/windows-agent-lab.json"), "utf8"));
  const checkpoint = {
    schema: "issue-18-windows-upgrade.v1",
    ...profile.ai.lifecycleCheckpointEvidence,
    sameComputerReused: true,
    durationMs: 123,
    sourceAttempt: "pre-ai-technical-failure",
  };
  try {
    await writeFile(path, JSON.stringify(checkpoint), { mode: 0o600 });
    assert.deepEqual(await loadUpgradeCheckpoint(path, profile), checkpoint);
    await writeFile(path, JSON.stringify({ ...checkpoint, candidateVersion: "1.0.0.14" }));
    await assert.rejects(loadUpgradeCheckpoint(path, profile), /does not match/u);
    await writeFile(path, JSON.stringify({ ...checkpoint, candidateSha256: "0".repeat(64) }));
    await assert.rejects(loadUpgradeCheckpoint(path, profile), /does not match/u);
    await writeFile(path, JSON.stringify({ ...checkpoint, baselineVersion: "1.0.0.13" }));
    await assert.rejects(loadUpgradeCheckpoint(path, profile), /does not match/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the executable one-shot boundary kills descendants and consumes its private marker", async () => {
  const script = resolve(repositoryRoot, "ops/windows-agent-lab/run-codex-once.sh");
  const result = await execFile(script, ["--self-test"], { timeout: 10_000 });
  assert.match(result.stdout, /^one_shot_control=passed\n$/u);
  const content = await readFile(script, "utf8");
  assert.match(content, /setsid "\$@"/u);
  assert.match(content, /kill -KILL -- "-\$1"/u);
  assert.match(content, /kill -TERM -- "-\$watchdog_pid"/u);
  assert.match(content, /set -o noclobber/u);
  assert.match(content, /--ephemeral/u);
  assert.doesNotMatch(content, /--sandbox workspace-write/u);
  assert.match(content, /--approve-for-me/u);
  assert.match(content, /CODEX_BIN="\/home\/linux\/\.local\/bin\/codex"/u);
  assert.match(content, /"\$CODEX_BIN" "\$\{CODEX_EXEC_OPTIONS\[@\]\}"/u);
  assert.doesNotMatch(content, /dangerously-bypass|OPENAI_API_KEY/u);
});

test("the SSH adapter accepts only the public local-client command and fixed synthetic folder", async () => {
  const adapter = resolve(repositoryRoot, "ops/windows-agent-lab/rappor-remote.sh");
  const content = await readFile(adapter, "utf8");
  assert.match(content, /only workspace continue is allowed/u);
  assert.match(content, /C:\\RapporLab\\corpus/u);
  assert.match(content, /\$8 == 1/u);
  const bridge = await readFile(resolve(repositoryRoot, "ops/windows-agent-lab/workspace-interactive.ps1"), "utf8");
  assert.match(bridge, /'--protocol', '1'/u);
  assert.match(bridge, /-LogonType Interactive -RunLevel Limited/u);
  assert.match(bridge, /ToUnixTimeSeconds\(\) -ge \$DeadlineUnix - 10/u);
  assert.doesNotMatch(bridge, /SupervisorRequest|ContinueWorkspace|Invoke-Expression/u);
  assert.doesNotMatch(content, /\beval\b|ssh .*\$@/u);
  assert.equal((await stat(adapter)).mode & 0o111, 0o111);
});

test("guest automation uses only the official MSIX and bounded reversible failures", async () => {
  const guest = await readFile(resolve(repositoryRoot, "ops/windows-agent-lab/guest.ps1"), "utf8");
  assert.match(guest, /Add-AppxPackage -Path \$script:CandidatePath/u);
  assert.match(guest, /installed\.version -ne \$CandidateVersion/u);
  assert.match(guest, /Get-AuthenticodeSignature/u);
  assert.match(guest, /RAPPOR_LAB_RESULT=/u);
  assert.match(guest, /credentialPreserved = \$true/u);
  assert.match(guest, /'--without-heartbeat'/u);
  assert.doesNotMatch(guest, /rappor-connect-windows|WorkspaceBridge|PrepareBaseline/u);

  const runner = await readFile(resolve(repositoryRoot, "src/run-windows-agent-lab.mjs"), "utf8");
  assert.match(runner, /host-codex-mcp-ssh-windows-app/u);
  assert.match(runner, /runAiAnalysis/u);
  assert.match(runner, /CandidateVersion: profile\.delivery\.candidateVersion/u);
  assert.match(runner, /executionMode: "Managed"/u);
  assert.match(runner, /preRotationDiagnosis\.category !== "ready"/u);
  assert.doesNotMatch(runner, /RefreshExpiredConfiguration/u);
  assert.doesNotMatch(runner, /rappor-connect-windows|restoreControlledVm|--restore-vm/u);

  const setup = await readFile(resolve(repositoryRoot, "ops/windows-agent-lab/official-setup.ps1"), "utf8");
  assert.match(setup, /official-setup-' \+ \$bridgeStage \+ '-failed'/u);
  assert.match(setup, /Unregister-ScheduledTask[^\n]+-ErrorAction SilentlyContinue/u);
  assert.doesNotMatch(setup, /\$_.Exception\.Message/u);
});


test("the installed CLI accepts the protected invocation without authentication or inference", async () => {
  const script = resolve(repositoryRoot, "ops/windows-agent-lab/run-codex-once.sh");
  const result = await execFile("bash", [script, "--check-cli"], { timeout: 15_000 });
  assert.equal(result.stdout, "cli_preflight=passed\n");
});

test("the inert preflight rejects conflicting CLI flags before consuming a live attempt", async () => {
  const source = await readFile(resolve(repositoryRoot, "ops/windows-agent-lab/run-codex-once.sh"), "utf8");
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-cli-regression-"));
  try {
    const script = resolve(directory, "conflicting.sh");
    const broken = source.replace(
      "--ignore-user-config --approve-for-me)",
      "--ignore-user-config --sandbox workspace-write --approve-for-me)",
    );
    assert.notEqual(broken, source);
    await writeFile(script, broken);
    await assert.rejects(execFile("bash", [script, "--check-cli"], { timeout: 15_000 }), (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /the inert CLI preflight did not stop at schema validation/u);
      return true;
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

const currentComputer = () => ({ id: "test-computer", state: "Active", online: true,
  hostPlatform: "WindowsDockerDesktopWsl2", protocolVersion: 7,
  capabilities: ["source.current-workspace.v1"], localFolderCompatible: false });

test("first workspace readiness accepts no registered folders and does not compare product releases", () => {
  assert.deepEqual(evaluateCurrentWorkspaceComputer({ ...currentComputer(), agentVersion: "older-release" }, 7),
    { ready: true, failureClass: null });
});

test("an online computer still needs the operation capability and supported protocol", () => {
  assert.equal(evaluateCurrentWorkspaceComputer({ ...currentComputer(), capabilities: [] }, 7).failureClass,
    "current-workspace-capability-missing");
  assert.equal(evaluateCurrentWorkspaceComputer({ ...currentComputer(), protocolVersion: 6 }, 7).failureClass,
    "computer-protocol-update-required");
  assert.equal(evaluateCurrentWorkspaceComputer({ ...currentComputer(), online: false }, 7).failureClass, "computer-offline");
  assert.equal(evaluateCurrentWorkspaceComputer({ ...currentComputer(), state: "Revoked" }, 7).failureClass, "computer-not-active");
});

test("public readiness refuses changed identities and duplicate computers before an AI marker", async () => {
  await assert.rejects(requireCurrentWorkspaceComputer({ agents: async () => ({ agents: [currentComputer()] }) }, "other", 7), /identity changed/u);
  await assert.rejects(requireCurrentWorkspaceComputer({ agents: async () => ({ agents: [currentComputer(), currentComputer()] }) }, "test-computer", 7), /identity changed/u);
  await assert.rejects(requireCurrentWorkspaceComputer({ agents: async () => ({ agents: [{ ...currentComputer(), capabilities: [] }] }) }, "test-computer", 7), /capability-missing/u);
});

function setupFixture(snapshots, computer = currentComputer()) {
  const actions = [];
  let capacityChecks = 0;
  let clock = 0;
  return {
    actions,
    checks: () => capacityChecks,
    options: {
      adapter: { async setupUi(action) {
        actions.push(action);
        if (action === "Open") return { state: "opened" };
        if (action === "Inspect") return { state: "inspected", ...(snapshots.length > 1 ? snapshots.shift() : snapshots[0]) };
        return { state: "invoked", action };
      } },
      client: { agents: async () => ({ agents: [computer] }) },
      computerId: "test-computer", protocolVersion: 7, baseUrl: "https://lab.example/",
      monitorCapacity: async () => { capacityChecks++; }, now: () => clock, timeoutSeconds: 10,
      pause: async () => { clock += 2000; },
    },
  };
}

test("runtime preparation uses the official UI and independently verifies capabilities", async () => {
  const fixture = setupFixture([
    { actions: ["DownloadAgent", "Refresh"] }, { checking: true },
    { actions: ["PrepareAgent", "Refresh"] }, { connected: true },
  ]);
  const result = await prepareOfficialWindowsRuntime(fixture.options);
  assert.deepEqual(result.actions, ["DownloadAgent", "PrepareAgent"]);
  assert.equal(result.computer.id, "test-computer");
  assert.equal(result.durationMs, 8000);
  assert.ok(fixture.checks() >= 7);
  assert.deepEqual(fixture.actions, ["Open", "Inspect", "DownloadAgent", "Inspect", "Inspect", "PrepareAgent", "Inspect"]);
});

test("preparation cannot replace identity, repeat failed updates or accept a cosmetic connected state", async () => {
  const repair = setupFixture([{ repairRequired: true, actions: ["Refresh"] }]);
  await assert.rejects(prepareOfficialWindowsRuntime(repair.options), /replace-preserved-connection/u);
  assert.deepEqual(repair.actions, ["Open", "Inspect"]);
  const repeated = setupFixture([{ actions: ["DownloadAgent"] }, { actions: ["DownloadAgent"] }]);
  await assert.rejects(prepareOfficialWindowsRuntime(repeated.options), /did-not-recover/u);
  assert.equal(repeated.actions.filter((a) => a === "DownloadAgent").length, 1);
  const cosmetic = setupFixture([{ connected: true }], { ...currentComputer(), capabilities: [] });
  await assert.rejects(prepareOfficialWindowsRuntime(cosmetic.options), /capability-missing/u);
});

test("preparation refreshes a stale readiness result once without repeating the update", async () => {
  const fixture = setupFixture([
    { actions: ["PrepareAgent", "Refresh"] }, { actions: ["Refresh"] },
    { checking: true }, { connected: true },
  ]);
  const result = await prepareOfficialWindowsRuntime(fixture.options);
  assert.deepEqual(result.actions, ["PrepareAgent", "Refresh"]);
  assert.equal(result.computer.id, "test-computer");
  assert.equal(fixture.actions.filter((action) => action === "Refresh").length, 1);
  assert.equal(fixture.actions.filter((action) => action === "PrepareAgent").length, 1);
});

test("a persistent readiness failure stops after one refresh and honors capacity gates", async () => {
  const persistent = setupFixture([{ actions: ["Refresh"] }]);
  await assert.rejects(prepareOfficialWindowsRuntime(persistent.options), /refresh-did-not-recover/u);
  assert.equal(persistent.actions.filter((action) => action === "Refresh").length, 1);
  const denied = setupFixture([{ actions: ["Refresh"] }]);
  let checks = 0;
  denied.options.monitorCapacity = async () => { if (++checks === 3) throw Error("capacity-denied"); };
  await assert.rejects(prepareOfficialWindowsRuntime(denied.options), /capacity-denied/u);
  assert.equal(denied.actions.includes("Refresh"), false);
});

test("capacity and missing desktop stop preparation before downloads and do not launch AI", async () => {
  const fixture = setupFixture([]);
  fixture.options.monitorCapacity = async () => { throw new Error("capacity-denied"); };
  await assert.rejects(prepareOfficialWindowsRuntime(fixture.options), /capacity-denied/u);
  assert.deepEqual(fixture.actions, []);
  const desktop = setupFixture([]);
  desktop.options.adapter.setupUi = async () => ({ state: "failed", failureClass: "laboratory-desktop-login-required" });
  await assert.rejects(prepareOfficialWindowsRuntime(desktop.options), /desktop-login-required/u);

  const actionReserve = setupFixture([{ actions: ["DownloadAgent"] }]);
  actionReserve.options.monitorActionCapacity = async () => { throw new Error("reserve-denied"); };
  await assert.rejects(prepareOfficialWindowsRuntime(actionReserve.options), /reserve-denied/u);
  assert.deepEqual(actionReserve.actions, ["Open", "Inspect"]);
});


test("preparation waits for a delayed heartbeat without repeating the update", async () => {
  const fixture = setupFixture([{ connected: true }]);
  let reads = 0;
  fixture.options.client.agents = async () => ({ agents: [{ ...currentComputer(),
    capabilities: ++reads < 3 ? [] : ["source.current-workspace.v1"] }] });
  const result = await prepareOfficialWindowsRuntime(fixture.options);
  assert.equal(result.computer.id, "test-computer");
  assert.equal(reads, 3);
  assert.deepEqual(fixture.actions, ["Open", "Inspect", "Inspect", "Inspect"]);
});

for (const initiallyReady of [true, false]) {
test(`runtime preparation recovers a stopped daemon without AI (initially ready: ${initiallyReady})`, async () => {
  let probeInstalled = false;
  const gib = 1024 ** 3;
  const actions = [];
  const guest = {
    passed: true,
    guestFreeBytes: 20 * gib,
    wsl2: true,
    dockerDesktop: true,
    composeV2: true,
    linuxContainers: true,
    installedVersion: "1.0.0.16",
    packageStatus: "Ok",
  };
  const adapter = {
    async vm(action) {
      return action === "preflight" ? { stdout: `autostart=enable\noverlay_bytes=${20 * gib}\n` } : { stdout: "" };
    },
    async waitForSsh() {},
    async hostFreeBytes() { return 30 * gib; },
    async guest(action) {
      if (action === "InspectCandidate") {
        return { candidateSha256: "a".repeat(64), signatureStatus: "Valid" };
      }
      if (action === "CleanupWorkspace") {
        actions.push("cleanup-workspace");
        return { cleaned: true };
      }
      return initiallyReady || probeInstalled ? guest : { ...guest, passed: false, failureClass: "docker-not-ready" };
    },
    async installGuestProbe() { actions.push("install-guest-probe"); probeInstalled = true; },
    async stageCandidate() { actions.push("stage-candidate"); },
    async setupUi(action) {
      actions.push(action);
      return action === "Open" ? { state: "opened" } : { state: "inspected", connected: true };
    },
  };
  const computer = { ...currentComputer(), protocolVersion: 7 };
  const client = {
    async request(path) {
      assert.equal(path, "/downloads/rappor-windows-delivery.json");
      return { schemaVersion: 1, protocolVersion: 7, revision: "b".repeat(40),
        imageDigest: "sha256:" + "c".repeat(64), runtimePlatform: "linux/amd64",
        supportedHostArchitectures: ["x64", "arm64"] };
    },
    async agents() { return { agents: [computer] }; },
  };
  const profile = {
    vm: { minimumHostFreeGiB: 20, minimumGuestFreeGiB: 10, maximumOverlayGiB: 55, maximumOverlayGrowthGiB: 2 },
    delivery: { candidateVersion: "1.0.0.16", candidateSha256: "a".repeat(64), packageLength: 1024,
      workspaceProtocolVersion: 1 },
    runtimeDelivery: { protocolVersion: 7, sourceRevision: "b".repeat(40),
      imageDigest: "sha256:" + "c".repeat(64) },
    timeoutsSeconds: { sshReady: 30, dockerReady: 30 },
  };
  const result = await prepareWindowsRuntimeOnly({
    adapter,
    client,
    profile,
    baseUrl: "https://lab.example/",
    msixPath: "/protected/candidate.msix",
    delivery: { sha256: "a".repeat(64), signatureStatus: "Valid" },
  });
  assert.deepEqual(result, {
    prepared: true,
    installedVersion: "1.0.0.16",
    signatureVerified: true,
    protocolVersion: 7,
    graphicalSessionUsed: true,
    currentWorkspaceReady: true,
    runtimeSourceRevision: "b".repeat(40),
    runtimeImageDigest: "sha256:" + "c".repeat(64),
    actions: [],
  });
  assert.deepEqual(actions, ["install-guest-probe", "stage-candidate", "Open", "Inspect", "cleanup-workspace"]);
  assert.equal("runAiAnalysis" in adapter, false);
});
}


test("runtime transitions retain capacity checks while ordinary admission requires Docker", async () => {
  const gib = 1024 ** 3;
  const profile = { vm: { minimumHostFreeGiB: 20, minimumGuestFreeGiB: 10,
    maximumOverlayGiB: 55, maximumOverlayGrowthGiB: 2 } };
  let guestFreeBytes = 12 * gib;
  let hostFreeBytes = 22 * gib;
  let overlay = 52 * gib;
  let failureClass = "docker-not-ready";
  const adapter = {
    hostFreeBytes: async () => hostFreeBytes,
    guest: async () => ({ passed: false, failureClass, guestFreeBytes }),
    vm: async () => ({ stdout: `overlay_bytes=${overlay}\n` }),
  };
  const check = () => requireDiskWithinLimits(adapter, profile, 52 * gib, { allowDockerTransition: true });
  await assert.rejects(requireDiskWithinLimits(adapter, profile, 52 * gib), /docker-not-ready/u);
  assert.equal((await check()).guest.passed, false);
  guestFreeBytes = 9 * gib;
  await assert.rejects(check(), /guest-free-space-below-threshold/u);
  guestFreeBytes = 12 * gib; hostFreeBytes = 19 * gib;
  await assert.rejects(check(), /host-free-space-below-threshold/u);
  hostFreeBytes = 22 * gib; overlay = 54 * gib + 1;
  await assert.rejects(check(), /overlay-growth-above-run-limit/u);
  overlay = 56 * gib;
  await assert.rejects(check(), /overlay-above-absolute-limit/u);
  overlay = 52 * gib; failureClass = "unsupported-architecture";
  await assert.rejects(check(), /unsupported-architecture/u);
});


test("native failures retain only an allowlisted readiness phase and no command output", async () => {
  const profile = JSON.parse(await readFile(resolve(repositoryRoot, "scanner-profiles/windows-agent-lab.json"), "utf8"));
  const adapter = new LiveWindowsAdapter({ profile, sshKey: "/unused-test-key" });
  await assert.rejects(adapter.execute(process.execPath, ["-e",
    "console.log('RAPPOR_LAB_PHASE=wsl-status');console.log('RAPPOR_LAB_PHASE=docker-info');console.error('private-test-value');process.exit(7);"], { timeout: 5000 }), (error) => {
    assert.equal(error.laboratoryPhase, "docker-info");
    assert.equal(error.laboratoryExitCode, 7);
    assert.doesNotMatch(error.message, /private-test-value|console/u);
    assert.equal(error.stdout, undefined);
    assert.equal(error.stderr, undefined);
    return true;
  });
  await assert.rejects(adapter.execute(process.execPath, ["-e",
    "console.log('RAPPOR_LAB_PHASE=private-test-value');process.exit(2);"], { timeout: 5000 }), (error) => {
    assert.equal(error.laboratoryPhase, undefined);
    assert.doesNotMatch(error.message, /private-test-value/u);
    return true;
  });
});
