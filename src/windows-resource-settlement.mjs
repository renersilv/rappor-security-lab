import assert from "node:assert/strict";
import { homedir } from "node:os";
import { createHash, randomBytes } from "node:crypto";
import { writeSync } from "node:fs";
import { mkdir, open, realpath, lstat } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { captureProtectedSnapshot, captureSourceSnapshot, readProtectedJson } from "./protected-inputs.mjs";
import { SettlementTransport, openStablePrivateCredential } from "./windows-settlement-transport.mjs";
import { executePowerShellStdin } from "./powershell-stdin-transport.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const HASH = /^[a-f0-9]{64}$/u;
const HOST_UUID = "13918e5c-5b79-4a99-9029-0aa515f5a732";
const HOST_PROBE_SHA = "586bb536d9cd18f576839188af71501e0042e04766b99281351e9ed5852041aa";
const hostIdentityPath = fileURLToPath(new URL("../ops/joao/windows-host-identity.py", import.meta.url));
const sourceNames = ["windows-resource-settlement.mjs", "windows-resource-settlement.ps1",
  "windows-settlement-transport.mjs", "powershell-stdin-transport.mjs", "protected-inputs.mjs"];
const planKeys = ["schema", "kind", "issue", "authorizationId", "candidate", "executorPass", "originPass", "incident",
  "originManifest", "originRuntimeReceipt", "taskName", "guestRoot", "ownershipFiles", "maxDurationMs", "sourceHashes"];
const activityFlags = ["inferenceStarted", "mcpToolCallIssued", "ideLaunched", "appServerLaunched", "scanStarted",
  "reauthenticationStarted", "configurationChanged", "ledgerChanged"];
const closed = (value, keys, label) => {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label}-object`);
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort(), `${label}-keys`);
};
async function writeJson(path, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  const file = await open(path, "wx", 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  const directory = await open(dirname(path), "r");
  try { await directory.sync(); } finally { await directory.close(); }
  return hash(bytes);
}
export async function settlementSources() {
  return { ...Object.fromEntries(await Promise.all(sourceNames.map(async name =>
    [`src/${name}`, (await captureSourceSnapshot(fileURLToPath(new URL(name, import.meta.url)))).sha256]))),
    "ops/joao/windows-host-identity.py": (await captureSourceSnapshot(hostIdentityPath)).sha256 };

}
function bundleSource(bundle, name, expected) {
  const source = bundle.sources?.[name];
  assert.ok(source && (source.omitted === undefined || source.omitted === false) && typeof source.content === "string", "settlement-bundle-source-missing");
  assert.equal(hash(Buffer.from(source.content)), expected, "settlement-bundle-content-mismatch");
  assert.equal(source.sha256, expected, "settlement-bundle-hash-mismatch");
  return JSON.parse(source.content);
}

export async function boundSettlementRequest(args, dependencies = {}) {
  const protectedRoot = dependencies.protectedRoot ?? resolve(homedir(), ".config/rappor-security-lab/campaign-reviews");
  const stateRoot = dependencies.stateRoot ?? resolve(homedir(), ".local/state/rappor-security-lab/joao");
  assert.equal(args.protectedRoot, protectedRoot, "settlement-protected-root-not-authoritative");
  const read = (reference, label) => readProtectedJson(reference, { root: args.protectedRoot, label });
  const { value: request } = await read({ path: args.requestPath, sha256: args.requestSha256 }, "settlement-request");
  closed(request, ["schema", "scope", "checkpoint", "plan", "outputDirectory"], "settlement-request");
  assert.equal(request.schema, 1); assert.equal(request.scope, "settlement_only");
  for (const ref of [request.checkpoint, request.plan]) closed(ref, ["path", "sha256"], "settlement-reference");
  const campaignSnapshot = await captureProtectedSnapshot(resolve(stateRoot, "campaign.json"), "settlement-current-campaign");
  const campaign = JSON.parse(campaignSnapshot.bytes);
  assert.deepEqual(campaign.reviewCheckpoint, request.checkpoint, "settlement-checkpoint-not-current");
  assert.equal(campaign.phase, "active", "settlement-campaign-not-active");
  const { value: checkpoint } = await read(request.checkpoint, "settlement-checkpoint");
  assert.equal(checkpoint.schema, 1); assert.equal(checkpoint.issue, 24); assert.equal(checkpoint.targetIssue, 19);
  const { value: correction } = await read(checkpoint.correction, "settlement-correction");
  const { value: diagnosis } = await read(checkpoint.diagnosis, "settlement-diagnosis");
  assert.equal(correction.scope, "settlement_only"); assert.equal(diagnosis.scope, "settlement_only");
  assert.equal(diagnosis.verdict, "pass"); assert.deepEqual(diagnosis.findings, []); assert.equal(diagnosis.ownerRequest, null);
  const route = correction.technicalRoute;
  assert.equal(route?.phase, "settlement");
  assert.deepEqual(route.settlementPlan, request.plan, "settlement-plan-review-mismatch");
  const { value: plan } = await read(request.plan, "settlement-plan");
  closed(plan, planKeys, "settlement-plan");
  assert.equal(plan.schema, 1); assert.equal(plan.kind, "windows_task_settlement");
  assert.equal(plan.issue, 19); assert.ok(Number.isSafeInteger(plan.originPass) && plan.originPass > 0);
  assert.equal(plan.authorizationId, "issue19-native-windows-20261023");
  assert.ok(Number.isSafeInteger(plan.executorPass) && plan.executorPass > plan.originPass);
  assert.equal(checkpoint.reviewedThroughPass + 1, plan.executorPass, "settlement-review-pass-mismatch");
  assert.equal(campaign.executorPasses, plan.executorPass, "settlement-current-pass-mismatch");
  assert.equal(campaign.lastFinishedPass, checkpoint.reviewedThroughPass, "settlement-prior-pass-not-finished");
  assert.deepEqual(route.cleanupOrigin, { executorPass: plan.originPass, manifestSha256: plan.originManifest.sha256 },
    "settlement-cleanup-origin-mismatch");
  assert.match(plan.incident, HASH); assert.equal(plan.incident, route.incident);
  assert.equal(plan.taskName, `RapporLab-Pass${plan.originPass}-IdeReadiness`);
  assert.equal(plan.guestRoot, `C:\\RapporLab\\runtime\\pass${plan.originPass}-ide-readiness`);
  assert.deepEqual(plan.ownershipFiles, ["owned-processes.json", "observer-ownership.json"]);
  assert.equal(plan.maxDurationMs, 55000);
  closed(plan.candidate, ["origin", "sha", "version"], "settlement-candidate");
  assert.equal(new URL(plan.candidate.origin).origin, plan.candidate.origin);
  assert.match(plan.candidate.sha, /^[a-f0-9]{40}$/u); assert.match(plan.candidate.version, /^v\d+\.\d+\.\d+$/u);
  assert.deepEqual(plan.sourceHashes, await settlementSources(), "settlement-installed-source-mismatch");
  closed(plan.originManifest, ["file", "sha256"], "settlement-origin-manifest");
  closed(plan.originRuntimeReceipt, ["file", "sha256", "manifestName"], "settlement-origin-runtime");
  for (const ref of [plan.originManifest, plan.originRuntimeReceipt]) {
    assert.match(ref.file, /^[a-zA-Z0-9][a-zA-Z0-9._-]+$/u); assert.match(ref.sha256, HASH);
  }
  assert.equal(plan.originRuntimeReceipt.manifestName, `live-pass${plan.originPass}-ide-mcp-discovery.json`);
  const { value: packet } = await read(correction.settlementBundle, "settlement-bundle");
  closed(packet, ["planName", "bundle"], "settlement-bundle");
  const bundle = packet.bundle;
  assert.equal(bundle.executorPass, checkpoint.reviewedThroughPass);
  assert.deepEqual(bundle.candidate, plan.candidate, "settlement-bundle-candidate-mismatch");
  assert.deepEqual(bundle.manifest, correction.manifest, "settlement-reviewed-manifest-mismatch");
  assert.deepEqual(bundleSource(bundle, packet.planName, request.plan.sha256), plan, "settlement-bundle-plan-mismatch");
  // Anchor the historical origin in the protected review chain, not a self-consistent packet.
  let ancestor = checkpoint;
  const seenReviews = new Set();
  while (ancestor.reviewedThroughPass > plan.originPass) {
    const previous = ancestor.previousReview;
    assert.ok(previous && !seenReviews.has(previous.sha256), "settlement-origin-review-chain-invalid");
    seenReviews.add(previous.sha256);
    assert.ok(seenReviews.size <= 1000, "settlement-origin-review-chain-limit");
    const next = (await read(previous, "settlement-origin-review")).value;
    assert.ok(Number.isSafeInteger(next.reviewedThroughPass) && next.reviewedThroughPass < ancestor.reviewedThroughPass,
      "settlement-origin-review-order");
    ancestor = next;
  }
  assert.equal(ancestor.reviewedThroughPass, plan.originPass, "settlement-origin-review-missing");
  const originCorrection = (await read(ancestor.correction, "settlement-origin-correction")).value;
  assert.equal(originCorrection.manifest?.sha256, plan.originManifest.sha256, "settlement-origin-not-reviewed");
  const origin = bundleSource(bundle, plan.originManifest.file, plan.originManifest.sha256);
  const runtime = bundleSource(bundle, plan.originRuntimeReceipt.file, plan.originRuntimeReceipt.sha256);
  assert.equal(origin.files?.[plan.originRuntimeReceipt.manifestName], plan.originRuntimeReceipt.sha256);
  for (const value of [origin, runtime]) {
    assert.equal(value.issue, plan.issue); assert.equal(value.executorPass, plan.originPass);
    assert.equal(value.authorizationId, plan.authorizationId); assert.deepEqual(value.candidate, plan.candidate);
  }
  const interactiveHash = runtime.artifacts?.["runtime/interactive.ps1"];
  const observerHash = runtime.artifacts?.["runtime/observe.ps1"];
  assert.match(interactiveHash, HASH); assert.match(observerHash, HASH);
  const inside = relative(resolve(stateRoot, "tmp"), request.outputDirectory);
  assert.ok(isAbsolute(request.outputDirectory) && inside && !inside.startsWith("../") && inside !== ".." && !isAbsolute(inside),
    "settlement-output-outside-root");
  assert.equal(await realpath(dirname(request.outputDirectory)), dirname(request.outputDirectory), "settlement-output-parent-not-canonical");
  return { request, plan, interactiveHash, observerHash };
}

function parsedResult(result) {
  assert.equal(result.exitCode, 0, "settlement-command-exit");
  assert.equal(result.settlement?.cause, "accepted", "settlement-transport-not-accepted");
  assert.equal(result.settlement.remoteQuiescenceObserved, true, "settlement-transport-unresolved");
  assert.equal(result.settlement.closeObserved, true, "settlement-transport-not-closed");
  assert.equal(result.settlement.stdinEndCallbackObserved, true, "settlement-stdin-not-closed");
  assert.equal(result.stderr.trim(), "", "settlement-command-stderr");
  return JSON.parse(result.stdout.trim());
}

const failureReasons = Object.freeze({
  host_identity: "host_identity_rejected", credential_open: "credential_unavailable",
  credential_validation: "credential_changed", transport_probe: "probe_failed",
  resource_cleanup: "cleanup_failed", credential_close: "credential_close_failed",
  source_validation: "source_changed", result_publication: "result_publication_failed",
});
function reasonCode(error, stage) {
  if (error?.code === "SETTLEMENT_DEADLINE") return "deadline_exhausted";
  const transportReasons = { timeout: "transport_timeout", output_limit: "transport_output_limit",
    stdin_error: "transport_pipe_failure", stdin_unsettled: "transport_pipe_failure",
    ssh_transport_exit: "transport_exit_255", nonzero_exit: "transport_nonzero_exit",
    spawn_error: "transport_start_failed", process_signal: "transport_interrupted",
  };
  const cause = error?.settlement?.cause;
  return Object.hasOwn(transportReasons, cause) ? transportReasons[cause] : failureReasons[stage];
}

export async function settleWindowsResources(args, dependencies = {}) {
  const now = dependencies.now ?? (() => performance.now());
  const started = now();
  const { request, plan, interactiveHash, observerHash } = await boundSettlementRequest(args, dependencies);
  const remaining = () => {
    const result = Math.floor(plan.maxDurationMs - (now() - started));
    if (result <= 1000) throw Object.assign(new Error("settlement-total-deadline-exhausted"), { code: "SETTLEMENT_DEADLINE" });
    return Math.min(45000, result);
  };
  remaining();
  // Exclusive directory is the durable one-shot intent. A different output path cannot replay this plan.
  const reservationPath = resolve(dirname(request.plan.path), `settlement-${request.plan.sha256}.intent.json`);
  const intentSha256 = await writeJson(reservationPath, { schema: 1, requestSha256: args.requestSha256, planSha256: request.plan.sha256,
    checkpoint: request.checkpoint, outputDirectory: request.outputDirectory });
  await mkdir(request.outputDirectory, { mode: 0o700 });
  const metadata = await lstat(request.outputDirectory);
  assert.equal(metadata.uid, process.getuid()); assert.equal(metadata.mode & 0o777, 0o700);
  assert.equal(await realpath(request.outputDirectory), request.outputDirectory);
  let credential;
  let guest;
  let stage = "host_identity";
  let failedStage;
  try {
    try {
      const hostTimeout = Math.min(15000, remaining());
      const identityResult = await (dependencies.runHostIdentity ?? (timeout => new SettlementTransport("/unused").execute(
        "/usr/bin/python3", ["-B", hostIdentityPath], { input: "", timeout, maxOutputBytes: 8192 })))(hostTimeout);
      const identity = parsedResult(identityResult);
      assert.equal(identity.result, "verified", "settlement-host-unverified");
      assert.equal(identity.schemaVersion, 1);
      assert.equal(identity.domain, "joao-windows-x64");
      assert.equal(identity.domainUuid, HOST_UUID, "settlement-host-uuid-mismatch");
      assert.equal(identity.sourceSha256, HOST_PROBE_SHA, "settlement-host-probe-mismatch");
      assert.equal(identity.executable, "/usr/bin/qemu-system-x86_64");
      assert.equal(identity.generationStable, true);
      assert.equal(identity.listenerOwnedByExactDomainProcess, true);
      assert.equal(identity.listenerAddress, "127.0.0.1");
      assert.equal(identity.listenerPort, 2222); assert.equal(identity.guestPort, 22);
      for (const flag of ["guestCommandExecuted", "vmMutated", "permissionsChanged"]) assert.equal(identity[flag], false);
      await writeJson(resolve(request.outputDirectory, "host-identity.json"), identity);
      remaining();
      stage = "credential_open";
      credential = await (dependencies.openCredential ?? openStablePrivateCredential)(process.env.RAPPOR_WINDOWS_SSH_KEY);
      stage = "credential_validation";
      await credential.assertStable();
      const adapter = (dependencies.createTransport ?? (key => new SettlementTransport(key)))(credential.consumerPath);
      const nonce = randomBytes(16).toString("hex");
      stage = "transport_probe";
      const probe = parsedResult(await executePowerShellStdin(adapter,
        `[ordered]@{ schema = 1; probe = '${nonce}'; domainUuid = [string](Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop).UUID.ToLowerInvariant() } | ConvertTo-Json -Compress\n`,
        { timeout: Math.min(8000, remaining()), maxOutputBytes: 16384 }));
      assert.deepEqual(probe, { schema: 1, probe: nonce, domainUuid: HOST_UUID }, "settlement-probe-mismatch");
      stage = "source_validation";
      const template = await captureSourceSnapshot(fileURLToPath(new URL("windows-resource-settlement.ps1", import.meta.url)));
      assert.equal(template.sha256, plan.sourceHashes["src/windows-resource-settlement.ps1"]);
      const timeout = remaining();
      const script = template.bytes.toString("utf8").replace("__DURATION_MS__", String(timeout - 2500))
        .replaceAll("__ORIGIN_PASS__", String(plan.originPass))
        .replace("__INTERACTIVE_SHA256__", interactiveHash).replace("__OBSERVER_SHA256__", observerHash);
      stage = "resource_cleanup";
      const result = await executePowerShellStdin(adapter, script, { timeout, maxOutputBytes: 32768 });
      guest = parsedResult(result);
      assert.deepEqual(guest, { schema: 1, kind: "windows_task_settlement_guest", taskAbsent: true, rootAbsent: true,
        ownershipVerified: true, remainingOwnedProcesses: 0 }, "settlement-guest-result-incomplete");
      stage = "credential_validation";
      await credential.assertStable();
    } catch (error) {
      failedStage = stage;
      throw error;
    } finally {
      if (credential) {
        try { stage = "credential_close"; await credential.close(); }
        catch (error) { failedStage = stage; throw error; }
      }
    }
    stage = "source_validation";
    remaining();
    assert.deepEqual(plan.sourceHashes, await settlementSources(), "settlement-source-changed-during-execution");
    const elapsedMs = Math.ceil(now() - started);
    assert.ok(elapsedMs <= plan.maxDurationMs, "settlement-total-deadline-exhausted");
    const receipt = {
      schema: 1, kind: "windows_task_settlement_result",
      ...Object.fromEntries(["issue", "authorizationId", "candidate", "executorPass", "originPass", "incident",
        "taskName", "guestRoot", "sourceHashes"].map(key => [key, plan[key]])),
      checkpointSha256: request.checkpoint.sha256, intentSha256,
      planSha256: request.plan.sha256, outcome: "settled", taskAbsent: true, rootAbsent: true,
      ownershipVerified: true, remainingOwnedProcesses: 0, transportProbeVerified: true, elapsedMs,
      ...Object.fromEntries(activityFlags.map(key => [key, false])),
    };
    stage = "result_publication";
    const receiptPath = resolve(request.outputDirectory, "settlement-result.json");
    return { receiptPath, receiptSha256: await writeJson(receiptPath, receipt), intentPath: reservationPath, intentSha256, outcome: "settled" };
  } catch (error) {
    const failureStage = failedStage ?? stage;
    // Only closed local enums are retained; never error.message or remote stdout/stderr.
    await writeJson(resolve(request.outputDirectory, "settlement-unresolved.json"), {
      schema: 1, kind: "windows_task_settlement_unresolved", planSha256: request.plan.sha256,
      checkpointSha256: request.checkpoint.sha256, intentSha256,
      outcome: "unresolved", failedStage: failureStage, reasonCode: reasonCode(error, failureStage),
      elapsedMs: Math.ceil(now() - started),
    });
    throw new Error("windows-resource-settlement-unresolved");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    assert.equal(process.argv.length, 5, "usage-request-path-sha256-protected-root");
    const [requestPath, requestSha256, protectedRoot] = process.argv.slice(2);
    writeSync(1, `${JSON.stringify(await settleWindowsResources({ requestPath, requestSha256, protectedRoot }))}\n`);
  } catch { writeSync(2, "windows-resource-settlement-unresolved\n"); process.exitCode = 1; }
}
