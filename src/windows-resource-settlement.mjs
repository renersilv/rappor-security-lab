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
  "originManifest", "taskName", "guestRoot", "ownershipFiles", "maxDurationMs", "sourceHashes"];
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
function bundleSource(bundle, name, expected, parse = true) {
  const source = bundle.sources?.[name];
  assert.ok(source && (source.omitted === undefined || source.omitted === false) && typeof source.content === "string", "settlement-bundle-source-missing");
  assert.equal(hash(Buffer.from(source.content)), expected, "settlement-bundle-content-mismatch");
  assert.equal(source.sha256, expected, "settlement-bundle-hash-mismatch");
  return parse ? JSON.parse(source.content) : source.content;
}

const earlyEvidenceNames = originPass => ({ transport: `pass${originPass}-transport.json`,
  cleanup: `pass${originPass}-cleanup.json`, runner: `runtime/run-pass${originPass}.mjs`,
  interactive: "runtime/interactive.ps1", observer: "runtime/observe.ps1" });
const earlyFlags = ["inferenceStarted", "mcpToolCallIssued", "scanStarted", "reauthenticationStarted",
  "configurationChanged", "ledgerChanged", "reservationSequence23Consumed"];
const failureCodes = ["nonzero_exit", "timeout", "output_limit", "stdin_error", "stdin_unsettled",
  "ssh_transport_exit", "spawn_error", "process_signal"];
function evidenceReference(bundle, manifest, reference, expectedName, parse = true) {
  closed(reference, ["file", "sha256", "manifestName"], "settlement-origin-evidence-reference");
  assert.match(reference.file, /^[A-Za-z0-9][A-Za-z0-9._-]+$/u);
  assert.match(reference.sha256, HASH);
  assert.equal(reference.manifestName, expectedName, "settlement-origin-evidence-name");
  assert.equal(manifest.files?.[expectedName], reference.sha256, "settlement-origin-evidence-binding");
  const material = bundleSource(bundle, reference.file, reference.sha256, parse);
  if (!parse) assert.ok(material.length > 0, "settlement-origin-source-empty");
  return material;
}
// A completed operation and a failure before its receipt exists are distinct evidence, not versions.
export function validateSettlementOriginEvidence(plan, bundle, manifest) {
  for (const key of ["issue", "authorizationId", "candidate"]) assert.deepEqual(manifest[key], plan[key]);
  assert.equal(manifest.executorPass, plan.originPass);
  const liveName = `live-pass${plan.originPass}-ide-mcp-discovery.json`;
  if (Object.hasOwn(plan, "originRuntimeReceipt")) {
    assert.equal(Object.hasOwn(plan, "originRuntimeEvidence"), false, "settlement-origin-evidence-mixed");
    const runtime = evidenceReference(bundle, manifest, plan.originRuntimeReceipt, liveName);
    for (const key of ["issue", "authorizationId", "candidate"]) assert.deepEqual(runtime[key], plan[key]);
    assert.equal(runtime.executorPass, plan.originPass);
    const interactiveHash = runtime.artifacts?.["runtime/interactive.ps1"];
    const observerHash = runtime.artifacts?.["runtime/observe.ps1"];
    assert.match(interactiveHash, HASH); assert.match(observerHash, HASH);
    return { interactiveHash, observerHash };
  }
  assert.equal(Object.hasOwn(manifest.files, liveName), false, "settlement-early-evidence-has-runtime-receipt");
  const names = earlyEvidenceNames(plan.originPass);
  closed(plan.originRuntimeEvidence, Object.keys(names), "settlement-early-evidence");
  const records = {};
  for (const [key, name] of Object.entries(names)) records[key] = evidenceReference(bundle, manifest,
    plan.originRuntimeEvidence[key], name, key === "transport" || key === "cleanup");
  const { transport, cleanup } = records;
  closed(transport, ["schema", "executorPass", "requestCount", "retryIssued", "operations"], "settlement-early-transport");
  assert.equal(transport.schema, 1); assert.equal(transport.executorPass, plan.originPass);
  assert.equal(transport.retryIssued, false);
  assert.ok(Array.isArray(transport.operations) && transport.operations.length >= 1 && transport.operations.length <= 3);
  assert.equal(transport.requestCount, transport.operations.length);
  const labels = transport.operations.map(operation => operation.label);
  assert.ok([['prepare'], ['prepare', 'settle'], ['prepare', 'signal-and-await', 'settle']]
    .some(expected => JSON.stringify(expected) === JSON.stringify(labels)), "settlement-early-operations-invalid");
  for (const operation of transport.operations) {
    assert.ok(["completed", "failed"].includes(operation.status));
    const keys = ["label", "status", "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes", "settlement",
      ...(operation.status === "failed" ? ["code", "cleanup"] : ["exitCode"])];
    closed(operation, keys, "settlement-early-operation");
    for (const key of ["stdoutSha256", "stderrSha256"]) assert.match(operation[key], HASH);
    for (const key of ["stdoutBytes", "stderrBytes"]) assert.ok(Number.isSafeInteger(operation[key]) && operation[key] >= 0);
    assert.equal(operation.settlement?.schema, 1);
    assert.equal(operation.settlement.remoteCommandTransport, "openssh");
    assert.ok(Number.isSafeInteger(operation.settlement.timeoutMs) && operation.settlement.timeoutMs > 0 && operation.settlement.timeoutMs <= 55000);
    if (operation.status === "failed") {
      assert.ok(failureCodes.includes(operation.code));
      assert.equal(operation.settlement.cause, operation.code);
      assert.equal(typeof operation.cleanup?.required, "boolean");
      assert.ok(["unresolved", "verified_remote_quiescence", "verified_not_started"].includes(operation.cleanup.status));
    } else { assert.equal(operation.exitCode, 0); assert.equal(operation.settlement.cause, "accepted"); }
  }
  assert.equal(transport.operations[0].status, "failed", "settlement-preparation-did-not-fail");
  closed(cleanup, ["schema", "executorPass", "cleanup", ...earlyFlags], "settlement-early-cleanup");
  assert.equal(cleanup.schema, 1); assert.equal(cleanup.executorPass, plan.originPass);
  for (const flag of earlyFlags) assert.equal(cleanup[flag], false, "settlement-early-activity-flag");
  closed(cleanup.cleanup, ["status", "required", "preparationAttempted", "preparationResponseValidated", "code"], "settlement-early-cleanup-state");
  assert.equal(cleanup.cleanup.status, "unresolved"); assert.equal(cleanup.cleanup.required, true);
  assert.equal(cleanup.cleanup.preparationAttempted, true); assert.equal(cleanup.cleanup.preparationResponseValidated, false);
  assert.ok(failureCodes.includes(cleanup.cleanup.code));
  return { interactiveHash: plan.originRuntimeEvidence.interactive.sha256, observerHash: plan.originRuntimeEvidence.observer.sha256 };
}

// Keep five seconds for command propagation before the fixed transport begins termination.
export function settlementTimingEnvelope(timeoutMs) {
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 10000 && timeoutMs <= 45000, "settlement-timeout-invalid");
  return Object.freeze({ timeoutMs, terminationGraceMs: 1000, terminationRequestDeadlineMs: timeoutMs - 2000,
    guestDurationMs: timeoutMs - 7000 });
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
  const forms = ["originRuntimeReceipt", "originRuntimeEvidence"].filter(key => Object.hasOwn(plan, key));
  assert.equal(forms.length, 1, "settlement-origin-evidence-form");
  closed(plan, [...planKeys, forms[0]], "settlement-plan");
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
  assert.match(plan.originManifest.file, /^[a-zA-Z0-9][a-zA-Z0-9._-]+$/u);
  assert.match(plan.originManifest.sha256, HASH);
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
  const { interactiveHash, observerHash } = validateSettlementOriginEvidence(plan, bundle, origin);
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
  if (result.stderr.trim() !== "") {
    throw Object.assign(new Error("settlement-command-stderr"), { code: "SETTLEMENT_STDERR" });
  }
  try { return JSON.parse(result.stdout.trim()); }
  catch { throw Object.assign(new Error("settlement-command-json-invalid"), { code: "SETTLEMENT_JSON_INVALID" }); }
}

const failureReasons = Object.freeze({
  host_identity: "host_identity_rejected", credential_open: "credential_unavailable",
  credential_validation: "credential_changed", transport_probe: "probe_failed",
  resource_cleanup: "cleanup_failed", credential_close: "credential_close_failed",
  source_validation: "source_changed", result_publication: "result_publication_failed",
});
function reasonCode(error, stage) {
  if (stage === "transport_probe") {
    const probeReasons = { SETTLEMENT_STDERR: "probe_stderr", SETTLEMENT_JSON_INVALID: "probe_invalid_json",
      SETTLEMENT_PROBE_MISMATCH: "probe_mismatch" };
    if (Object.hasOwn(probeReasons, error?.code)) return probeReasons[error.code];
  }
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
      try { assert.deepEqual(probe, { schema: 1, probe: nonce, domainUuid: HOST_UUID }); }
      catch { throw Object.assign(new Error("settlement-probe-mismatch"), { code: "SETTLEMENT_PROBE_MISMATCH" }); }
      stage = "source_validation";
      const template = await captureSourceSnapshot(fileURLToPath(new URL("windows-resource-settlement.ps1", import.meta.url)));
      assert.equal(template.sha256, plan.sourceHashes["src/windows-resource-settlement.ps1"]);
      const timeout = remaining();
      if (timeout < 10000) throw Object.assign(new Error("settlement-total-deadline-exhausted"), { code: "SETTLEMENT_DEADLINE" });
      const timing = settlementTimingEnvelope(timeout);
      const script = template.bytes.toString("utf8").replace("__DURATION_MS__", String(timing.guestDurationMs))
        .replaceAll("__ORIGIN_PASS__", String(plan.originPass))
        .replace("__INTERACTIVE_SHA256__", interactiveHash).replace("__OBSERVER_SHA256__", observerHash);
      stage = "resource_cleanup";
      const result = await executePowerShellStdin(adapter, script, { timeout, maxOutputBytes: 32768, terminationGraceMs: timing.terminationGraceMs });
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
