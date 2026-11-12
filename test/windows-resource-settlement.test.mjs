import assert from "node:assert/strict";
import test from "node:test";
import { readFile, rm } from "node:fs/promises";
import { settleWindowsResources } from "../src/windows-resource-settlement.mjs";
import { settlementFixture } from "./support-settlement-fixture.mjs";

async function fixture(t, options) {
  const value = await settlementFixture(options);
  t.after(() => rm(value.root, { recursive: true, force: true })); return value;
}
test("settlement requires the current review and publishes only after credential closure", async t => {
  let value;
  value = await fixture(t, { onClose: async () => assert.equal(await value.exists("settlement-result.json"), false) });
  const result = await settleWindowsResources(value.args, value.dependencies);
  assert.equal(result.outcome, "settled"); assert.equal(value.closed, true); assert.equal(value.calls, 2);
  const receipt = await value.receipt();
  assert.equal(receipt.originPass, 220); assert.equal(receipt.executorPass, 223);
  assert.equal(receipt.inferenceStarted, false); assert.equal(receipt.transportProbeVerified, true);
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /EEXIST/u);
  assert.equal(value.calls, 2);
});
for (const [name, options] of [
  ["different origin with unchanged protected checkpoint", { mutatePlan: p => { p.originPass = 219; p.taskName = "RapporLab-Pass219-IdeReadiness"; p.guestRoot = "C:\\RapporLab\\runtime\\pass219-ide-readiness"; } }],
  ["noncanonical doubled separators", { mutatePlan: p => { p.guestRoot = p.guestRoot.replaceAll("\\", "\\\\"); } }],
  ["wrong task", { mutatePlan: p => { p.taskName = "OtherTask"; } }],
  ["arbitrary command", { mutatePlan: p => { p.command = "Remove-Item C:\\"; } }],
  ["renewed deadline", { mutatePlan: p => { p.maxDurationMs = 60000; } }],
  ["source replacement", { mutatePlan: p => { p.sourceHashes["src/windows-resource-settlement.ps1"] = "0".repeat(64); } }],
  ["unreviewed historical copy", { unreviewedOrigin: true }],
  ["obsolete checkpoint", { mutateCampaign: c => { c.reviewCheckpoint.sha256 = "0".repeat(64); } }],
  ["wrong current pass", { mutateCampaign: c => { c.executorPasses++; } }],
  ["inactive campaign", { mutateCampaign: c => { c.phase = "review_pending"; } }],
]) test(`settlement rejects ${name} before any transport`, async t => {
  const value = await fixture(t, options);
  await assert.rejects(settleWindowsResources(value.args, value.dependencies));
  assert.equal(value.calls, 0); assert.equal(await value.exists("settlement-result.json"), false);
});
for (const [name, mutation] of [
  ["unconfirmed remote exit", r => { r.settlement.remoteQuiescenceObserved = false; }],
  ["SSH exit 255", r => { r.exitCode = 255; }],
  ["empty output", r => { r.stdout = ""; }],
  ["partial result", r => { r.stdout = '{"taskAbsent":true}'; }],
  ["stderr", r => { r.stderr = "guest-error"; }],
]) test(`settlement retains unresolved after ${name}`, async t => {
  const value = await fixture(t, { mutateResult: (r, call) => { if (call === 2) mutation(r); } });
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  assert.equal(value.closed, true); assert.equal(await value.exists("settlement-result.json"), false);
  assert.equal(await value.exists("settlement-unresolved.json"), true);
});
test("credential close failure cannot publish settlement", async t => {
  const value = await fixture(t, { onClose: async () => { throw Error("close-failed"); } });
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  assert.equal(await value.exists("settlement-result.json"), false);
});
test("changing output path does not renew the intent", async t => {
  const value = await fixture(t);
  await settleWindowsResources(value.args, value.dependencies);
  value.request.outputDirectory += "-another";
  const ref = await value.put("request-other.json", value.request);
  await assert.rejects(settleWindowsResources({ ...value.args, requestPath: ref.path, requestSha256: ref.sha256 }, value.dependencies), /EEXIST/u);
  assert.equal(value.calls, 2);
});

test("probe and cleanup share one deadline without renewing the budget", async t => {
  let elapsed = 0;
  const value = await fixture(t, { onExecute: async (execution, call) => {
    if (call === 1) { assert.equal(execution.timeout, 8000); elapsed = 41000; }
    else { assert.equal(execution.timeout, 14000); elapsed = 50000; }
  } });
  value.dependencies.now = () => elapsed;
  await settleWindowsResources(value.args, value.dependencies);
  assert.equal((await value.receipt()).elapsedMs, 50000);
});
test("credential closure cannot extend the total deadline", async t => {
  let elapsed = 0;
  const value = await fixture(t, { onClose: async () => { elapsed = 56000; } });
  value.dependencies.now = () => elapsed;
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  assert.equal(await value.exists("settlement-result.json"), false);
});

for (const [name, options] of [
  ["wrong host UUID", { mutateHostIdentity: value => { value.domainUuid = "wrong-host"; } }],
  ["wrong host listener", { mutateHostIdentity: value => { value.listenerOwnedByExactDomainProcess = false; } }],
  ["host identity timeout", { onHostIdentity: async () => { throw Error("timeout"); } }],
]) test(`${name} cannot start the guest`, async t => {
  const value = await fixture(t, options);
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  assert.equal(value.calls, 0); assert.equal(value.closed, false);
  assert.equal(await value.exists("settlement-result.json"), false);
});
test("host identity cannot consume the budget and then start cleanup", async t => {
  let elapsed = 0;
  const value = await fixture(t, { onHostIdentity: async timeout => { assert.equal(timeout, 15000); elapsed = 55000; } });
  value.dependencies.now = () => elapsed;
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  assert.equal(value.calls, 0);
});

for (const [stage, reason, options] of [
  ["host_identity", "host_identity_rejected", { mutateHostIdentity: value => { value.domainUuid = "untrusted-secret"; } }],
  ["credential_open", "credential_unavailable", { onOpen: async () => { throw Error("secret-key-path"); } }],
  ["credential_validation", "credential_changed", { onStable: async () => { throw Error("secret-key-bytes"); } }],
  ["transport_probe", "probe_invalid_json", { mutateResult: (value, call) => { if (call === 1) value.stdout = "secret-token"; } }],
  ["transport_probe", "probe_stderr", { mutateResult: (value, call) => { if (call === 1) value.stderr = "secret-remote-error"; } }],
  ["transport_probe", "probe_mismatch", { mutateResult: (value, call) => { if (call === 1) value.stdout = JSON.stringify({schema:1,probe:"secret-nonce",domainUuid:"secret-uuid"}); } }],
  ["resource_cleanup", "cleanup_failed", { mutateResult: (value, call) => { if (call === 2) value.stderr = "secret-password"; } }],
  ["credential_close", "credential_close_failed", { onClose: async () => { throw Error("secret-descriptor"); } }],
  ["resource_cleanup", "transport_timeout", { onExecute: async (_execution, call) => { if (call === 2) throw Object.assign(Error("secret-timeout"), { settlement: { cause: "timeout" }, stderr: "secret-remote-output" }); } }],
]) test(`unresolved receipt identifies ${stage}/${reason} without sensitive details`, async t => {
  const value = await fixture(t, options);
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  const receipt = await value.unresolved();
  assert.equal(receipt.failedStage, stage); assert.equal(receipt.reasonCode, reason);
  assert.doesNotMatch(JSON.stringify(receipt), /secret|password|token/u);
  assert.equal(await value.exists("settlement-result.json"), false);
});

for (const omitted of [true, null, 0, "false"]) test(`settlement rejects an invalid omitted source flag: ${JSON.stringify(omitted)}`, async t => {
  const value = await fixture(t);
  const read = async ref => JSON.parse(await readFile(ref.path, "utf8"));
  const checkpoint = await read(value.request.checkpoint);
  const correction = await read(checkpoint.correction);
  const packet = await read(correction.settlementBundle);
  packet.bundle.sources[packet.planName].omitted = omitted;
  correction.settlementBundle = await value.put("invalid-bundle.json", packet);
  checkpoint.correction = await value.put("invalid-correction.json", correction);
  const checkpointRef = await value.put("invalid-checkpoint.json", checkpoint);
  const campaign = await read({path: `${value.dependencies.stateRoot}/campaign.json`});
  campaign.reviewCheckpoint = checkpointRef;
  await value.put("campaign.json", campaign, value.dependencies.stateRoot);
  value.request.checkpoint = checkpointRef;
  const request = await value.put("invalid-request.json", value.request);
  await assert.rejects(settleWindowsResources({...value.args, requestPath:request.path, requestSha256:request.sha256},value.dependencies), /settlement-bundle-source-missing/u);
  assert.equal(value.calls,0);
});
