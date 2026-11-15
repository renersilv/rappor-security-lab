import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import test from "node:test";
import { boundSettlementRequest, settleWindowsResources, settlementTimingEnvelope } from "../src/windows-resource-settlement.mjs";
import { settlementFixture } from "./support-settlement-fixture.mjs";

async function fixture(t, options = {}) {
  const value = await settlementFixture({ earlyFailure: true, ...options });
  t.after(() => rm(value.root, { recursive: true, force: true }));
  return value;
}
for (const earlyFailure of [false, true]) test(`the authentic ${earlyFailure ? "early failure" : "runtime receipt"} form validates`, async t => {
  const value = await fixture(t, { earlyFailure });
  const result = await boundSettlementRequest(value.args, value.dependencies);
  assert.equal(result.plan.originPass, earlyFailure ? 226 : 220);
  assert.match(result.interactiveHash, /^[a-f0-9]{64}$/u);
  assert.equal(Object.hasOwn(result.plan, "originRuntimeReceipt"), !earlyFailure);
  assert.equal(value.calls, 0);
});
const invalid = [
  ["missing evidence", { mutatePlan: p => { delete p.originRuntimeEvidence; } }],
  ["mixed forms", { mutatePlan: p => { p.originRuntimeReceipt = { file: "invented.json", sha256: "a".repeat(64), manifestName: "live-pass226-ide-mcp-discovery.json" }; } }],
  ["extra evidence field", { mutatePlan: p => { p.originRuntimeEvidence.command = "arbitrary"; } }],
  ["different pending origin", { mutatePlan: p => { p.originPass = 225; p.taskName = "RapporLab-Pass225-IdeReadiness"; p.guestRoot = "C:\\RapporLab\\runtime\\pass225-ide-readiness"; } }],
  ["unprotected origin", { unreviewedOrigin: true }],
  ["missing runner", { mutatePacket: p => { delete p.bundle.sources["origin-runner.mjs"]; } }],
  ["forged script bytes", { mutatePacket: p => { p.bundle.sources["origin-interactive.ps1"].content += "changed"; } }],
  ["wrong manifest entry", { mutatePlan: p => { p.originRuntimeEvidence.runner.manifestName = "runtime/run-pass225.mjs"; } }],
  ["transport pass mismatch", { mutateEarlyEvidence: e => { e.transport.executorPass++; } }],
  ["cleanup pass mismatch", { mutateEarlyEvidence: e => { e.cleanup.executorPass++; } }],
  ["activation in early evidence", { mutateEarlyEvidence: e => { e.transport.operations[1].label = "activate"; } }],
  ["preparation was successful", { mutateEarlyEvidence: e => { e.transport.operations[0] = { ...e.transport.operations[1], label: "prepare" }; } }],
  ["request count mismatch", { mutateEarlyEvidence: e => { e.transport.requestCount++; } }],
  ["retry issued", { mutateEarlyEvidence: e => { e.transport.retryIssued = true; } }],
  ["validated preparation response", { mutateEarlyEvidence: e => { e.cleanup.cleanup.preparationResponseValidated = true; } }],
  ["already resolved cleanup", { mutateEarlyEvidence: e => { e.cleanup.cleanup.status = "verified"; } }],
  ["contradictory runtime receipt", { mutateEarlyManifest: m => { m.files["live-pass226-ide-mcp-discovery.json"] = "a".repeat(64); } }],
];
for (const flag of ["inferenceStarted", "mcpToolCallIssued", "scanStarted", "reauthenticationStarted",
  "configurationChanged", "ledgerChanged", "reservationSequence23Consumed"]) {
  invalid.push([`${flag} true`, { mutateEarlyEvidence: e => { e.cleanup[flag] = true; } }]);
  invalid.push([`${flag} missing`, { mutateEarlyEvidence: e => { delete e.cleanup[flag]; } }]);
}
for (const [name, options] of invalid) test(`early settlement rejects ${name}`, async t => {
  const value = await fixture(t, options);
  await assert.rejects(boundSettlementRequest(value.args, value.dependencies));
  assert.equal(value.calls, 0); assert.equal(await value.exists("settlement-result.json"), false);
});
test("guest deadline leaves a fixed propagation margin before transport termination", () => {
  for (const timeout of [10000, 14000, 45000]) {
    const timing = settlementTimingEnvelope(timeout);
    assert.equal(timing.timeoutMs, timeout); assert.equal(timing.terminationGraceMs, 1000);
    assert.equal(timing.terminationRequestDeadlineMs - timing.guestDurationMs, 5000);
    assert.ok(timing.guestDurationMs > 0 && timing.terminationRequestDeadlineMs < timeout);
  }
  for (const timeout of [9999, 45001, 55000, NaN, 10000.5]) assert.throws(() => settlementTimingEnvelope(timeout));
});

test("insufficient time after the probe records deadline exhaustion without cleanup", async t => {
  let elapsed = 0;
  const value = await fixture(t, { onExecute: async (_execution, call) => {
    assert.equal(call, 1, "cleanup must not start with an insufficient remaining budget");
    elapsed = 47000;
  } });
  value.dependencies.now = () => elapsed;
  await assert.rejects(settleWindowsResources(value.args, value.dependencies), /unresolved/u);
  const unresolved = await value.unresolved();
  assert.equal(unresolved.failedStage, "source_validation");
  assert.equal(unresolved.reasonCode, "deadline_exhausted");
  assert.equal(value.calls, 1); assert.equal(value.closed, true);
  assert.equal(await value.exists("settlement-result.json"), false);
});
