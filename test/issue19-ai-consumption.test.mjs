import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { consumptionStatus, finishAttempt, reserveAttempt } from "../src/issue19-ai-consumption.mjs";

const authorization = {
  authorizationId: "issue19-ai-20261016",
  issue: 19,
  maxStarts: 4,
  maxSecondsPerRun: 600,
  sequentialOnly: true,
  consumeBeforeStart: true,
  countFailedStarts: true,
  persistentConsumptionRequired: true,
  allowOpenAiApiKey: false,
  allowNewVm: false,
  doesNotResetIssue18: true,
};

async function fixture() {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-issue19-consumption-"));
  const authorizationPath = resolve(directory, "authorization.json");
  const extensionReceiptPath = resolve(directory, "authorization-extension.json");
  const statePath = resolve(directory, "state.json");
  await writeFile(authorizationPath, JSON.stringify(authorization), { mode: 0o600 });
  return { directory, authorizationPath, extensionReceiptPath, statePath };
}

async function writeExtension(value, overrides = {}) {
  const original = await readFile(value.authorizationPath);
  const state = await readFile(value.statePath);
  const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const extension = {
    schemaVersion: 1,
    amendmentId: "issue19-ai-20261016-extension-1",
    authorizationId: "issue19-ai-20261016",
    issue: 19,
    authorizedAtUtc: "2026-10-17T15:00:00.123456+00:00",
    authorizationSource: "unit-test",
    originalAuthorizationReceiptSha256: hash(original),
    consumptionStateSha256AtAuthorization: hash(state),
    consumedStartsAtAuthorization: 2,
    additionalStarts: 1,
    maxStarts: 5,
    maxCliLinuxStarts: 3,
    reservedIdeWindowsStarts: 2,
    maxSecondsPerRun: 600,
    sequentialOnly: true,
    allowOpenAiApiKey: false,
    allowNewVm: false,
    consumeBeforeStart: true,
    countFailedStarts: true,
    persistentConsumptionRequired: true,
    doesNotResetIssue18: true,
    preserveOriginalReceiptAndAttempts: true,
    ...overrides,
  };
  await writeFile(value.extensionReceiptPath, JSON.stringify(extension), { mode: 0o600 });
}

test("a start is persisted before completion and every outcome remains consumed", async () => {
  const value = await fixture();
  try {
    const sequence = await reserveAttempt({ ...value, client: "cli-linux",
      now: new Date("2026-10-16T18:00:00Z") });
    assert.equal(sequence, 1);
    assert.equal((await stat(value.statePath)).mode & 0o777, 0o600);
    let status = await consumptionStatus(value);
    assert.equal(status.consumedStarts, 1);
    assert.equal(status.active, true);
    await assert.rejects(reserveAttempt({ ...value, client: "cli-linux" }), /attempt-already-active/u);
    await finishAttempt({ ...value, sequence, outcome: "failed", processExit: 1,
      now: new Date("2026-10-16T18:01:00Z") });
    status = await consumptionStatus(value);
    assert.equal(status.remainingStarts, 3);
    assert.deepEqual(status.outcomes, [{ sequence: 1, client: "cli-linux", outcome: "failed" }]);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("the CLI slice stops at two starts while preserving two starts for IDE/Windows", async () => {
  const value = await fixture();
  try {
    for (let sequence = 1; sequence <= 2; sequence += 1) {
      assert.equal(await reserveAttempt({ ...value, client: "cli-linux" }), sequence);
      await finishAttempt({ ...value, sequence, outcome: "timed-out", processExit: 124 });
    }
    await assert.rejects(reserveAttempt({ ...value, client: "cli-linux" }),
      /client-authorization-exhausted/u);
    assert.equal(await reserveAttempt({ ...value, client: "ide-windows" }), 3);
    const status = await consumptionStatus(value);
    assert.equal(status.remainingStarts, 1);
    assert.equal(status.cliLinuxStarts, 2);
    assert.equal(status.ideWindowsStarts, 1);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("the audited extension atomically preserves two attempts and enforces the 5/3/2 limits", async () => {
  const value = await fixture();
  try {
    for (let sequence = 1; sequence <= 2; sequence += 1) {
      assert.equal(await reserveAttempt({ ...value, client: "cli-linux" }), sequence);
      await finishAttempt({ ...value, sequence, outcome: "needs-owner-action", processExit: 0 });
    }
    const originalState = JSON.parse(await readFile(value.statePath, "utf8"));
    await writeExtension(value);
    let status = await consumptionStatus(value);
    assert.equal(status.maxStarts, 4);
    status = await consumptionStatus({ ...value, extensionPath: value.extensionReceiptPath });
    assert.equal(status.maxStarts, 5);
    assert.equal(status.maxCliLinuxStarts, 3);
    assert.equal(status.maxIdeWindowsStarts, 2);
    assert.equal(status.extensionActive, false);

    assert.equal(await reserveAttempt({ ...value, extensionPath: value.extensionReceiptPath,
      client: "cli-linux" }), 3);
    const activated = JSON.parse(await readFile(value.statePath, "utf8"));
    assert.equal(activated.schemaVersion, 2);
    assert.deepEqual(activated.attempts.slice(0, 2), originalState.attempts);
    assert.match(activated.authorizationReceiptSha256, /^[a-f0-9]{64}$/u);
    assert.match(activated.authorizationExtensionReceiptSha256, /^[a-f0-9]{64}$/u);
    await finishAttempt({ ...value, extensionPath: value.extensionReceiptPath, sequence: 3,
      outcome: "timed-out", processExit: 124 });
    await assert.rejects(reserveAttempt({ ...value, extensionPath: value.extensionReceiptPath,
      client: "cli-linux" }), /client-authorization-exhausted/u);

    for (let sequence = 4; sequence <= 5; sequence += 1) {
      assert.equal(await reserveAttempt({ ...value, extensionPath: value.extensionReceiptPath,
        client: "ide-windows" }), sequence);
      await finishAttempt({ ...value, extensionPath: value.extensionReceiptPath, sequence,
        outcome: "failed", processExit: 1 });
    }
    status = await consumptionStatus({ ...value, extensionPath: value.extensionReceiptPath });
    assert.equal(status.consumedStarts, 5);
    assert.equal(status.remainingStarts, 0);
    assert.equal(status.cliLinuxStarts, 3);
    assert.equal(status.ideWindowsStarts, 2);
    assert.equal(status.extensionActive, true);
    await assert.rejects(reserveAttempt({ ...value, extensionPath: value.extensionReceiptPath,
      client: "ide-windows" }), /authorization-exhausted/u);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("the extension fails closed if its receipt or authorized history changes", async () => {
  const value = await fixture();
  try {
    for (let sequence = 1; sequence <= 2; sequence += 1) {
      await reserveAttempt({ ...value, client: "cli-linux" });
      await finishAttempt({ ...value, sequence, outcome: "failed", processExit: 1 });
    }
    await writeExtension(value, { maxStarts: 6 });
    await assert.rejects(consumptionStatus({ ...value, extensionPath: value.extensionReceiptPath }),
      /authorization-extension-contract-changed/u);
    await writeExtension(value);
    const state = JSON.parse(await readFile(value.statePath, "utf8"));
    await writeFile(value.statePath, JSON.stringify(state, null, 2), { mode: 0o600 });
    await assert.rejects(reserveAttempt({ ...value, extensionPath: value.extensionReceiptPath,
      client: "cli-linux" }), /authorization-extension-state-changed/u);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("activated history requires the exact private extension receipt", async () => {
  const value = await fixture();
  try {
    for (let sequence = 1; sequence <= 2; sequence += 1) {
      await reserveAttempt({ ...value, client: "cli-linux" });
      await finishAttempt({ ...value, sequence, outcome: "failed", processExit: 1 });
    }
    await writeExtension(value);
    await reserveAttempt({ ...value, extensionPath: value.extensionReceiptPath, client: "cli-linux" });
    await assert.rejects(consumptionStatus(value), /authorization-extension-required/u);
    const extension = JSON.parse(await readFile(value.extensionReceiptPath, "utf8"));
    extension.authorizationSource = "changed-after-activation";
    await writeFile(value.extensionReceiptPath, JSON.stringify(extension), { mode: 0o600 });
    await assert.rejects(consumptionStatus({ ...value, extensionPath: value.extensionReceiptPath }),
      /consumption-state-invalid/u);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("changed authorization and consumption receipts fail closed", async () => {
  const value = await fixture();
  try {
    await writeFile(value.authorizationPath, JSON.stringify({ ...authorization, maxStarts: 5 }), { mode: 0o600 });
    await assert.rejects(reserveAttempt({ ...value, client: "cli-linux" }),
      /authorization-contract-changed/u);
    await writeFile(value.authorizationPath, JSON.stringify(authorization), { mode: 0o600 });
    await reserveAttempt({ ...value, client: "cli-linux" });
    const state = JSON.parse(await readFile(value.statePath, "utf8"));
    state.maxStarts = 5;
    await writeFile(value.statePath, JSON.stringify(state), { mode: 0o600 });
    await assert.rejects(consumptionStatus(value), /consumption-state-invalid/u);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("private receipt modes are enforced", async () => {
  const value = await fixture();
  try {
    await chmod(value.authorizationPath, 0o644);
    await assert.rejects(consumptionStatus(value), /private-file-boundary-changed/u);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});

test("the authorization extension must remain a private regular file", async () => {
  const value = await fixture();
  try {
    for (let sequence = 1; sequence <= 2; sequence += 1) {
      await reserveAttempt({ ...value, client: "cli-linux" });
      await finishAttempt({ ...value, sequence, outcome: "failed", processExit: 1 });
    }
    await writeExtension(value);
    await chmod(value.extensionReceiptPath, 0o644);
    await assert.rejects(consumptionStatus({ ...value, extensionPath: value.extensionReceiptPath }),
      /private-file-boundary-changed/u);
  } finally {
    await rm(value.directory, { recursive: true, force: true });
  }
});
