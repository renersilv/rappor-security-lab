#!/usr/bin/env node

import { createHash } from "node:crypto";
import { chmod, lstat, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const AUTHORIZATION_ID = "issue19-ai-20261016";
const AUTHORIZATION_EXTENSION_ID = "issue19-ai-20261016-extension-1";
const CLIENTS = new Set(["cli-linux", "ide-windows"]);
const OUTCOMES = new Set(["completed", "failed", "refused", "needs-owner-action", "timed-out"]);
const ORIGINAL_MAX_STARTS = 4;
const EXTENDED_MAX_STARTS = 5;
const ORIGINAL_CLI_LINUX_LIMIT = 2;
const EXTENDED_CLI_LINUX_LIMIT = 3;
const IDE_WINDOWS_LIMIT = 2;

function fail(code) {
  throw new Error(code);
}

async function readPrivateJson(path, missingAllowed = false) {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if (missingAllowed && error?.code === "ENOENT") return null;
    fail("private-file-unavailable");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o777) !== 0o600) {
    fail("private-file-boundary-changed");
  }
  try {
    return { bytes: await readFile(path), metadata };
  } catch {
    fail("private-file-unreadable");
  }
}

function verifyAuthorization(value) {
  const expected = {
    authorizationId: AUTHORIZATION_ID,
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
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value?.[key] !== expectedValue) fail("authorization-contract-changed");
  }
}

function verifyAuthorizationExtension(value, originalAuthorizationHash) {
  const expected = {
    schemaVersion: 1,
    amendmentId: AUTHORIZATION_EXTENSION_ID,
    authorizationId: AUTHORIZATION_ID,
    issue: 19,
    consumedStartsAtAuthorization: 2,
    additionalStarts: 1,
    maxStarts: EXTENDED_MAX_STARTS,
    maxCliLinuxStarts: EXTENDED_CLI_LINUX_LIMIT,
    reservedIdeWindowsStarts: IDE_WINDOWS_LIMIT,
    maxSecondsPerRun: 600,
    sequentialOnly: true,
    consumeBeforeStart: true,
    countFailedStarts: true,
    persistentConsumptionRequired: true,
    allowOpenAiApiKey: false,
    allowNewVm: false,
    doesNotResetIssue18: true,
    preserveOriginalReceiptAndAttempts: true,
  };
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value?.[key] !== expectedValue) fail("authorization-extension-contract-changed");
  }
  if (value.originalAuthorizationReceiptSha256 !== originalAuthorizationHash ||
      !/^[a-f0-9]{64}$/u.test(value.consumptionStateSha256AtAuthorization ?? "") ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$/u.test(value.authorizedAtUtc ?? "") ||
      typeof value.authorizationSource !== "string" || value.authorizationSource.length < 1 ||
      value.authorizationSource.length > 160) {
    fail("authorization-extension-contract-changed");
  }
}

function verifyAttempt(attempt, index) {
  if (attempt?.sequence !== index + 1 || !CLIENTS.has(attempt.client) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(attempt.startedAtUtc ?? "") ||
      !["started", ...OUTCOMES].includes(attempt.outcome)) {
    fail("consumption-history-invalid");
  }
  if (attempt.outcome === "started") {
    if (attempt.endedAtUtc !== null || attempt.processExit !== null) fail("consumption-history-invalid");
  } else if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(attempt.endedAtUtc ?? "") ||
      !Number.isInteger(attempt.processExit) || attempt.processExit < 0 || attempt.processExit > 255) {
    fail("consumption-history-invalid");
  }
}

function verifyState(value, authorizationHash, extension = null) {
  if (![1, 2].includes(value?.schemaVersion) || value.authorizationId !== AUTHORIZATION_ID ||
      value.authorizationReceiptSha256 !== authorizationHash ||
      !Array.isArray(value.attempts) || value.attempts.length > value.maxStarts) {
    fail("consumption-state-invalid");
  }
  if (value.schemaVersion === 1 && value.maxStarts !== ORIGINAL_MAX_STARTS) {
    fail("consumption-state-invalid");
  }
  if (value.schemaVersion === 2 && (!extension || value.maxStarts !== EXTENDED_MAX_STARTS ||
      value.maxCliLinuxStarts !== EXTENDED_CLI_LINUX_LIMIT ||
      value.reservedIdeWindowsStarts !== IDE_WINDOWS_LIMIT ||
      value.authorizationExtensionReceiptSha256 !== extension.hash ||
      value.consumptionStateSha256AtAuthorization !== extension.value.consumptionStateSha256AtAuthorization)) {
    fail(extension ? "consumption-state-invalid" : "authorization-extension-required");
  }
  value.attempts.forEach(verifyAttempt);
  if (value.attempts.filter(({ outcome }) => outcome === "started").length > 1) {
    fail("consumption-history-invalid");
  }
}

function extendedState(state, extension) {
  return {
    schemaVersion: 2,
    authorizationId: state.authorizationId,
    authorizationReceiptSha256: state.authorizationReceiptSha256,
    authorizationExtensionReceiptSha256: extension.hash,
    consumptionStateSha256AtAuthorization: extension.value.consumptionStateSha256AtAuthorization,
    maxStarts: EXTENDED_MAX_STARTS,
    maxCliLinuxStarts: EXTENDED_CLI_LINUX_LIMIT,
    reservedIdeWindowsStarts: IDE_WINDOWS_LIMIT,
    attempts: state.attempts,
  };
}

async function load(authorizationPath, statePath, extensionPath = null) {
  const authorizationRecord = await readPrivateJson(authorizationPath);
  let authorization;
  try {
    authorization = JSON.parse(authorizationRecord.bytes.toString("utf8"));
  } catch {
    fail("authorization-receipt-invalid");
  }
  verifyAuthorization(authorization);
  const authorizationHash = createHash("sha256").update(authorizationRecord.bytes).digest("hex");
  let extension = null;
  if (extensionPath) {
    const extensionRecord = await readPrivateJson(extensionPath);
    let value;
    try {
      value = JSON.parse(extensionRecord.bytes.toString("utf8"));
    } catch {
      fail("authorization-extension-invalid");
    }
    verifyAuthorizationExtension(value, authorizationHash);
    extension = { value, hash: createHash("sha256").update(extensionRecord.bytes).digest("hex") };
  }
  const stateRecord = await readPrivateJson(statePath, true);
  if (!stateRecord) {
    if (extension) fail("authorization-extension-state-changed");
    return {
      authorization,
      state: { schemaVersion: 1, authorizationId: AUTHORIZATION_ID,
        authorizationReceiptSha256: authorizationHash, maxStarts: ORIGINAL_MAX_STARTS, attempts: [] },
      extensionActive: false,
    };
  }
  let state;
  try {
    state = JSON.parse(stateRecord.bytes.toString("utf8"));
  } catch {
    fail("consumption-state-invalid");
  }
  if (state.schemaVersion === 1) {
    verifyState(state, authorizationHash);
    if (extension) {
      const stateHash = createHash("sha256").update(stateRecord.bytes).digest("hex");
      if (stateHash !== extension.value.consumptionStateSha256AtAuthorization ||
          state.attempts.length !== extension.value.consumedStartsAtAuthorization ||
          state.attempts.some(({ outcome }) => outcome === "started")) {
        fail("authorization-extension-state-changed");
      }
      state = extendedState(state, extension);
    }
  } else {
    verifyState(state, authorizationHash, extension);
  }
  return { authorization, state, extensionActive: stateRecord && stateRecord.bytes &&
    JSON.parse(stateRecord.bytes.toString("utf8")).schemaVersion === 2 };
}

async function writeAtomic(path, value) {
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, path);
  } catch {
    await unlink(temporary).catch(() => {});
    fail("consumption-state-write-failed");
  }
}

function parseArguments(arguments_) {
  const [command, ...rest] = arguments_;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    if (!rest[index]?.startsWith("--") || rest[index + 1] === undefined) fail("invalid-arguments");
    options[rest[index].slice(2)] = rest[index + 1];
  }
  if (!command || !options.authorization || !options.state) fail("invalid-arguments");
  return { command, options };
}

export async function reserveAttempt({ authorizationPath, extensionPath = null, statePath, client,
  now = new Date() }) {
  if (!CLIENTS.has(client)) fail("invalid-reservation");
  const { state } = await load(resolve(authorizationPath), resolve(statePath),
    extensionPath ? resolve(extensionPath) : null);
  if (state.attempts.some(({ outcome }) => outcome === "started")) fail("attempt-already-active");
  if (state.attempts.length >= state.maxStarts) fail("authorization-exhausted");
  const clientLimit = client === "cli-linux" ?
    (state.schemaVersion === 2 ? state.maxCliLinuxStarts : ORIGINAL_CLI_LINUX_LIMIT) :
    (state.schemaVersion === 2 ? state.reservedIdeWindowsStarts : IDE_WINDOWS_LIMIT);
  if (state.attempts.filter((attempt) => attempt.client === client).length >= clientLimit) {
    fail("client-authorization-exhausted");
  }
  const sequence = state.attempts.length + 1;
  state.attempts.push({ sequence, client, startedAtUtc: now.toISOString().replace(/\.\d{3}Z$/u, "Z"),
    endedAtUtc: null, outcome: "started", processExit: null });
  await writeAtomic(resolve(statePath), state);
  return sequence;
}

export async function finishAttempt({ authorizationPath, extensionPath = null, statePath, sequence, outcome,
  processExit, now = new Date() }) {
  if (!Number.isInteger(sequence) || !OUTCOMES.has(outcome) || !Number.isInteger(processExit) ||
      processExit < 0 || processExit > 255) fail("invalid-completion");
  const { state } = await load(resolve(authorizationPath), resolve(statePath),
    extensionPath ? resolve(extensionPath) : null);
  const attempt = state.attempts[sequence - 1];
  if (!attempt || attempt.sequence !== sequence || attempt.outcome !== "started") fail("attempt-not-active");
  attempt.endedAtUtc = now.toISOString().replace(/\.\d{3}Z$/u, "Z");
  attempt.outcome = outcome;
  attempt.processExit = processExit;
  await writeAtomic(resolve(statePath), state);
}

export async function consumptionStatus({ authorizationPath, extensionPath = null, statePath }) {
  const { state, extensionActive } = await load(resolve(authorizationPath), resolve(statePath),
    extensionPath ? resolve(extensionPath) : null);
  const maxCliLinuxStarts = state.schemaVersion === 2 ? state.maxCliLinuxStarts : ORIGINAL_CLI_LINUX_LIMIT;
  const maxIdeWindowsStarts = state.schemaVersion === 2 ? state.reservedIdeWindowsStarts : IDE_WINDOWS_LIMIT;
  return {
    authorizationId: state.authorizationId,
    maxStarts: state.maxStarts,
    maxCliLinuxStarts,
    maxIdeWindowsStarts,
    consumedStarts: state.attempts.length,
    remainingStarts: state.maxStarts - state.attempts.length,
    cliLinuxStarts: state.attempts.filter(({ client }) => client === "cli-linux").length,
    ideWindowsStarts: state.attempts.filter(({ client }) => client === "ide-windows").length,
    extensionActive,
    active: state.attempts.some(({ outcome }) => outcome === "started"),
    outcomes: state.attempts.map(({ sequence, client, outcome }) => ({ sequence, client, outcome })),
  };
}

async function main() {
  const { command, options } = parseArguments(process.argv.slice(2));
  const common = { authorizationPath: options.authorization, extensionPath: options.extension,
    statePath: options.state };
  if (command === "reserve") {
    const sequence = await reserveAttempt({ ...common, client: options.client });
    process.stdout.write(`${sequence}\n`);
  } else if (command === "finish") {
    await finishAttempt({ ...common, sequence: Number.parseInt(options.sequence, 10), outcome: options.outcome,
      processExit: Number.parseInt(options["process-exit"], 10) });
    process.stdout.write("attempt_completion=recorded\n");
  } else if (command === "status") {
    process.stdout.write(`${JSON.stringify(await consumptionStatus(common))}\n`);
  } else {
    fail("invalid-command");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`issue19_consumption_control=${error.message}\n`);
    process.exitCode = 1;
  });
}
