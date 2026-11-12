// Narrow stdin transport extracted from the reviewed pass222 adapter; no VM lifecycle API.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { isAbsolute } from "node:path";
const fail = message => { throw new Error(message); };
function assertPrivateRegularFile(metadata, label) {
  assert.ok(metadata.isFile(), `${label}-must-be-regular`);
  assert.equal(metadata.uid, process.getuid(), `${label}-owner-mismatch`);
  assert.equal(metadata.mode & 0o777, 0o600, `${label}-mode-mismatch`);
}
export async function openStablePrivateCredential(path, label = "private-credential", maxBytes = 131072) {
  assert.ok(isAbsolute(path), `${label}-path-must-be-absolute`);
  assert.ok(Number.isInteger(maxBytes) && maxBytes > 0, `${label}-max-size-invalid`);
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error?.code === "ELOOP") assert.fail(`${label}-must-not-be-symlink`);
    throw error;
  }
  try {
    const metadata = await file.stat();
    assertPrivateRegularFile(metadata, label);
    assert.ok(metadata.size > 0 && metadata.size <= maxBytes, `${label}-size-invalid`);
    const descriptorPath = `/proc/${process.pid}/fd/${file.fd}`;
    assert.equal(await realpath(descriptorPath), path, `${label}-descriptor-path-mismatch`);
    assert.equal(await realpath(path), path, `${label}-realpath-mismatch`);
    const verificationBuffer = Buffer.alloc(metadata.size);
    let offset = 0;
    while (offset < verificationBuffer.length) {
      const { bytesRead } = await file.read(verificationBuffer, offset,
        verificationBuffer.length - offset, offset);
      assert.ok(bytesRead > 0, `${label}-short-read`);
      offset += bytesRead;
    }
    const verifiedMetadata = await file.stat();
    for (const field of ["dev", "ino", "uid", "mode", "size", "mtimeMs", "ctimeMs"]) {
      assert.equal(verifiedMetadata[field], metadata[field], `${label}-changed-during-validation`);
    }
    let closed = false;
    return Object.freeze({
      consumerPath: descriptorPath,
      sourcePath: path,
      async assertStable() {
        assert.equal(closed, false, `${label}-already-closed`);
        const current = await file.stat();
        for (const field of ["dev", "ino", "uid", "mode", "size", "mtimeMs"]) {
          assert.equal(current[field], metadata[field], `${label}-descriptor-changed`);
        }
        const currentBytes = Buffer.alloc(current.size);
        let currentOffset = 0;
        while (currentOffset < currentBytes.length) {
          const { bytesRead } = await file.read(currentBytes, currentOffset,
            currentBytes.length - currentOffset, currentOffset);
          assert.ok(bytesRead > 0, `${label}-stable-short-read`);
          currentOffset += bytesRead;
        }
        assert.deepEqual(currentBytes, verificationBuffer, `${label}-descriptor-content-changed`);
        return true;
      },
      async close() {
        if (closed) return;
        closed = true;
        await file.close();
      },
    });
  } catch (error) {
    await file.close();
    throw error;
  }
}

export class SettlementTransport {
  constructor(sshKey) {
    this.sshTarget = "joao@127.0.0.1";
    this.sshArguments = ["-F", "/dev/null", "-p", "2222", "-i", sshKey,
      "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
      "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"];
  }
  async execute(file, arguments_, {
    input,
    timeout = 300_000,
    acceptedExitCodes = [0],
    environment,
    maxOutputBytes = 16 * 1024 * 1024,
    terminationGraceMs,
    remoteCommandTransport = "local_process",
  } = {}) {
    if (input !== undefined) {
      if (!Number.isInteger(timeout) || timeout < 3) fail("the bounded command timeout is invalid");
      terminationGraceMs ??= Math.min(1_000, Math.max(1, Math.floor((timeout - 1) / 6)));
      if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 1) {
        fail("the bounded command output limit is invalid");
      }
      if (!Number.isInteger(terminationGraceMs) || terminationGraceMs < 1 ||
        terminationGraceMs * 2 >= timeout) {
        fail("the bounded command termination grace is invalid");
      }
      if (!["local_process", "openssh"].includes(remoteCommandTransport)) {
        fail("the bounded command remote transport is invalid");
      }
      return new Promise((resolvePromise, rejectPromise) => {
        const child = spawn(file, arguments_, { stdio: ["pipe", "pipe", "pipe"], env: environment ?? process.env });
        const stdoutChunks = [];
        const stderrChunks = [];
        let outputBytesSeen = 0;
        let outputBytesRetained = 0;
        let outputTruncated = false;
        let spawnObserved = false;
        let closeObserved = false;
        let stdinEndCallbackObserved = false;
        let terminationCause = null;
        let sigtermSent = false;
        let sigkillSent = false;
        let settled = false;
        let escalationTimer;
        let forcedSettlementTimer;
        const startedAt = Date.now();
        const terminationRequestDeadlineMs = timeout - (terminationGraceMs * 2);
        const escalationDeadlineMs = timeout - terminationGraceMs;
        const deadlineGuardMs = Math.min(50, Math.max(1, Math.floor(terminationGraceMs / 2)));
        const forcedSettlementDeadlineMs = timeout - deadlineGuardMs;

        const clearTimers = () => {
          clearTimeout(terminationRequestTimer);
          clearTimeout(forcedSettlementDeadlineTimer);
          clearTimeout(escalationTimer);
          clearTimeout(forcedSettlementTimer);
        };
        const retainedOutput = () => ({
          stdout: Buffer.concat(stdoutChunks).toString("utf8"),
          stderr: Buffer.concat(stderrChunks).toString("utf8"),
        });
        const settlement = ({ cause, exitCode = null, signal = null, localProcessTerminated,
          remoteCommandExitObserved }) => Object.freeze({
          schema: 1,
          cause,
          exitCode,
          signal,
          spawnObserved,
          closeObserved,
          stdinEndCallbackObserved,
          timeoutMs: timeout,
          terminationGraceMs,
          terminationRequestDeadlineMs,
          escalationDeadlineMs,
          forcedSettlementDeadlineMs,
          hardSettlementDeadlineMs: timeout,
          elapsedMs: Math.max(0, Date.now() - startedAt),
          outputLimitBytes: maxOutputBytes,
          outputBytesSeen,
          outputBytesRetained,
          outputTruncated,
          sigtermSent,
          sigkillSent,
          localProcessTerminated,
          remoteCommandTransport,
          remoteCommandExitObserved,
          remoteQuiescenceObserved: remoteCommandExitObserved,
          cleanupRequired: spawnObserved && !remoteCommandExitObserved,
        });
        const rejectWithSettlement = (message, value, output = retainedOutput()) => {
          if (settled) return;
          settled = true;
          clearTimers();
          const failure = new Error(message);
          failure.name = "BoundedProcessExecutionError";
          failure.settlement = value;
          failure.stdout = output.stdout;
          failure.stderr = output.stderr;
          failure.exitCode = value.exitCode;
          rejectPromise(failure);
        };
        const forceUnclosedSettlement = () => {
          if (settled || closeObserved) return;
          rejectWithSettlement(`a bounded laboratory command did not settle (${file})`, settlement({
            cause: terminationCause ?? "timeout",
            localProcessTerminated: false,
            remoteCommandExitObserved: false,
          }));
        };
        const requestTermination = (cause) => {
          if (settled || closeObserved) return;
          terminationCause ??= cause;
          if (!sigtermSent) sigtermSent = child.kill("SIGTERM");
          const elapsedMs = Math.max(0, Date.now() - startedAt);
          const untilEscalation = Math.max(0, escalationDeadlineMs - elapsedMs);
          const untilForcedSettlement = Math.max(0, forcedSettlementDeadlineMs - elapsedMs);
          escalationTimer ??= setTimeout(() => {
            if (settled || closeObserved) return;
            sigkillSent = child.kill("SIGKILL") || sigkillSent;
          }, Math.min(terminationGraceMs, untilEscalation));
          forcedSettlementTimer ??= setTimeout(forceUnclosedSettlement,
            Math.min(terminationGraceMs * 2, untilForcedSettlement));
        };
        const retain = chunks => chunk => {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          outputBytesSeen += bytes.length;
          const available = Math.max(0, maxOutputBytes - outputBytesRetained);
          const retained = Math.min(available, bytes.length);
          if (retained > 0) chunks.push(bytes.subarray(0, retained));
          outputBytesRetained += retained;
          if (retained < bytes.length) {
            outputTruncated = true;
            requestTermination("output_limit");
          }
        };
        child.stdout.on("data", retain(stdoutChunks));
        child.stderr.on("data", retain(stderrChunks));
        child.once("spawn", () => { spawnObserved = true; });
        child.stdin.once("error", () => requestTermination("stdin_error"));
        const terminationRequestTimer = setTimeout(() => requestTermination("timeout"),
          terminationRequestDeadlineMs);
        const forcedSettlementDeadlineTimer = setTimeout(() => {
          if (settled || closeObserved) return;
          terminationCause ??= "timeout";
          sigkillSent = child.kill("SIGKILL") || sigkillSent;
          forceUnclosedSettlement();
        }, forcedSettlementDeadlineMs);
        child.once("error", () => {
          rejectWithSettlement(`a bounded laboratory command could not start (${file})`, settlement({
            cause: "spawn_error",
            localProcessTerminated: true,
            remoteCommandExitObserved: false,
          }));
        });
        child.once("close", (code) => {
          if (settled) return;
          closeObserved = true;
          const output = retainedOutput();
          const signal = child.signalCode ?? null;
          const numericExitCode = typeof code === "number" ? code : null;
          const opensshTransportFailure = remoteCommandTransport === "openssh" && numericExitCode === 255;
          const remoteCommandExitObserved = terminationCause === null && spawnObserved &&
            stdinEndCallbackObserved && signal === null && numericExitCode !== null &&
            !opensshTransportFailure;
          const cause = terminationCause ?? (!stdinEndCallbackObserved ? "stdin_unsettled" :
            (signal !== null ? "process_signal" : (opensshTransportFailure ? "ssh_transport_exit" :
              (acceptedExitCodes.includes(code) ? "accepted" : "nonzero_exit"))));
          const value = settlement({
            cause,
            exitCode: numericExitCode,
            signal,
            localProcessTerminated: true,
            remoteCommandExitObserved,
          });
          if (cause === "accepted") {
            settled = true;
            clearTimers();
            resolvePromise({ ...output, exitCode: code, settlement: value });
            return;
          }
          rejectWithSettlement(`a bounded laboratory command failed (${file}, exit ${code ?? -1})`, value, output);
        });
        child.stdin.end(input, error => {
          if (error) {
            requestTermination("stdin_error");
            return;
          }
          stdinEndCallbackObserved = true;
        });
      });
    }
    throw new Error("settlement-stdin-required");
  }
}
