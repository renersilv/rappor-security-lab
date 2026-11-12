import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const WINDOWS_COMMAND_LINE_LIMIT = 8191;
export const POWERSHELL_STDIN_BOOTSTRAP = [
  "$source = [Console]::In.ReadToEnd()",
  "& ([ScriptBlock]::Create($source))",
].join("; ");
export const POWERSHELL_STDIN_BOOTSTRAP_BASE64 = Buffer
  .from(POWERSHELL_STDIN_BOOTSTRAP, "utf16le").toString("base64");
export const POWERSHELL_STDIN_COMMAND =
  `powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ${POWERSHELL_STDIN_BOOTSTRAP_BASE64}`;
export const MAX_POWERSHELL_SOURCE_BYTES = 512 * 1024;

const sha256 = value => createHash("sha256").update(value).digest("hex");

export function createPowerShellStdinTransport(source) {
  assert.equal(typeof source, "string", "powershell-source-must-be-string");
  assert.ok(source.length > 0, "powershell-source-empty");
  assert.doesNotMatch(source, /\u0000/u, "powershell-source-contains-nul");
  assert.doesNotMatch(source, /[^\u0009\u000a\u000d\u0020-\u007e]/u,
    "powershell-source-must-be-ascii");
  const bytes = Buffer.from(source, "utf8");
  assert.ok(bytes.length <= MAX_POWERSHELL_SOURCE_BYTES, "powershell-source-too-large");
  assert.ok(POWERSHELL_STDIN_COMMAND.length < WINDOWS_COMMAND_LINE_LIMIT,
    "powershell-command-line-too-long");
  return Object.freeze({
    remoteCommand: POWERSHELL_STDIN_COMMAND,
    input: source,
    framing: "encoded-bootstrap-reads-complete-stdin",
    bootstrapSha256: sha256(Buffer.from(POWERSHELL_STDIN_BOOTSTRAP, "utf16le")),
    sourceBytes: bytes.length,
    sourceSha256: sha256(bytes),
  });
}

export async function executePowerShellStdin(adapter, source, options = {}) {
  assert.equal(typeof adapter?.execute, "function", "windows-adapter-required");
  assert.ok(Array.isArray(adapter.sshArguments), "windows-adapter-ssh-arguments-required");
  assert.equal(typeof adapter.sshTarget, "string", "windows-adapter-ssh-target-required");
  assert.equal(Object.hasOwn(options, "input"), false, "powershell-input-override-rejected");
  assert.equal(Object.hasOwn(options, "remoteCommandTransport"), false,
    "powershell-remote-transport-override-rejected");
  const transport = createPowerShellStdinTransport(source);
  return adapter.execute("ssh", [
    ...adapter.sshArguments,
    adapter.sshTarget,
    transport.remoteCommand,
  ], {
    ...options,
    input: transport.input,
    remoteCommandTransport: "openssh",
  });
}

export function transportCleanupFromSettlement(settlement) {
  assert.equal(settlement?.schema, 1, "transport-settlement-required");
  assert.equal(typeof settlement.cause, "string", "transport-settlement-cause-required");
  assert.equal(typeof settlement.spawnObserved, "boolean", "transport-spawn-state-required");
  assert.equal(typeof settlement.remoteQuiescenceObserved, "boolean",
    "transport-quiescence-state-required");
  const remoteQuiescence = settlement.remoteQuiescenceObserved === true;
  const remoteCommandNotStarted = settlement.cause === "spawn_error" && settlement.spawnObserved === false;
  const resolved = remoteQuiescence || remoteCommandNotStarted;
  return Object.freeze({
    required: !resolved,
    status: remoteQuiescence ? "verified_remote_quiescence" :
      (remoteCommandNotStarted ? "verified_not_started" : "unresolved"),
    localProcessTerminated: settlement.localProcessTerminated === true,
    remoteCommandTransport: settlement.remoteCommandTransport,
    remoteQuiescenceObserved: remoteQuiescence,
    reason: remoteQuiescence ? "The bounded process closed after an observed remote command exit." :
      (remoteCommandNotStarted ? "The local process failed before the remote command could start." :
        "Local termination does not prove that the remote PowerShell process is quiescent."),
  });
}
