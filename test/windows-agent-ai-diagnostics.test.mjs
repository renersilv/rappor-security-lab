import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { captureDiagnostics } from "../src/capture-windows-agent-ai-diagnostics.mjs";

const execFile = promisify(execFileCallback);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const collector = resolve(root, "src/capture-windows-agent-ai-diagnostics.mjs");
const wrapper = resolve(root, "ops/windows-agent-lab/run-codex-once.sh");

test("schema errors retain only known contract fields and static failure reasons", async () => {
  const message = "Invalid schema for response_format 'SYNTHETIC_SECRET': In context=('properties', 'clientPath'), schema must have a 'type' key.";
  const result = await captureDiagnostics(Readable.from([
    JSON.stringify({ type: "turn.failed", error: { message } }) + "\n",
  ]), () => {});
  assert.deepEqual(result.schemaTargets, ["final-response"]);
  assert.deepEqual(result.schemaContexts, ["clientPath", "properties", "type"]);
  assert.deepEqual(result.schemaReasons, ["missing-type"]);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_SECRET/u);
});

test("a failed shell permission boundary is categorized without retaining tool output", async () => {
  const result = await captureDiagnostics(Readable.from([
    JSON.stringify({ type: "item.completed", item: { type: "command_execution", exit_code: 255,
      aggregated_output: "socket: Operation not permitted SYNTHETIC_PRIVATE_VALUE" } }) + "\n",
  ]), () => {});
  assert.deepEqual(result.failureClasses, ["permission-refused"]);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE_VALUE/u);
});

test("the adapter uses scoped approval while preserving the refusal boundary", async () => {
  const source = await readFile(wrapper, "utf8");
  assert.match(source, /approval_policy="on-request"/u);
  assert.match(source, /--approve-for-me/u);
  assert.match(source, /request the normal scoped shell-tool approval/u);
  assert.match(source, /If approval is denied or unavailable, stop/u);
  assert.doesNotMatch(source, /network_access\s*=\s*true|danger-full-access|approval_policy="never"/u);
});

test("the startup failure from an empty prompt has an explicit diagnostic category", async () => {
  const result = await captureDiagnostics(Readable.from(["No prompt provided via stdin.\n"]), () => {});
  assert.deepEqual(result.failureClasses, ["missing-prompt"]);
});

test("the inert preflight rejects a background runner that discards the prompt", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-prompt-regression-"));
  try {
    const scripts = resolve(directory, "ops/windows-agent-lab");
    await mkdir(scripts, { recursive: true });
    await mkdir(resolve(directory, "src"));
    await writeFile(resolve(directory, "src/capture-windows-agent-ai-diagnostics.mjs"), await readFile(collector));
    const source = await readFile(wrapper, "utf8");
    const broken = source.replace('setsid "$@" <&0 &', 'setsid "$@" &');
    assert.notEqual(broken, source);
    const script = resolve(scripts, "run-codex-once.sh");
    await writeFile(script, broken);
    await assert.rejects(execFile("bash", [script, "--check-diagnostics"], { timeout: 10000 }), (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /codex_process_exit=18 diagnostic_capture_exit=0/u);
      return true;
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("diagnostics preserve event stages and classify failure without retaining private payloads", async () => {
  const secret = "SYNTHETIC_PRIVATE_CANARY";
  const records = [];
  const result = await captureDiagnostics(Readable.from([
    JSON.stringify({ type: "thread.started", thread_id: secret }) + "\n",
    JSON.stringify({ type: "item.completed", item: { text: secret, command: secret } }) + "\n",
    JSON.stringify({ type: "turn.failed", error: { message: `Invalid schema for response_format ${secret} https://private.invalid/?token=${secret}` } }) + "\n",
  ]), (record) => records.push(record));
  assert.equal(records[0].streamClosed, false);
  assert.equal(result.streamClosed, true);
  assert.equal(result.lastEvent, "turn.failed");
  assert.equal(result.eventCounts["thread.started"], 1);
  assert.deepEqual(result.failureClasses, ["schema-rejected"]);
  assert.doesNotMatch(JSON.stringify(records), /SYNTHETIC_PRIVATE_CANARY|private\.invalid|response_format/u);
});

test("stderr, malformed JSON and unknown errors produce only closed categories", async () => {
  const result = await captureDiagnostics(Readable.from([
    "TLS certificate failure Authorization: Bearer SYNTHETIC_SECRET\n",
    '{"type":"error","message":"unrecognized failure with SYNTHETIC_SECRET"}\n',
    '{"type":"SYNTHETIC_SECRET","message":"ignored"}\n',
    "{malformed:SYNTHETIC_SECRET}\n",
  ]), () => {});
  assert.deepEqual(result.failureClasses, ["network-failed", "unclassified-error"]);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_SECRET|Bearer|Authorization/u);
});

test("oversized lines cannot grow retained diagnostics and subsequent errors remain readable", async () => {
  const result = await captureDiagnostics(Readable.from([
    Buffer.alloc(40000, 65), Buffer.alloc(40000, 65), Buffer.alloc(1000000, 65),
    Buffer.from('\n{"type":"turn.failed","error":{"message":"quota exceeded"}}'),
  ]), () => {});
  assert.equal(result.oversizedLine, true);
  assert.equal(result.lastEvent, "turn.failed");
  assert.deepEqual(result.failureClasses, ["quota-or-rate-limit"]);
  assert.ok(JSON.stringify(result).length < 2048);
});

test("successful agent text cannot masquerade as a diagnostic error", async () => {
  const result = await captureDiagnostics(Readable.from([
    '{"type":"item.completed","item":{"text":"authentication failed"}}\n',
    '{"type":"turn.completed","usage":{"private":"SECRET"}}\n',
  ]), () => {});
  assert.equal(result.lastEvent, "turn.completed");
  assert.deepEqual(result.failureClasses, []);
});

test("reported review refusal stays separate from directly observed tool failures", async () => {
  const result = await captureDiagnostics(Readable.from([
    JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: JSON.stringify({
      outcome: "refused", summaryCode: "automatic-review-rejected-network-approval-sandbox-conflict",
      private: "SYNTHETIC_SECRET",
    }) } }) + "\n",
  ]), () => {});
  assert.deepEqual(result.failureClasses, []);
  assert.deepEqual(result.failedToolTypes, []);
  assert.deepEqual(result.agentReportedFailureClasses, ["automatic-review-denied", "permission-refused", "sandbox-conflict"]);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_SECRET/u);
});

test("failed command without an exit code retains review categories without the rationale", async () => {
  const records = [];
  const result = await captureDiagnostics(Readable.from([
    JSON.stringify({ type: "item.completed", item: { type: "command_execution", status: "failed",
      aggregated_output: "Automatic review rejected: sandbox conflict. SYNTHETIC_PRIVATE_RATIONALE" } }) + "\n",
  ]), (record) => records.push(record));
  assert.deepEqual(result.failureClasses, ["automatic-review-denied", "permission-refused", "sandbox-conflict"]);
  assert.deepEqual(result.failedToolTypes, ["command_execution"]);
  assert.deepEqual(result.agentReportedFailureClasses, []);
  assert.equal(records.at(-2).streamClosed, false);
  assert.deepEqual(records.at(-2).failureClasses, result.failureClasses);
  assert.doesNotMatch(JSON.stringify(records), /SYNTHETIC_PRIVATE_RATIONALE/u);
});

test("a completed command with no error status is not a permission failure", async () => {
  const result = await captureDiagnostics(Readable.from([
    JSON.stringify({ type: "item.completed", item: { type: "command_execution", status: "completed",
      aggregated_output: "Documentation example: automatic review rejected" } }) + "\n",
  ]), () => {});
  assert.deepEqual(result.failureClasses, []);
  assert.deepEqual(result.failedToolTypes, []);
});

test("the inert wrapper preserves nonzero child status through successful capture", async () => {
  const result = await execFile("bash", [wrapper, "--check-diagnostics"], { timeout: 10000 });
  assert.equal(result.stdout, "diagnostic_capture=passed\n");
  assert.match(result.stderr, /codex_process_exit=17 diagnostic_capture_exit=0/u);
  assert.doesNotMatch(result.stderr, /synthetic diagnostic probe/u);
});

test("a fast child does not leave a delayed watchdog holding the execution lock", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-delayed-watchdog-"));
  try {
    await writeFile(resolve(directory, "setsid"), `#!/usr/bin/env bash
if [[ $1 == bash && $2 == -c ]]; then
  case "$3" in *'sleep "$2"'*) sleep 0.2 ;; esac
fi
exec /usr/bin/setsid "$@"
`, { mode: 0o700 });
    const result = await execFile("bash", [wrapper, "--check-diagnostics"], {
      timeout: 5000, env: { ...process.env, PATH: directory + ":" + process.env.PATH },
    });
    assert.equal(result.stdout, "diagnostic_capture=passed\n");
    assert.match(result.stderr, /codex_process_exit=17 diagnostic_capture_exit=0/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a broken collector fails the inert preflight before a live attempt is possible", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-diagnostic-failure-"));
  try {
    const source = await readFile(wrapper, "utf8");
    const script = resolve(directory, "wrapper.sh");
    const altered = source.replace('node "$DIAGNOSTIC_CAPTURE" "$diagnostic_file"', '/bin/false');
    assert.notEqual(altered, source);
    await writeFile(script, altered);
    await assert.rejects(execFile("bash", [script, "--check-diagnostics"]), (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /diagnostic_capture_exit=1/u);
      return true;
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("collector files are private and symlinks fail without disclosing their target", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-diagnostic-file-"));
  try {
    const output = resolve(directory, "output.json");
    await writeFile(output, "", { mode: 0o644 });
    // An empty pipe closes immediately; this does not invoke Codex.
    await execFile("bash", ["-c", 'printf "" | node "$1" "$2"', "--", collector, output]);
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.equal(JSON.parse(await readFile(output, "utf8")).streamClosed, true);
    const link = resolve(directory, "private-symlink.json");
    await symlink(output, link);
    const before = await readFile(output, "utf8");
    await assert.rejects(execFile("bash", ["-c", 'printf "" | node "$1" "$2"', "--", collector, link]), (error) => {
      assert.equal(error.code, 1);
      assert.equal(error.stderr, "ai_diagnostic_capture=failed\n");
      return true;
    });
    assert.equal(await readFile(output, "utf8"), before);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
