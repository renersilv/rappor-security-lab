import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { SettlementTransport, openStablePrivateCredential } from "../src/windows-settlement-transport.mjs";
import { executePowerShellStdin, POWERSHELL_STDIN_COMMAND } from "../src/powershell-stdin-transport.mjs";
const childEnvironment = { ...process.env };
delete childEnvironment.NODE_TEST_CONTEXT;
const transport = () => new SettlementTransport("/fixture/no-key");
test("real fake SSH child receives the entire source through stdin", async t => {
  const root = await mkdtemp(resolve(tmpdir(), "fake-ssh-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(resolve(root, "ssh"), `#!/usr/bin/env node\nconst fs=require('node:fs');const input=fs.readFileSync(0,'utf8');fs.writeSync(1,JSON.stringify({input,arguments:process.argv.slice(2)}));\n`, { mode: 0o700 });
  const script = "& {\nWrite-Output 'bounded'\n}\n";
  const result = await executePowerShellStdin(transport(), script, { timeout: 1000,
    environment: { ...childEnvironment, PATH: `${root}:${process.env.PATH}` } });
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.input, script); assert.equal(parsed.arguments.at(-1), POWERSHELL_STDIN_COMMAND);
  assert.equal(result.settlement.remoteQuiescenceObserved, true);
  assert.equal(result.settlement.stdinEndCallbackObserved, true);
});
for (const [name, command, input, expected] of [
  ["timeout", "process.stdin.resume();setInterval(()=>{},100)", "x", ["timeout"]],
  ["output cap", "process.stdin.resume();require('node:fs').writeSync(1,'x'.repeat(100000));setInterval(()=>{},100)", "x", ["output_limit"]],
  ["SSH 255", "process.stdin.resume();process.stdin.on('end',()=>process.exit(255))", "x", ["ssh_transport_exit"]],
  ["EPIPE", "process.stdin.destroy();process.exit(0)", "x".repeat(8 * 1024 * 1024), ["stdin_error","stdin_unsettled"]],
  ["inherited pipe left open", "require('node:child_process').spawn(process.execPath,['-e','setTimeout(()=>{},1000)'],{stdio:['ignore',1,2]});process.stdin.resume();process.stdin.on('end',()=>process.exit(0))", "x", ["timeout"]],
]) test(`bounded transport leaves ${name} unresolved without leaked unbounded output`, async () => {
  const started = performance.now();
  await assert.rejects(transport().execute(process.execPath, ["-e", command], {
    input, environment: childEnvironment, timeout: 400, terminationGraceMs: 50, maxOutputBytes: 1024, remoteCommandTransport: "openssh",
  }), error => {
    assert.ok(expected.includes(error.settlement.cause), error.settlement.cause);
    assert.equal(error.settlement.remoteQuiescenceObserved, false);
    assert.ok(error.settlement.outputBytesRetained <= 1024);
    assert.ok(Buffer.byteLength(error.stdout) + Buffer.byteLength(error.stderr) <= 1024);
    return true;
  });
  assert.ok(performance.now() - started < 800);
});
test("held credential rejects content drift and closes idempotently", async t => {
  const root = await mkdtemp(resolve(tmpdir(), "fixture-key-")); t.after(() => rm(root, { recursive: true, force: true }));
  const path = resolve(root, "key"); await writeFile(path, "fixture-only", { mode: 0o600 });
  const credential = await openStablePrivateCredential(path);
  await credential.assertStable(); await writeFile(path, "changed-only", { mode: 0o600 });
  await assert.rejects(credential.assertStable()); await credential.close(); await credential.close();
  await assert.rejects(credential.assertStable(), /closed/u);
});
