import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { settleWindowsResources } from "../src/windows-resource-settlement.mjs";
import { SettlementTransport } from "../src/windows-settlement-transport.mjs";
import { settlementFixture } from "./support-settlement-fixture.mjs";

for (const genuineError of [false, true]) test(
  genuineError ? "real SSH subprocess stderr still rejects a successful-looking probe" :
    "SSH informational host-key notice does not reject the bound settlement probe",
  async t => {
    const fixture = await settlementFixture();
    const bin = await mkdtemp(resolve(tmpdir(), "settlement-ssh-warning-"));
    t.after(async () => { await rm(fixture.root, { recursive: true, force: true }); await rm(bin, { recursive: true, force: true }); });
    const executable = `#!${process.execPath}
const fs = require('node:fs');
const input = fs.readFileSync(0, 'utf8');
if (!process.argv.includes('LogLevel=ERROR')) {
  fs.writeSync(2, "Warning: Permanently added '[127.0.0.1]:2222' (ED25519) to the list of known hosts.\\r\\n");
}
if (${genuineError}) fs.writeSync(2, 'Synthetic remote PowerShell error.\\n');
const probe = input.match(/probe = '([a-f0-9]+)'/);
const result = probe ? {schema:1,probe:probe[1],domainUuid:'13918e5c-5b79-4a99-9029-0aa515f5a732'} :
  {schema:1,kind:'windows_task_settlement_guest',taskAbsent:true,rootAbsent:true,ownershipVerified:true,remainingOwnedProcesses:0};
fs.writeSync(1, JSON.stringify(result)+'\\n');
`;
    await writeFile(resolve(bin, "ssh"), executable, { mode: 0o700 });
    const environment = { ...process.env, PATH: `${bin}:${process.env.PATH}` };
    delete environment.NODE_TEST_CONTEXT;
    let calls = 0;
    fixture.dependencies.createTransport = key => {
      const adapter = new SettlementTransport(key), execute = adapter.execute.bind(adapter);
      adapter.execute = (file, args, options) => { calls++; return execute(file, args, { ...options, environment }); };
      return adapter;
    };
    if (genuineError) {
      await assert.rejects(settleWindowsResources(fixture.args, fixture.dependencies), /unresolved/u);
      const failure = await fixture.unresolved();
      assert.equal(failure.failedStage, "transport_probe");
      assert.equal(failure.reasonCode, "probe_stderr");
      assert.equal(calls, 1);
      assert.equal(await fixture.exists("settlement-result.json"), false);
      assert.doesNotMatch(JSON.stringify(failure), /Synthetic|Permanently added/u);
    } else {
      const result = await settleWindowsResources(fixture.args, fixture.dependencies);
      assert.equal(result.outcome, "settled");
      assert.equal(calls, 2);
      assert.equal((await fixture.receipt()).transportProbeVerified, true);
    }
    assert.equal(fixture.closed, true);
  },
);
