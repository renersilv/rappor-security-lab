import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";
import { Readable } from "node:stream";
import { prepareAuthenticatedBrowser, prepareWindowsWorkspaceUi, workspaceUiScope } from "../src/prepare-windows-workspace-ui.mjs";
import { captureDiagnostics } from "../src/capture-windows-agent-ai-diagnostics.mjs";

const origin = "https://laboratory.example/";
const computerId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const missing = { state: "failed", stage: "browser-window", counts: { candidates: 0 } };
const ready = { state: "login-ready" };
const authenticated = { state: "authenticated" };

function browserFixture(states) {
  let time = 0;
  const calls = [];
  return { calls, options: {
    inspect: async () => states.shift() ?? missing,
    openLogin: async () => { calls.push("open"); return { state: "opened" }; },
    submitLogin: async () => { calls.push("submit"); return { state: "login-submitted" }; },
    pause: async milliseconds => { time += milliseconds; }, now: () => time,
  } };
}

test("an authenticated browser requires no password or repeated login", async () => {
  const fixture = browserFixture([authenticated]);
  await prepareAuthenticatedBrowser(fixture.options);
  assert.deepEqual(fixture.calls, []);
});

test("missing browser is prepared and the exact login is submitted once", async () => {
  const fixture = browserFixture([missing, ready, missing, authenticated]);
  await prepareAuthenticatedBrowser(fixture.options);
  assert.deepEqual(fixture.calls, ["open", "submit"]);
});

test("ambiguous targets never receive credentials", async () => {
  const fixture = browserFixture([{ ...missing, counts: { candidates: 2 } }]);
  await assert.rejects(prepareAuthenticatedBrowser(fixture.options), /ambiguous/u);
  assert.deepEqual(fixture.calls, []);
});

test("rejected login is not submitted again and missing UI is bounded", async () => {
  const rejected = browserFixture([ready, ready]);
  await assert.rejects(prepareAuthenticatedBrowser(rejected.options), /did not complete/u);
  assert.deepEqual(rejected.calls, ["submit"]);
  const unavailable = browserFixture([]);
  await assert.rejects(prepareAuthenticatedBrowser(unavailable.options), /timed out/u);
  assert.deepEqual(unavailable.calls, ["open"]);
});

test("consent scope binds the synthetic folder, exact computer, HTTPS origin and deadline", () => {
  assert.deepEqual(workspaceUiScope(origin, computerId, 1_000_000), {
    origin, computerId, workspace: "C:\\RapporLab\\corpus", deadlineUnix: 1570,
  });
  for (const value of ["http://laboratory.example/", "https://u:p@laboratory.example/", `${origin}other`, `${origin}?x=1`, `${origin}#other`]) {
    assert.throws(() => workspaceUiScope(value, computerId));
  }
  assert.throws(() => workspaceUiScope(origin, "invalid"));
});

test("failed password submission removes both temporary credential copies", async () => {
  let hostCredentialPath;
  const removals = [];
  const adapter = {
    profile: { vm: { sshPort: 2222 } }, sshArguments: [], sshTarget: "synthetic", sshKey: "unused",
    async vm(action) { assert.equal(action, "wake-display"); },
    async execute(command, args) {
      if (command === "scp") {
        const target = args.at(-1);
        if (target.endsWith("/credentials.json")) {
          hostCredentialPath = args.at(-2);
          assert.equal((await stat(hostCredentialPath)).mode & 0o777, 0o600);
          assert.deepEqual(JSON.parse(await readFile(hostCredentialPath, "utf8")), {
            email: "synthetic@example.test", password: "nonfunctional-test-password",
          });
        }
        return { stdout: "" };
      }
      const remote = args.at(-1);
      if (remote.includes("-EncodedCommand")) {
        removals.push(decodeCleanup(remote));
        return { stdout: "RAPPOR_LAB_CLEANUP=removed\r\n" };
      }
      if (remote.includes("-Action Inspect")) return { stdout: 'RAPPOR_LAB_RESULT={"state":"login-ready"}' };
      if (remote.includes("-Action Login")) throw new Error("Synthetic transport failure.");
      throw new Error("Unexpected fixture command.");
    },
  };
  await assert.rejects(prepareWindowsWorkspaceUi({ adapter, baseUrl: origin, computerId,
    credentials: { RAPPOR_HML_EMAIL: "synthetic@example.test", RAPPOR_HML_PASSWORD: "nonfunctional-test-password" } }), /Synthetic/u);
  assert.equal(removals.length, 1);
  assert.match(removals[0], /browser-preparation\/credentials\.json/u);
  await assert.rejects(stat(hostCredentialPath), { code: "ENOENT" });
});

test("interactive reviewer decisions remain distinct from model claims", async () => {
  const input = [
    { event: "approval-review", source: "model", status: "denied", rationale: "PRIVATE_VALUE" },
    { event: "approval-review", source: "reviewer", status: "approved", rationale: "PRIVATE_VALUE" },
    { event: "approval-review", source: "reviewer", status: "denied", rationale: "PRIVATE_VALUE" },
    { event: "tool-completed", tool: "commandExecution", status: "failed", command: "PRIVATE_VALUE" },
  ].map(value => JSON.stringify(value) + "\n");
  const result = await captureDiagnostics(Readable.from(input), async () => {});
  assert.deepEqual(result.failureClasses, ["automatic-review-denied", "permission-refused"]);
  assert.deepEqual(result.failedToolTypes, ["command_execution"]);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_VALUE/u);
});

function decodeCleanup(command) {
  assert.match(command, /^powershell\.exe -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+$/u);
  return Buffer.from(command.split(" ").at(-1), "base64").toString("utf16le");
}

function cleanupFixture({ acknowledgment = true, transportFailure = false, scopeCopyFailure = false } = {}) {
  const scripts = [];
  const adapter = {
    profile: { vm: { sshPort: 2222 } }, sshArguments: [], sshTarget: "synthetic", sshKey: "unused",
    async vm(action) { assert.equal(action, "wake-display"); },
    async execute(command, args, options) {
      if (command === "scp") {
        if (scopeCopyFailure && args.at(-1).endsWith("/workspace-ui-scope.json")) throw new Error("Synthetic scope transfer failed.");
        return { stdout: "" };
      }
      const remote = args.at(-1);
      if (remote.includes("-EncodedCommand")) {
        assert.equal(options.timeout, 50_000);
        scripts.push(decodeCleanup(remote));
        if (transportFailure) throw new Error("PRIVATE_SYNTHETIC_TRANSPORT_VALUE");
        return { stdout: acknowledgment ? "RAPPOR_LAB_CLEANUP=removed\r\n" : "" };
      }
      if (remote.includes("-Action Inspect")) return { stdout: 'RAPPOR_LAB_RESULT={"state":"authenticated"}' };
      throw new Error("Unexpected fixture command.");
    },
  };
  return { adapter, scripts };
}

test("scope cleanup preserves the fixed script and verifies removal on every invocation", async () => {
  const fixture = cleanupFixture();
  const ui = await prepareWindowsWorkspaceUi({ adapter: fixture.adapter, baseUrl: origin, computerId });
  await ui.cleanup();
  await ui.cleanup();
  assert.equal(fixture.scripts.length, 2);
  assert.equal(fixture.scripts[0], fixture.scripts[1]);
  assert.match(fixture.scripts[0], /\$ErrorActionPreference = 'Stop'/u);
  assert.match(fixture.scripts[0], /\[IO\.File\]::Delete\('C:\/RapporLab\/runtime\/browser-preparation\/workspace-ui-scope\.json'\)/u);
  assert.match(fixture.scripts[0], /Test-Path -LiteralPath/u);
  assert.match(fixture.scripts[0], /Write-Output 'RAPPOR_LAB_CLEANUP=removed'/u);
});

test("zero exit without cleanup acknowledgment fails closed", async () => {
  const fixture = cleanupFixture({ acknowledgment: false });
  const ui = await prepareWindowsWorkspaceUi({ adapter: fixture.adapter, baseUrl: origin, computerId });
  await assert.rejects(ui.cleanup(), { code: "workspace-ui-cleanup-failed", laboratoryPhase: "workspace-ui-cleanup" });
  assert.equal(fixture.scripts.length, 1);
});

test("cleanup transport failure exposes a stage without private output or automatic retry", async () => {
  const fixture = cleanupFixture({ transportFailure: true });
  const ui = await prepareWindowsWorkspaceUi({ adapter: fixture.adapter, baseUrl: origin, computerId });
  await assert.rejects(ui.cleanup(), error => {
    assert.equal(error.code, "workspace-ui-cleanup-failed");
    assert.equal(error.laboratoryPhase, "workspace-ui-cleanup");
    assert.doesNotMatch(error.stack, /PRIVATE_SYNTHETIC_TRANSPORT_VALUE/u);
    return true;
  });
  assert.equal(fixture.scripts.length, 1);
});

test("partial scope transfer verifies cleanup before propagating the transfer failure", async () => {
  const fixture = cleanupFixture({ scopeCopyFailure: true });
  await assert.rejects(prepareWindowsWorkspaceUi({ adapter: fixture.adapter, baseUrl: origin, computerId }), /Synthetic scope transfer failed/u);
  assert.equal(fixture.scripts.length, 1);
  assert.match(fixture.scripts[0], /workspace-ui-scope\.json/u);
});
