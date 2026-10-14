import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const remoteRoot = "C:/RapporLab/runtime";
const remoteCredentials = `${remoteRoot}/browser-preparation/credentials.json`;
const remoteScope = `${remoteRoot}/browser-preparation/workspace-ui-scope.json`;

export function workspaceUiScope(baseUrl, computerId, now = Date.now()) {
  const origin = new URL(baseUrl);
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/" ||
      origin.search || origin.hash || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu.test(computerId)) {
    throw new Error("Invalid laboratory UI scope.");
  }
  return { origin: origin.href, computerId, workspace: "C:\\RapporLab\\corpus", deadlineUnix: Math.floor(now / 1000) + 570 };
}

export async function prepareAuthenticatedBrowser({ inspect, openLogin, submitLogin, pause = delay, now = Date.now }) {
  const deadline = now() + 90_000;
  let opened = false;
  let submitted = false;
  while (now() < deadline) {
    const state = await inspect();
    if (state.state === "authenticated") return;
    if (state.state === "login-ready") {
      if (submitted) throw new Error("Laboratory browser login did not complete.");
      if ((await submitLogin()).state !== "login-submitted") throw new Error("Laboratory browser login failed.");
      submitted = true;
    } else if (state.state === "failed" && state.stage === "browser-window" && state.counts?.candidates === 0) {
      if (!opened && !submitted) {
        if ((await openLogin()).state !== "opened") throw new Error("Laboratory browser could not open.");
        opened = true;
      }
    } else {
      throw new Error("Laboratory browser target is ambiguous or unavailable.");
    }
    await pause(1500);
  }
  throw new Error("Laboratory browser preparation timed out.");
}

export async function prepareWindowsWorkspaceUi({ adapter, baseUrl, computerId, credentials }) {
  // Validate before copying anything or accessing the browser's password controls.
  workspaceUiScope(baseUrl, computerId);
  const origin = new URL(baseUrl).href;
  const execute = command => adapter.execute("ssh", [...adapter.sshArguments, adapter.sshTarget, command], { timeout: 50_000 });
  const copy = (source, target) => adapter.execute("scp", ["-F", "/dev/null", "-P", String(adapter.profile.vm.sshPort),
    "-i", adapter.sshKey, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
    source, `${adapter.sshTarget}:${target}`], { timeout: 30_000 });
  async function removeRemote(path) {
    const phase = path === remoteCredentials ? "browser-credential-cleanup" : "workspace-ui-cleanup";
    if (path !== remoteCredentials && path !== remoteScope) throw new Error("Invalid laboratory cleanup target.");
    // Encode the fixed script to preserve its quoting through the remote shell.
    const script = `$ErrorActionPreference = 'Stop'\n[IO.File]::Delete('${path}')\n` +
      `if (Test-Path -LiteralPath '${path}') { throw 'Laboratory cleanup did not complete.' }\n` +
      "Write-Output 'RAPPOR_LAB_CLEANUP=removed'";
    try {
      const result = await execute(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, "utf16le").toString("base64")}`);
      if (!result.stdout.split(/\r?\n/u).includes("RAPPOR_LAB_CLEANUP=removed")) {
        throw new Error("Laboratory cleanup acknowledgment is unavailable.");
      }
    } catch {
      // Remote transport errors may contain private paths; expose only the stage.
      const error = new Error("Laboratory temporary-file cleanup could not be verified.");
      error.code = `${phase}-failed`;
      error.laboratoryPhase = phase;
      throw error;
    }
  }
  async function browser(action) {
    const result = await execute(`powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ${remoteRoot}/browser-ui.ps1 -Action ${action} -Origin ${origin}`);
    const line = result.stdout.split(/\r?\n/u).find(value => value.startsWith("RAPPOR_LAB_RESULT="));
    if (!line) throw new Error("Laboratory browser result is unavailable.");
    return JSON.parse(line.slice("RAPPOR_LAB_RESULT=".length));
  }
  await adapter.vm("wake-display");
  await copy(resolve(repositoryRoot, "ops/windows-agent-lab/browser-ui.ps1"), `${remoteRoot}/browser-ui.ps1`);
  const directory = await mkdtemp(join(tmpdir(), "rappor-workspace-ui-"));
  try {
    await prepareAuthenticatedBrowser({
      inspect: () => browser("Inspect"),
      openLogin: () => browser("OpenLogin"),
      submitLogin: async () => {
        if (!credentials?.RAPPOR_HML_EMAIL || !credentials?.RAPPOR_HML_PASSWORD) {
          throw new Error("Protected laboratory login is unavailable.");
        }
        const path = join(directory, "credentials.json");
        await writeFile(path, JSON.stringify({ email: credentials.RAPPOR_HML_EMAIL, password: credentials.RAPPOR_HML_PASSWORD }), { mode: 0o600 });
        try {
          await copy(path, remoteCredentials);
          return await browser("Login");
        } finally {
          try { await removeRemote(remoteCredentials); }
          finally { await rm(path, { force: true }); }
        }
      },
    });
    for (const name of ["workspace-ui.ps1", "workspace-interactive.ps1"]) {
      await copy(resolve(repositoryRoot, "ops/windows-agent-lab", name), `${remoteRoot}/${name}`);
    }
    const scope = workspaceUiScope(origin, computerId);
    const scopePath = join(directory, "scope.json");
    await writeFile(scopePath, JSON.stringify(scope), { mode: 0o600 });
    try {
      await copy(scopePath, remoteScope);
    } catch (error) {
      await removeRemote(remoteScope);
      throw error;
    }
    return { deadlineUnix: scope.deadlineUnix, cleanup: () => removeRemote(remoteScope) };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
