import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { reviewSummary, verifyPolicy } from "./run-windows-agent-ai-client.mjs";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function emptyFirstUse() {
  return {
    catalogInitiallyEmpty: false,
    productReused: false,
    clientDiscovered: false,
    clientInstalled: false,
    computerApproved: false,
    exactComputerSelected: false,
    folderConsented: false,
    typedRecoveryObserved: false,
    noSecretExposed: true,
  };
}

function emptyAnalysis() {
  return { completed: false, score: "unavailable", findingCount: -1, coverageComplete: false, historyObserved: false };
}

export function stoppedCurrentWorkspaceResult(reason) {
  return {
    outcome: reason === "approval-denied" ? "refused" :
      reason === "human-action-required" ? "needs-owner-action" : "failed",
    clientPath: "host-codex-linux-client",
    firstUse: emptyFirstUse(),
    baseline: emptyAnalysis(),
    guidanceRead: false,
    remediationApplied: false,
    functionalTestsPassed: false,
    rerun: emptyAnalysis(),
    web: { rendered: false, scoreMatched: false, findingsMatched: false, coverageMatched: false, historyMatched: false },
    ownerAction: reason === "human-action-required" ? "continue-client-consent" : "none",
    summaryCode: reason,
    scanners: [],
  };
}

function stoppedAfterBaseline(reason, baselineResult) {
  const stopped = stoppedCurrentWorkspaceResult(reason);
  if (!baselineResult) return stopped;
  stopped.firstUse = baselineResult.firstUse;
  stopped.baseline = baselineResult.baseline;
  stopped.scanners = baselineResult.scanners;
  if (["failed", "refused", "needs-owner-action"].includes(baselineResult.outcome)) {
    stopped.outcome = baselineResult.outcome;
    stopped.ownerAction = baselineResult.ownerAction;
    stopped.summaryCode = baselineResult.summaryCode;
  }
  return stopped;
}

function baselineCanContinue(value) {
  return value?.outcome === "completed" && value.clientPath === "host-codex-linux-client" &&
    value.ownerAction === "none" && value.baseline?.completed === true && value.firstUse &&
    Array.isArray(value.scanners);
}

function mcpTarget(status) {
  const rows = Array.isArray(status?.data) ? status.data : Array.isArray(status?.servers) ? status.servers : [];
  return rows.find((row) => row?.name === "rapporLabIssue19" || row?.serverName === "rapporLabIssue19") ??
    (rows.length === 1 ? rows[0] : status?.rapporLabIssue19);
}

function mcpToolCount(status) {
  const target = mcpTarget(status);
  if (!target) return 0;
  if (Array.isArray(target.tools)) return target.tools.length;
  if (Array.isArray(target.tools?.data)) return target.tools.data.length;
  if (target.tools && typeof target.tools === "object") return Object.keys(target.tools).length;
  return 0;
}

function mcpStatusSummary(status) {
  const target = mcpTarget(status) ?? {};
  const runtimeState = typeof target.runtimeStatus === "string" ? target.runtimeStatus :
    target.runtimeStatus?.status ?? target.runtimeStatus?.state;
  const allowedStates = new Set(["ready", "failed", "starting", "disabled", "notStarted", "unknown"]);
  const allowedReasons = new Set(["reauthenticationRequired", "connectionFailed", "initializationFailed",
    "timedOut", "disabled", "unknown"]);
  const state = allowedStates.has(runtimeState) ? runtimeState : "unknown";
  const reasonValue = target.failureReason ?? target.runtimeStatus?.failureReason;
  const reason = allowedReasons.has(reasonValue) ? reasonValue : "unknown";
  const error = [target.error, target.toolsError, target.runtimeStatus?.error].find((value) => typeof value === "string") ?? "";
  const failureClass = /keyring|keychain|secret service|credential store|failed to (?:load|read).{0,30}(?:credential|token)/iu.test(error) ?
    "credential-store-unavailable" :
    /expired|refresh/iu.test(error) ? "oauth-refresh-failed" :
      /authorization required|reauth|not logged|login required/iu.test(error) ? "oauth-authorization-required" :
        /\b401\b|unauthorized/iu.test(error) ? "oauth-unauthorized" :
          /oauth|token|authentication/iu.test(error) ? "authentication-failed" :
    /certificate|\btls\b/iu.test(error) ? "tls-failed" :
      /connect|network|dns|socket/iu.test(error) ? "network-failed" :
        /protocol|initialize|handshake|invalid/iu.test(error) ? "protocol-failed" : error ? "unclassified" : "none";
  const authStatus = ["o_auth", "not_logged_in", "unsupported"].includes(target.authStatus) ? target.authStatus : "unknown";
  return { state, reason, authStatus, failureClass, errorPresent: Boolean(error), toolCount: mcpToolCount(status) };
}

function structuralShape(value, depth = 0) {
  if (depth >= 6) return Array.isArray(value) ? `array:${value.length}` : typeof value;
  if (Array.isArray(value)) return { length: value.length, item: value.length ? structuralShape(value[0], depth + 1) : "empty" };
  if (!value || typeof value !== "object") return typeof value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, structuralShape(item, depth + 1)]));
}

function safeEnvironment() {
  const environment = {
    HOME: "/home/linux",
    CODEX_HOME: "/home/linux/.codex",
    PATH: "/usr/local/bin:/usr/bin:/bin",
    LANG: "C.UTF-8",
  };
  for (const key of ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]) {
    if (process.env[key]) environment[key] = process.env[key];
  }
  for (const key of ["USER", "USERNAME", "LOGNAME", "TERM"]) if (process.env[key]) environment[key] = process.env[key];
  return environment;
}

async function main() {
  const preflight = process.argv[2] === "--preflight";
  assert.ok((preflight && process.argv.length === 3) || (process.argv[2] === "--run" && process.argv.length === 8));
  const [promptPath, followUpPath, baselinePath, resultPath, reviewPath] = process.argv.slice(3);
  const workspace = resolve(process.env.RAPPOR_CURRENT_WORKSPACE ?? "");
  const stateRoot = "/home/linux/.local/state/rappor-security-lab/joao/tmp/";
  assert.ok(`${workspace}/`.startsWith(stateRoot) && workspace !== stateRoot.slice(0, -1));
  const override = process.env.RAPPOR_ISSUE19_MCP_OVERRIDE ?? "";
  assert.match(override, /^mcp_servers\.rapporLabIssue19\.url="https:\/\/[A-Za-z0-9.-]+(?::[0-9]{1,5})?\/mcp"$/u);
  if (!preflight) {
    const deadline = Number(process.env.RAPPOR_LAB_ATTEMPT_DEADLINE);
    assert.ok(Number.isInteger(deadline) && deadline > Date.now() / 1000 && deadline <= Date.now() / 1000 + 600);
  }

  const pending = new Map();
  const reviews = [];
  let sequence = 0;
  let baselineResult;
  let result;
  let halted = false;
  let stage = "startup";
  let stopReason = "incomplete-result";
  let activeTurn = 0;
  let settleFirst;
  let settleSecond;
  const firstFinished = new Promise((resolveFinished) => { settleFirst = resolveFinished; });
  const secondFinished = new Promise((resolveFinished) => { settleSecond = resolveFinished; });
  const output = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
  const child = spawn("/home/linux/.local/bin/codex", [
    "app-server", "--stdio",
    "-c", "approval_policy=\"on-request\"",
    "-c", "approvals_reviewer=\"auto_review\"",
    "-c", "sandbox_mode=\"workspace-write\"",
    "-c", override,
    "-c", "mcp_servers.rapporLabIssue19.required=true",
  ], { cwd: workspace, env: safeEnvironment(), detached: true, stdio: ["pipe", "pipe", "pipe"] });
  let stderrBytes = 0;
  child.stderr.on("data", (data) => { stderrBytes += data.length; });
  child.on("error", () => { halted = true; settleFirst("failed"); settleSecond("failed"); });
  child.on("exit", () => {
    for (const { reject } of pending.values()) reject(new Error("server-exited"));
    pending.clear();
    settleFirst("failed");
    settleSecond("failed");
  });
  const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`);
  const request = (method, params) => {
    const id = ++sequence;
    return new Promise((resolveRequest, reject) => {
      pending.set(id, { resolve: resolveRequest, reject });
      send({ id, method, params });
    });
  };
  function halt(reason = "observer-failed") {
    stopReason = reason;
    halted = true;
    settleFirst("failed");
    settleSecond("failed");
    try { process.kill(-child.pid, "SIGTERM"); } catch {}
  }
  function stopServer() {
    halt("attempt-timeout");
    try { process.kill(-child.pid, "SIGKILL"); } catch {}
  }
  process.once("SIGTERM", stopServer);
  process.once("SIGINT", stopServer);
  let buffer = "";
  child.stdout.on("data", (data) => {
    buffer += data.toString("utf8");
    if (Buffer.byteLength(buffer) > 4 * 1024 * 1024) { halt(); return; }
    let newline;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      let event;
      try { event = JSON.parse(line); } catch { halt(); continue; }
      if (event.id !== undefined && pending.has(event.id) && !event.method) {
        const target = pending.get(event.id);
        pending.delete(event.id);
        if (event.error) {
          output({ event: "protocol-error", code: Number.isInteger(event.error.code) ? event.error.code : 0 });
          target.reject(new Error("protocol-error"));
        } else target.resolve(event.result);
        continue;
      }
      if (event.method && event.id !== undefined) {
        output({ event: "human-action-required", approval: /Approval|approval|requestPermissions/u.test(event.method) });
        halt("human-action-required");
        continue;
      }
      if (event.method === "item/autoApprovalReview/completed" || event.method === "item/guardianApprovalReview/completed") {
        const value = reviewSummary(event.params ?? {});
        reviews.push(value);
        output(value);
        if (value.status !== "approved") halt(value.status === "denied" ? "approval-denied" : "approval-unavailable");
      }
      if (event.method === "item/completed") {
        const item = event.params?.item;
        if (item?.type === "agentMessage") {
          try {
            if (activeTurn === 1) baselineResult = JSON.parse(item.text);
            if (activeTurn === 2) result = JSON.parse(item.text);
          } catch { /* Raw agent text is never retained. */ }
        }
        if (["commandExecution", "mcpToolCall"].includes(item?.type)) {
          output({ event: "tool-completed", tool: item.type,
            status: ["completed", "failed", "declined"].includes(item.status) ? item.status : "unknown" });
        }
      }
      if (event.method === "turn/completed") {
        if (activeTurn === 1) settleFirst(event.params?.turn?.status);
        if (activeTurn === 2) settleSecond(event.params?.turn?.status);
      }
    }
  });

  const timer = setTimeout(stopServer, preflight ? 25000 : 585000);
  try {
    await request("initialize", { clientInfo: { name: "rappor_current_workspace_lab",
      title: "Rappor Current Workspace Laboratory", version: "1.0.0" },
      capabilities: { experimentalApi: true } });
    send({ method: "initialized", params: {} });
    stage = "mcp-status";
    const appMcpStatus = await request("mcpServerStatus/list", { serverName: "rapporLabIssue19",
      detail: "toolsAndAuthOnly", limit: 100 });
    const appMcpSummary = mcpStatusSummary(appMcpStatus);
    output({ event: "mcp-app-status", server: "rapporLabIssue19", ...appMcpSummary });
    if (appMcpSummary.toolCount === 0) output({ event: "mcp-app-status-shape", shape: structuralShape(appMcpStatus) });
    assert.ok(appMcpSummary.toolCount > 0);
    stage = "thread-start";
    const thread = await request("thread/start", { cwd: workspace, ephemeral: true, approvalPolicy: "on-request",
      approvalsReviewer: "auto_review", sandbox: "workspace-write", experimentalRawEvents: false });
    verifyPolicy(thread);
    const mcpStatus = await request("mcpServerStatus/list", { serverName: "rapporLabIssue19",
      threadId: thread.thread.id, detail: "toolsAndAuthOnly", limit: 100 });
    const toolCount = mcpToolCount(mcpStatus);
    assert.ok(toolCount > 0);
    output({ event: "policy-verified", ephemeral: true, approvalPolicy: thread.approvalPolicy,
      reviewer: thread.approvalsReviewer, sandbox: thread.sandbox.type,
      model: /^[A-Za-z0-9._-]{1,60}$/u.test(thread.model) ? thread.model : "unknown" });
    output({ event: "mcp-tools-verified", server: "rapporLabIssue19", toolCount });
    if (preflight) return;
    const prompt = await readFile(promptPath, "utf8");
    const followUpPrompt = await readFile(followUpPath, "utf8");
    const baselineSchema = JSON.parse(await readFile(resolve(repositoryRoot, "schemas/current-workspace-ai-baseline.schema.json"), "utf8"));
    const outputSchema = JSON.parse(await readFile(resolve(repositoryRoot, "schemas/current-workspace-ai-result.schema.json"), "utf8"));
    stage = "baseline-turn-start";
    activeTurn = 1;
    await request("turn/start", { threadId: thread.thread.id,
      input: [{ type: "text", text: prompt, text_elements: [] }], outputSchema: baselineSchema });
    const firstStatus = await firstFinished;
    if (halted || !baselineResult || firstStatus !== "completed") {
      result = stoppedAfterBaseline(halted ? stopReason : "incomplete-baseline", baselineResult);
    } else {
      await writeFile(baselinePath, JSON.stringify(baselineResult), { mode: 0o600 });
      if (!baselineCanContinue(baselineResult)) {
        result = stoppedAfterBaseline("baseline-did-not-complete", baselineResult);
      } else {
        stage = "remediation-turn-start";
        activeTurn = 2;
        await request("turn/start", { threadId: thread.thread.id,
          input: [{ type: "text", text: followUpPrompt, text_elements: [] }], outputSchema });
        const secondStatus = await secondFinished;
        if (halted || !result || secondStatus !== "completed") {
          result = stoppedAfterBaseline(halted ? stopReason : "incomplete-result", baselineResult);
        }
      }
    }
    if (!baselineResult) await writeFile(baselinePath, JSON.stringify(stoppedCurrentWorkspaceResult("incomplete-baseline")), { mode: 0o600 });
    await writeFile(resultPath, JSON.stringify(result), { mode: 0o600 });
    await writeFile(reviewPath, JSON.stringify(reviews), { mode: 0o600 });
    output({ event: "run-ended", stopped: halted, reviewerEvents: reviews.length });
  } catch {
    output({ event: "client-failed", stage });
    if (!preflight) {
      const stopped = stoppedAfterBaseline(halted ? stopReason : "client-failed", baselineResult);
      await writeFile(baselinePath, JSON.stringify(baselineResult ?? stopped), { mode: 0o600 });
      await writeFile(resultPath, JSON.stringify(stopped), { mode: 0o600 });
      await writeFile(reviewPath, JSON.stringify(reviews), { mode: 0o600 });
    }
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
    if (!child.stdin.destroyed) child.stdin.end();
    try { process.kill(-child.pid, "SIGTERM"); } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 1000));
    try { process.kill(-child.pid, "SIGKILL"); } catch {}
    output({ event: "client-closed", stderrPresent: stderrBytes > 0 });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
