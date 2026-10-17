import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { stoppedCurrentWorkspaceResult } from "../src/run-current-workspace-ai-client.mjs";
import { verifyCurrentWorkspaceAiResult } from "../src/verify-current-workspace-ai-result.mjs";

const execFile = promisify(execFileCallback);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const wrapper = resolve(root, "ops/current-workspace-lab/run-codex-bounded.sh");

test("stopped results distinguish refusal, owner action and technical failure", () => {
  const refusal = stoppedCurrentWorkspaceResult("approval-denied");
  assert.equal(refusal.outcome, "refused");
  assert.equal(refusal.ownerAction, "none");
  assert.equal(stoppedCurrentWorkspaceResult("human-action-required").outcome, "needs-owner-action");
  assert.equal(stoppedCurrentWorkspaceResult("attempt-timeout").outcome, "failed");
  verifyCurrentWorkspaceAiResult(refusal);
});

test("the profile pins the exact short natural prompt and bounded candidate", async () => {
  const profile = JSON.parse(await readFile(resolve(root, "scanner-profiles/current-workspace-ai.json"), "utf8"));
  assert.equal(profile.prompt,
    "Analise este projeto com a Rappor Security, processando neste computador. Mostre a nota e os principais problemas antes de corrigir qualquer coisa.");
  assert.equal(profile.candidate.visibleVersion, "v0.79.0");
  assert.match(profile.candidate.publicClientSourceRevision, /^[a-f0-9]{40}$/u);
  assert.equal(profile.authorization.extensionId, "issue19-ai-20261016-extension-1");
  assert.equal(profile.authorization.maximumStarts, 5);
  assert.equal(profile.authorization.maximumCliLinuxStarts, 3);
  assert.equal(profile.authorization.reservedIdeWindowsStarts, 2);
  assert.equal(profile.authorization.maximumSecondsPerStart, 600);
});

test("the live client preserves automatic review, sandbox and isolated invocation override", async () => {
  const source = await readFile(resolve(root, "src/run-current-workspace-ai-client.mjs"), "utf8");
  assert.match(source, /approval_policy=\\"on-request\\"/u);
  assert.match(source, /approvals_reviewer=\\"auto_review\\"/u);
  assert.match(source, /sandbox_mode=\\"workspace-write\\"/u);
  assert.match(source, /mcp_servers\\\.rapporLabIssue19/u);
  assert.match(source, /mcp_servers\.rapporLabIssue19\.required=true/u);
  assert.match(source, /mcpServerStatus\/list/u);
  assert.match(source, /toolsAndAuthOnly/u);
  assert.doesNotMatch(source, /danger-full-access|network_access\s*=\s*true|OPENAI_API_KEY/u);
});

test("the bounded process-tree and persistent history self-test is inert", async () => {
  const result = await execFile("bash", [wrapper, "--self-test"], { timeout: 10000 });
  assert.equal(result.stdout, "issue19_bounded_control=passed\n");
});
