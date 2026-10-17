#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

function exactKeys(value, keys) {
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}

export function verifyCurrentWorkspaceAiResult(result) {
  exactKeys(result, ["outcome", "clientPath", "firstUse", "baseline", "guidanceRead", "remediationApplied",
    "functionalTestsPassed", "rerun", "web", "ownerAction", "summaryCode", "scanners"]);
  assert.ok(["completed", "failed", "refused", "needs-owner-action"].includes(result.outcome));
  assert.equal(result.clientPath, "host-codex-linux-client");
  exactKeys(result.firstUse, ["catalogInitiallyEmpty", "productReused", "clientDiscovered", "clientInstalled",
    "computerApproved", "exactComputerSelected", "folderConsented", "typedRecoveryObserved", "noSecretExposed"]);
  for (const value of Object.values(result.firstUse)) assert.equal(typeof value, "boolean");
  for (const analysis of [result.baseline, result.rerun]) {
    exactKeys(analysis, ["completed", "score", "findingCount", "coverageComplete", "historyObserved"]);
    assert.equal(typeof analysis.completed, "boolean");
    assert.match(analysis.score, /^(?:[0-9]+(?:\.[0-9]+)?|unavailable)$/u);
    assert.ok(Number.isInteger(analysis.findingCount) && analysis.findingCount >= -1);
    assert.equal(typeof analysis.coverageComplete, "boolean");
    assert.equal(typeof analysis.historyObserved, "boolean");
  }
  for (const key of ["guidanceRead", "remediationApplied", "functionalTestsPassed"]) assert.equal(typeof result[key], "boolean");
  exactKeys(result.web, ["rendered", "scoreMatched", "findingsMatched", "coverageMatched", "historyMatched"]);
  for (const value of Object.values(result.web)) assert.equal(typeof value, "boolean");
  assert.ok(["none", "continue-client-consent", "approve-computer-in-browser", "confirm-folder-locally"].includes(result.ownerAction));
  assert.match(result.summaryCode, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
  assert.ok(result.summaryCode.length <= 80);
  assert.ok(Array.isArray(result.scanners) && result.scanners.length <= 3);
  for (const scanner of result.scanners) {
    exactKeys(scanner, ["key", "version", "state", "databaseState"]);
    assert.ok(["semgrep", "gitleaks", "trivy"].includes(scanner.key));
    assert.match(scanner.version, /^(?:[A-Za-z0-9][A-Za-z0-9._+-]{0,63}|unavailable)$/u);
    assert.ok(["completed", "failed", "unavailable"].includes(scanner.state));
    assert.ok(["not-applicable", "current", "approved-offline-stale", "unavailable"].includes(scanner.databaseState));
  }
  if (result.outcome === "completed") {
    assert.equal(result.ownerAction, "none");
    assert.equal(result.baseline.completed, true);
    assert.equal(result.rerun.completed, true);
    assert.equal(result.guidanceRead, true);
    assert.equal(result.remediationApplied, true);
    assert.equal(result.functionalTestsPassed, true);
  }
  if (result.outcome === "needs-owner-action") assert.notEqual(result.ownerAction, "none");
  return result;
}

const path = process.argv[2];
if (path && process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  verifyCurrentWorkspaceAiResult(JSON.parse(await readFile(resolve(path), "utf8")));
  process.stdout.write("current_workspace_ai_result=valid\n");
}
