#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const path = process.argv[2];
if (!path) throw new Error("the private AI result path is required");

const result = JSON.parse(await readFile(resolve(path), "utf8"));
assert.deepEqual(Object.keys(result).sort(), [
  "analysisCompleted", "clientPath", "operationContinued", "outcome", "scanners", "summaryCode",
].sort());
assert.ok(["completed", "failed", "refused"].includes(result.outcome));
assert.equal(result.clientPath, "host-codex-ssh-windows-app");
assert.equal(typeof result.operationContinued, "boolean");
assert.equal(typeof result.analysisCompleted, "boolean");
assert.match(result.summaryCode, /^[a-z0-9]+(?:-[a-z0-9]+)*$/u);
assert.ok(result.summaryCode.length <= 80);
assert.ok(Array.isArray(result.scanners) && result.scanners.length <= 3);
for (const scanner of result.scanners) {
  assert.deepEqual(Object.keys(scanner).sort(), ["key", "state", "version"]);
  assert.ok(["semgrep", "gitleaks", "trivy"].includes(scanner.key));
  assert.match(scanner.version, /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u);
  assert.ok(["completed", "failed", "unavailable"].includes(scanner.state));
}
if (result.outcome === "completed") {
  assert.equal(result.operationContinued, true);
  assert.equal(result.analysisCompleted, true);
  assert.deepEqual(result.scanners.map(({ key }) => key).sort(), ["gitleaks", "semgrep", "trivy"]);
  assert.equal(result.scanners.every(({ state }) => state === "completed"), true);
}
process.stdout.write(`${JSON.stringify(result)}\n`);
