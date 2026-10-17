import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { verifyCurrentWorkspaceReport } from "../src/verify-current-workspace-report.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const record = resolve(root, "observations/current-workspace/2026-10-17T152047Z.json");
const narrative = resolve(root, "observations/current-workspace/2026-10-17T152047Z.md");

test("the current workspace report preserves a partial non-clean result", async () => {
  const report = JSON.parse(await readFile(record, "utf8"));
  const markdown = await readFile(narrative, "utf8");
  assert.deepEqual(verifyCurrentWorkspaceReport(report, markdown), {
    status: "partial",
    verdict: "inconclusive",
    consumedStarts: 3,
    remainingIdeWindowsStarts: 2,
    clean: false,
  });
});

test("an incomplete baseline cannot be relabeled as completed or clean", async () => {
  const report = JSON.parse(await readFile(record, "utf8"));
  report.status = "completed";
  report.verdict = "passed";
  report.acceptance.partialRunTreatedAsClean = true;
  assert.throws(() => verifyCurrentWorkspaceReport(report), /Expected values to be strictly equal/u);
});
