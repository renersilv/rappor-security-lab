import assert from "node:assert/strict";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { inspectCurrentWorkspace, prepareCurrentWorkspace } from "../src/current-workspace-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("preparation creates the controlled vulnerable workspace once and never resets it", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-current-workspace-parent-"));
  const workspace = resolve(directory, "workspace");
  try {
    const prepared = await prepareCurrentWorkspace(workspace, root);
    assert.equal(prepared.created, true);
    assert.equal(prepared.functionalAssertionPassed, true);
    assert.deepEqual(prepared.detections, { semgrep: true, gitleaks: true, trivy: true });
    await writeFile(resolve(workspace, "app.mjs"), "export function parseQuantity(raw) { return Number(raw); }\n");
    const repeated = await prepareCurrentWorkspace(workspace, root);
    assert.equal(repeated.created, false);
    assert.equal(await readFile(resolve(workspace, "app.mjs"), "utf8"),
      "export function parseQuantity(raw) { return Number(raw); }\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("only reviewed complete fixture revisions are executed as functional assertions", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "rappor-current-workspace-inspect-"));
  try {
    for (const file of ["app.mjs", "deployment.yaml", "synthetic.env"]) {
      await copyFile(resolve(root, "corpus/code/fixed", file), resolve(directory, file));
    }
    const fixed = await inspectCurrentWorkspace(directory);
    assert.equal(fixed.functionalAssertionPassed, true);
    assert.deepEqual(fixed.detections, { semgrep: false, gitleaks: false, trivy: false });
    await writeFile(resolve(directory, "app.mjs"), "throw new Error('must not execute');\n");
    const unknown = await inspectCurrentWorkspace(directory);
    assert.equal(unknown.functionalAssertionPassed, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
