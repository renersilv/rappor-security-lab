import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("preparation stage survives restart and enforces review and authorization boundaries", () => {
  const result = spawnSync("python3", ["ops/joao/test/stage-tests.py"], {
    cwd: new URL("..", import.meta.url), encoding: "utf8",
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" }, timeout: 30000,
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
