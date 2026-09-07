import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("João runner handles deterministic mocked lifecycle scenarios", () => {
  const result = spawnSync("bash", ["ops/joao/test/run-tests.sh"], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /ok - joao runner scenarios/);
});
