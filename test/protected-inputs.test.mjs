import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import * as contract from "../src/protected-inputs.mjs";
const digest = bytes => createHash("sha256").update(bytes).digest("hex");

for (const operation of ["capture", "rebuild"]) {
  for (const replacement of ["symlink", "regular-file"]) {
    test(`${operation} cannot attest external bytes after a ${replacement} replacement`, async () => {
      const root = await fs.mkdtemp(join(tmpdir(), "descriptor-race-"));
      const output = join(root, "output");
      await fs.mkdir(output, { mode: 0o700 });
      const target = join(output, "artifact.mjs");
      const outside = join(root, "outside.mjs");
      const external = Buffer.from("unvalidated external replacement\n");
      await fs.writeFile(target, "trusted original\n", { mode: 0o600 });
      await fs.writeFile(outside, external, { mode: 0o600 });
      const realpath = fs.realpath;
      let replaced = false;
      fs.realpath = async function (path, ...options) {
        const result = await realpath(path, ...options);
        if (path === target && !replaced) {
          replaced = true;
          await fs.rename(target, `${target}.retained`);
          if (replacement === "symlink") await fs.symlink(outside, target);
          else await fs.rename(outside, target);
        }
        return result;
      };
      syncBuiltinESMExports();
      try {
        let returned;
        let rejected = false;
        try {
          returned = operation === "capture"
            ? await contract.captureSourceSnapshot(target, "race-source")
            : await contract.rebuildPrivateArtifactMap(output, { "artifact.mjs": digest(external) });
        } catch (error) {
          assert.ok(error instanceof Error);
          rejected = true;
        }
        assert.equal(replaced, true, "replacement must occur at the validated-path/read boundary");
        assert.equal(rejected, true,
          `Unvalidated replacement was attested: ${operation === "capture" ? returned?.sha256 : returned?.["artifact.mjs"]}`);
      } finally {
        fs.realpath = realpath;
        syncBuiltinESMExports();
        await fs.rm(root, { recursive: true, force: true });
      }
    });
  }
}

test("source capture rejects an ancestor symlink replacement after canonical validation", async () => {
  const root = await fs.mkdtemp(join(tmpdir(), "descriptor-parent-race-"));
  const parent = join(root, "parent");
  const outside = join(root, "outside");
  await fs.mkdir(parent, { mode: 0o700 });
  await fs.mkdir(outside, { mode: 0o700 });
  const target = join(parent, "source.mjs");
  await fs.writeFile(target, "trusted original\n", { mode: 0o600 });
  await fs.writeFile(join(outside, "source.mjs"), "external parent\n", { mode: 0o600 });
  const realpath = fs.realpath;
  let replaced = false;
  fs.realpath = async function (path, ...options) {
    const result = await realpath(path, ...options);
    if (path === target && !replaced) {
      replaced = true;
      await fs.rename(parent, `${parent}.retained`);
      await fs.symlink(outside, parent);
    }
    return result;
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(contract.captureSourceSnapshot(target, "parent-race"));
    assert.equal(replaced, true);
  } finally {
    fs.realpath = realpath;
    syncBuiltinESMExports();
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("ordinary retained source bytes and private artifact hashes remain valid", async () => {
  const output = await fs.mkdtemp(join(tmpdir(), "descriptor-regular-"));
  const target = join(output, "source.mjs");
  const bytes = Buffer.from("export const safe = true;\n");
  try {
    await fs.writeFile(target, bytes, { mode: 0o600 });
    const captured = await contract.captureSourceSnapshot(target);
    assert.deepEqual(captured.bytes, bytes);
    assert.equal(captured.sha256, digest(bytes));
    assert.deepEqual(await contract.rebuildPrivateArtifactMap(output, { "source.mjs": captured.sha256 }),
      { "source.mjs": captured.sha256 });
    await fs.chmod(target, 0o644);
    await assert.rejects(contract.rebuildPrivateArtifactMap(output, { "source.mjs": captured.sha256 }), /mode-mismatch/u);
    await fs.rm(target);
    await fs.symlink("missing", target);
    await assert.rejects(contract.captureSourceSnapshot(target));
  } finally {
    await fs.rm(output, { recursive: true, force: true });
  }
});

for (const label of ["campaign", "review", "authorization", "ledger", "binding", "environment"]) {
  test(`protected ${label} rejects a replacement at the canonical-path/read boundary`, async () => {
    const root = await fs.mkdtemp(join(tmpdir(), "protected-race-"));
    const target = join(root, "input.json");
    const external = join(root, "external.json");
    await fs.writeFile(target, '{"allowed":true}', { mode: 0o600 });
    await fs.writeFile(external, '{"allowed":false}', { mode: 0o600 });
    const realpath = fs.realpath;
    let replaced = false;
    fs.realpath = async function (path, ...options) {
      const result = await realpath(path, ...options);
      if (path === target && !replaced) {
        replaced = true;
        await fs.rename(target, `${target}.retained`);
        await fs.symlink(external, target);
      }
      return result;
    };
    syncBuiltinESMExports();
    try {
      await assert.rejects(contract.captureProtectedSnapshot(target, label));
      assert.equal(replaced, true);
    } finally {
      fs.realpath = realpath;
      syncBuiltinESMExports();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
}

test("protected JSON uses the reviewed hash, canonical root, private mode, and retained bytes", async () => {
  const root = await fs.mkdtemp(join(tmpdir(), "protected-json-"));
  const target = join(root, "input.json");
  const original = Buffer.from('{"authorized":true}');
  try {
    await fs.writeFile(target, original, { mode: 0o600 });
    const reference = { path: target, sha256: digest(original) };
    const captured = await contract.readProtectedJson(reference, { root });
    assert.deepEqual(captured.value, { authorized: true });
    assert.deepEqual(captured.snapshot.bytes, original);
    await assert.rejects(contract.readProtectedJson({ ...reference, sha256: "a".repeat(64) }, { root }), /hash-mismatch/u);
    await fs.mkdir(join(root, "restricted"), { mode: 0o700 });
    await assert.rejects(contract.readProtectedJson(reference, { root: join(root, "restricted") }), /outside-root/u);
    await fs.chmod(target, 0o644);
    await assert.rejects(contract.readProtectedJson(reference, { root }), /mode-mismatch/u);
    await fs.chmod(target, 0o600);
    await assert.rejects(contract.captureProtectedSnapshot(target, "bounded", 1), /size-limit/u);
    await fs.writeFile(target, '{"authorized":false}');
    await assert.rejects(contract.assertSourceSnapshot(captured.snapshot), /changed-after-snapshot/u);
    assert.deepEqual(captured.snapshot.bytes, original, "a later file replacement cannot change the retained snapshot");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
