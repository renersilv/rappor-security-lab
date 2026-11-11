import assert from "node:assert/strict";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");
const HASH = /^[a-f0-9]{64}$/u;

// The laboratory executor runs on Linux. Bind the opened inode, not a later pathname read.
async function readValidatedFile(path, { label, privateMode, maximumBytes }) {
  assert.ok(isAbsolute(path), `${label}-path-must-be-absolute`);
  assert.ok(Number.isSafeInteger(maximumBytes) && maximumBytes > 0, `${label}-size-limit-invalid`);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat();
    assert.equal(before.isFile(), true, `${label}-must-be-regular`);
    assert.equal(before.uid, process.getuid(), `${label}-owner-mismatch`);
    if (privateMode) assert.equal(before.mode & 0o777, 0o600, `${label}-mode-mismatch`);
    assert.ok(before.size <= maximumBytes, `${label}-size-limit`);
    const descriptorPath = `/proc/self/fd/${file.fd}`;
    assert.equal(await realpath(descriptorPath), path, `${label}-descriptor-path-mismatch`);
    assert.equal(await realpath(path), path, `${label}-realpath-mismatch`);
    const bytes = await file.readFile();
    const after = await file.stat();
    for (const field of ["dev", "ino", "uid", "mode", "size", "mtimeMs", "ctimeMs"]) {
      assert.equal(after[field], before[field], `${label}-changed-during-read`);
    }
    assert.equal(bytes.length, after.size, `${label}-size-changed-during-read`);
    assert.equal(await realpath(descriptorPath), path, `${label}-descriptor-path-changed`);
    return Object.freeze({ path, bytes, size: bytes.length, sha256: sha256(bytes) });
  } finally {
    await file.close();
  }
}

export function captureProtectedSnapshot(path, label = "protected-input", maximumBytes = 1024 * 1024) {
  return readValidatedFile(path, { label, privateMode: true, maximumBytes });
}

export function captureSourceSnapshot(path, label = "source", maximumBytes = 16 * 1024 * 1024) {
  return readValidatedFile(path, { label, privateMode: false, maximumBytes });
}

export async function assertSourceSnapshot(snapshot, label = "source") {
  const current = await captureSourceSnapshot(snapshot.path, label);
  assert.equal(current.sha256, snapshot.sha256, `${label}-changed-after-snapshot`);
  assert.equal(current.size, snapshot.size, `${label}-size-changed-after-snapshot`);
  return true;
}

export async function readProtectedJson(reference, { root, label = "protected-json" }) {
  assert.ok(reference && typeof reference.path === "string", `${label}-reference-required`);
  assert.match(reference.sha256, HASH, `${label}-hash-required`);
  assert.ok(isAbsolute(root) && await realpath(root) === root, `${label}-root-not-canonical`);
  const inside = relative(root, reference.path);
  assert.ok(inside && !inside.startsWith("../") && inside !== ".." && !isAbsolute(inside), `${label}-outside-root`);
  const snapshot = await captureProtectedSnapshot(reference.path, label);
  assert.equal(snapshot.sha256, reference.sha256, `${label}-hash-mismatch`);
  const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(snapshot.bytes));
  return Object.freeze({ value, snapshot });
}

export async function rebuildPrivateArtifactMap(outputDirectory, expectedArtifacts) {
  assert.ok(isAbsolute(outputDirectory), "artifact-root-must-be-absolute");
  assert.ok(expectedArtifacts && typeof expectedArtifacts === "object" && !Array.isArray(expectedArtifacts),
    "artifact-map-required");
  const entries = Object.entries(expectedArtifacts);
  assert.ok(entries.length > 0 && entries.length <= 150, "artifact-map-size-invalid");
  const metadata = await lstat(outputDirectory);
  assert.ok(metadata.isDirectory() && !metadata.isSymbolicLink(), "artifact-root-must-be-directory");
  assert.equal(metadata.uid, process.getuid(), "artifact-root-owner-mismatch");
  assert.equal(metadata.mode & 0o777, 0o700, "artifact-root-mode-mismatch");
  assert.equal(await realpath(outputDirectory), outputDirectory, "artifact-root-realpath-mismatch");
  const rebuilt = {};
  for (const [name, expected] of entries) {
    assert.match(name, /^[A-Za-z0-9][A-Za-z0-9._/-]{0,239}$/u, "artifact-name-invalid");
    assert.ok(!isAbsolute(name) && !name.split("/").includes(".."), "artifact-name-outside-root");
    assert.match(expected, HASH, "artifact-hash-invalid");
    const path = resolve(outputDirectory, name);
    const snapshot = await captureProtectedSnapshot(path, "artifact");
    assert.equal(snapshot.sha256, expected, "artifact-drift");
    rebuilt[name] = snapshot.sha256;
  }
  return rebuilt;
}
