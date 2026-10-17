#!/usr/bin/env node

import { createHash } from "node:crypto";
import { copyFile, lstat, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const FILES = ["app.mjs", "deployment.yaml", "synthetic.env"];
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const EXECUTABLE_REVISIONS = new Set([
  "sha256:c840f07f3271d47515b8677ce1efcb1ba3e962b7e27bac9cde3c11ac0443bae4",
  "sha256:ae002c07820d5af9893a5eb260e08c876f8cde5eff229fefa9e0fe059fc39fd2",
  "sha256:2826f18722c51124fdf4ccbc0a3d2a12ce83ce9cf069b6b63abc2f0f7792c5dc",
  "sha256:1199eb4dec455a2a79db7874dfca459e1d41cd16b1c84af541896af405816c96",
]);

export async function inspectCurrentWorkspace(directory) {
  const contents = await Promise.all(FILES.map((file) => readFile(resolve(directory, file), "utf8")));
  const digest = createHash("sha256");
  FILES.forEach((file, index) => digest.update(`${file}\0${contents[index]}\0`));
  const revision = `sha256:${digest.digest("hex")}`;
  // Never execute arbitrary model-written code. Functional execution is allowed
  // only after the complete fixture digest matches one of the reviewed states.
  let functionalAssertionPassed = false;
  if (EXECUTABLE_REVISIONS.has(revision)) {
    const moduleUrl = `${pathToFileURL(resolve(directory, "app.mjs")).href}?verification=${Date.now()}`;
    const application = await import(moduleUrl);
    functionalAssertionPassed = application.parseQuantity("2") === 2;
  }
  return {
    revision,
    functionalAssertionPassed,
    detections: {
      semgrep: contents[0].includes("Function("),
      gitleaks: /RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_[A-Z0-9]{16}/u.test(contents[2]),
      trivy: /^\s*privileged:\s*true\s*$/mu.test(contents[1]),
    },
  };
}

export async function prepareCurrentWorkspace(directory, repositoryRoot = ROOT) {
  const absolute = resolve(directory);
  try {
    const metadata = await lstat(absolute);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("workspace-boundary-changed");
    return { created: false, ...(await inspectCurrentWorkspace(absolute)) };
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await mkdir(absolute, { recursive: false, mode: 0o700 });
  for (const file of FILES) {
    await copyFile(resolve(repositoryRoot, "corpus", "code", "vulnerable", file), resolve(absolute, file));
  }
  await writeFile(resolve(absolute, ".rappor-laboratory-fixture.json"), `${JSON.stringify({
    schemaVersion: 1,
    fixture: "controlled-current-workspace",
    sourceState: "vulnerable",
    containsOnlySyntheticData: true,
  }, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  return { created: true, ...(await inspectCurrentWorkspace(absolute)) };
}

async function main() {
  const [command, directory] = process.argv.slice(2);
  if (!directory || !["prepare", "inspect"].includes(command)) throw new Error("invalid-arguments");
  const result = command === "prepare" ? await prepareCurrentWorkspace(directory) : await inspectCurrentWorkspace(directory);
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`current_workspace_fixture=${error.message}\n`);
    process.exitCode = 1;
  });
}
