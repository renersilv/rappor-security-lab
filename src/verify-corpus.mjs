#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const STATES = {
  vulnerable: { semgrep: true, gitleaks: true, trivy: true },
  "partially-fixed": { semgrep: false, gitleaks: true, trivy: true },
  fixed: { semgrep: false, gitleaks: false, trivy: false },
  reintroduced: { semgrep: true, gitleaks: true, trivy: true },
};

const FILES = ["app.mjs", "deployment.yaml", "synthetic.env"];
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");

export async function inspectState(state, repositoryRoot = REPOSITORY_ROOT) {
  if (!(state in STATES)) throw new Error(`unknown corpus state: ${state}`);
  const directory = resolve(repositoryRoot, "corpus", "code", state);
  const contents = await Promise.all(FILES.map((file) => readFile(resolve(directory, file), "utf8")));
  const [application, deployment, marker] = contents;
  const digest = createHash("sha256");
  for (let index = 0; index < FILES.length; index += 1) {
    digest.update(`${FILES[index]}\0${contents[index]}\0`);
  }
  return {
    revision: `sha256:${digest.digest("hex")}`,
    detections: {
      semgrep: application.includes("Function("),
      gitleaks: /RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_[A-Z0-9]{16}/.test(marker),
      trivy: /^\s*privileged:\s*true\s*$/m.test(deployment),
    },
  };
}

export async function verifyCorpus(repositoryRoot = REPOSITORY_ROOT) {
  const results = {};
  for (const [state, expected] of Object.entries(STATES)) {
    const actual = await inspectState(state, repositoryRoot);
    for (const scanner of Object.keys(expected)) {
      if (actual.detections[scanner] !== expected[scanner]) {
        throw new Error(`${state}/${scanner} does not match the expected corpus signal`);
      }
    }
    const applicationUrl = pathToFileURL(resolve(repositoryRoot, "corpus", "code", state, "app.mjs"));
    const application = await import(applicationUrl.href);
    if (application.parseQuantity("2") !== 2) {
      throw new Error(`${state} does not preserve the functional assertion`);
    }
    results[state] = actual;
  }
  return results;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  verifyCorpus()
    .then((results) => process.stdout.write(`${JSON.stringify(results, null, 2)}\n`))
    .catch((error) => {
      process.stderr.write(`Corpus verification failed: ${error.message}\n`);
      process.exitCode = 1;
    });
}
