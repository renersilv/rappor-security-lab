import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { verifyExternalPublicBaseline } from "../src/verify-external-public-baseline.mjs";

const recordUrl = new URL("../observations/public-external/2026-09-07T235826Z-v0.9.0.json", import.meta.url);
const controlledManifestUrl = new URL("../manifests/public-vibe-coding.json", import.meta.url);

test("dated external baseline is bounded, sanitized and informational", async () => {
  assert.deepEqual(await verifyExternalPublicBaseline(), {
    recordPath: "observations/public-external/2026-09-07T235826Z-v0.9.0.json",
    disposition: "informational",
    observations: 4,
    completed: 3,
    partial: 1,
    failed: 0,
  });
});

test("external observations do not enter controlled benchmark truth", async () => {
  const record = JSON.parse(await readFile(recordUrl, "utf8"));
  const controlledManifest = JSON.parse(await readFile(controlledManifestUrl, "utf8"));
  const externalUrls = new Set(record.observations.map((observation) => observation.url));
  const controlledTruth = JSON.stringify(controlledManifest);

  assert.equal(record.disposition, "informational");
  assert.ok(controlledManifest.targets.every((target) => target.control === "controlled"));
  for (const url of externalUrls) {
    assert.equal(controlledTruth.includes(url), false);
  }
});
