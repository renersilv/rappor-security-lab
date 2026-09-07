import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { compare, validateInputs } from "../src/compare.mjs";
import { buildPublicManifest } from "../src/generate-public-manifest.mjs";
import {
  CASE_DEFINITIONS,
  EXPECTED_OBSERVATIONS,
  verifyPublicTarget,
} from "../src/verify-public-target.mjs";

const manifestUrl = new URL("../manifests/public-vibe-coding.json", import.meta.url);

test("public target HTTP and DOM assertions match every lifecycle state", async () => {
  const results = await verifyPublicTarget();
  assert.deepEqual(Object.keys(results), Object.keys(EXPECTED_OBSERVATIONS));
  assert.equal(new Set(Object.values(results).map((result) => result.revision)).size, 4);

  for (const [state, expected] of Object.entries(EXPECTED_OBSERVATIONS)) {
    assert.match(results[state].revision, /^sha256:[a-f0-9]{64}$/);
    assert.deepEqual(results[state].observations, expected);
    assert.deepEqual(results[state].functional, {
      inertForm: true,
      mutationRejected: true,
      publicResourceAvailable: true,
      rootAvailable: true,
    });
  }
});

test("checked-in public manifest is deterministic, valid and clean for ground truth", async () => {
  const checkedIn = JSON.parse(await readFile(manifestUrl, "utf8"));
  const generated = await buildPublicManifest();
  assert.deepEqual(checkedIn, generated);
  validateInputs(checkedIn, checkedIn.exampleRun);

  const report = compare(checkedIn, checkedIn.exampleRun);
  assert.equal(report.verdict, "passed");
  assert.equal(report.clean, true);
  assert.deepEqual(report.counts, {
    "true-positive": 29,
    "false-positive": 0,
    "true-negative": 11,
    "false-negative": 0,
    inconclusive: 0,
  });
});

test("manifest pins every condition, state, assertion type and scanner profile", async () => {
  const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));
  const profile = await readFile(new URL("../scanner-profiles/public-passive.json", import.meta.url));
  const rulesetDigest = `sha256:${createHash("sha256").update(profile).digest("hex")}`;

  assert.equal(manifest.targets.length, 4);
  assert.equal(manifest.cases.length, Object.keys(CASE_DEFINITIONS).length * 4);
  for (const state of Object.keys(EXPECTED_OBSERVATIONS)) {
    const target = manifest.targets.find((item) => item.id === `public-vibe-coding-${state}`);
    assert.ok(target, `missing target for ${state}`);
    assert.equal(target.control, "controlled");
    assert.equal(target.layer, "public");

    for (const [key, definition] of Object.entries(CASE_DEFINITIONS)) {
      assert.match(definition.assertion, /^(http|dom|http-and-dom)$/);
      const benchmarkCase = manifest.cases.find((item) => item.id === `public-${definition.id}-${state}`);
      assert.ok(benchmarkCase, `missing manifest case for ${key}/${state}`);
      assert.equal(benchmarkCase.targetId, target.id);
      assert.equal(benchmarkCase.targetRevision, target.revision);
      assert.equal(benchmarkCase.expectedPresence, EXPECTED_OBSERVATIONS[state][key]);
      assert.equal(benchmarkCase.fixedCaseId, `public-${definition.id}-fixed`);
      assert.equal(benchmarkCase.scannerProfile, "public-passive@2");
      assert.equal(benchmarkCase.rulesetDigest, rulesetDigest);
    }
  }
});

test("target source defaults safe and cannot submit or persist visitor data", async () => {
  const states = await readFile(new URL("../targets/public/vibe-coding/lib/states.mjs", import.meta.url), "utf8");
  const proxy = await readFile(new URL("../targets/public/vibe-coding/proxy.js", import.meta.url), "utf8");
  const client = await readFile(new URL("../targets/public/vibe-coding/app/lab-client.jsx", import.meta.url), "utf8");
  const page = await readFile(new URL("../targets/public/vibe-coding/app/page.jsx", import.meta.url), "utf8");

  assert.match(states, /RAPPOR_LAB_STATE \?\? "fixed"/);
  assert.match(proxy, /!\[.*"GET".*"HEAD".*\]\.includes\(request\.method\)/s);
  assert.doesNotMatch(proxy, /request\.(?:arrayBuffer|blob|formData|json|text)\(/);
  assert.match(client, /persistSession: false/);
  assert.match(client, /global: \{ fetch: blockedFetch \}/);
  assert.match(page, /<input[^>]+disabled/s);
  assert.doesNotMatch(page, /<input[^>]+name=/s);
  assert.match(page, /<button type="button" disabled>/);
});
