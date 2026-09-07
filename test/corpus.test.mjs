import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { STATES, verifyCorpus } from "../src/verify-corpus.mjs";

test("corpus signals and functional assertions match every lifecycle state", async () => {
  const results = await verifyCorpus();
  assert.deepEqual(Object.keys(results), Object.keys(STATES));
  for (const [state, expected] of Object.entries(STATES)) {
    assert.deepEqual(results[state].detections, expected);
    assert.match(results[state].revision, /^sha256:[a-f0-9]{64}$/);
  }
});

test("manifest code targets pin the corpus content revisions and case matrix", async () => {
  const manifest = JSON.parse(await readFile(new URL("../manifests/example.json", import.meta.url), "utf8"));
  const results = await verifyCorpus();
  const targets = new Map(manifest.targets.map((target) => [target.id, target]));

  const caseIds = {
    semgrep: {
      vulnerable: "semgrep-sql-injection-vulnerable",
      "partially-fixed": "semgrep-dynamic-function-partially-fixed",
      fixed: "semgrep-sql-injection-fixed",
      reintroduced: "semgrep-dynamic-function-reintroduced",
    },
    gitleaks: {
      vulnerable: "gitleaks-marker-vulnerable",
      "partially-fixed": "gitleaks-marker-partially-fixed",
      fixed: "gitleaks-marker-fixed",
      reintroduced: "gitleaks-marker-reintroduced",
    },
    trivy: {
      vulnerable: "trivy-privileged-container-vulnerable",
      "partially-fixed": "trivy-package-partially-fixed",
      fixed: "trivy-package-fixed",
      reintroduced: "trivy-package-reintroduced",
    },
  };

  for (const state of Object.keys(STATES)) {
    assert.equal(targets.get(`code-${state}`).revision, results[state].revision);
    for (const scanner of Object.keys(STATES[state])) {
      const benchmarkCase = manifest.cases.find((item) => item.id === caseIds[scanner][state]);
      assert.ok(benchmarkCase, `missing manifest case for ${scanner}/${state}`);
      assert.equal(benchmarkCase.targetId, `code-${state}`);
      assert.equal(benchmarkCase.expectedPresence, STATES[state][scanner]);
    }
  }
});

test("synthetic marker family is explicit and no provider-shaped fixture is present", async () => {
  const fixed = await readFile(new URL("../corpus/code/fixed/synthetic.env", import.meta.url), "utf8");
  assert.doesNotMatch(fixed, /SYNTHETIC_SECRET_DO_NOT_USE/);
  assert.match(fixed, /RAPPOR_LAB_NO_SECRET_FIXTURE/);
});
