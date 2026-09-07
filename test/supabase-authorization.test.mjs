import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { compare, validateInputs } from "../src/compare.mjs";
import { buildSupabaseManifest } from "../src/generate-supabase-manifest.mjs";
import {
  checkSupabaseState,
  loadPublicEnvironment,
  resetSupabaseLab,
  runSupabaseLifecycle,
} from "../src/run-supabase-authorization.mjs";
import { verifySupabaseTarget } from "../src/verify-supabase-target.mjs";
import { createPublicSupabaseConfig } from "../targets/connected/supabase-authorization/browser/public-config.mjs";
import {
  STATE_ORDER,
  STATES,
} from "../targets/connected/supabase-authorization/lib/states.mjs";

const manifestUrl = new URL("../manifests/supabase-authorization.json", import.meta.url);
const config = {
  url: "https://rappor-lab.supabase.co",
  publishableKey: "sb_publishable_RAPPOR_LAB_TEST_ONLY",
  email: "auth-user@example.invalid",
  password: "RAPPOR_LAB_DUMMY_PASSWORD",
};

function response(status, headers = {}) {
  return new Response(null, { status, headers });
}

function createProtocolFixture(getState, requests) {
  return async (url, options) => {
    requests.push({ url, options });
    if (url.includes("/auth/v1/token")) {
      return new Response(JSON.stringify({ access_token: "RAPPOR_LAB_DUMMY_USER_TOKEN" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    const actor = options.headers.authorization ? "authenticated" : "anon";
    const operation = options.method === "HEAD" ? "read" : "write";
    const allowed = STATES[getState()].expectedAccess[actor][operation];
    if (operation === "read") {
      return allowed
        ? response(206, { "content-range": "0-0/1" })
        : response(200, { "content-range": "*/0" });
    }
    return response(allowed ? 201 : 403);
  };
}

test("Supabase migrations pin four distinct access-control revisions", async () => {
  const results = await verifySupabaseTarget();
  assert.deepEqual(Object.keys(results), STATE_ORDER);
  assert.equal(new Set(Object.values(results).map((result) => result.revision)).size, 4);
  for (const stateName of STATE_ORDER) {
    assert.match(results[stateName].revision, /^sha256:[a-f0-9]{64}$/);
    assert.deepEqual(results[stateName].accessControl, STATES[stateName].accessControl);
    assert.deepEqual(results[stateName].expectedAccess, STATES[stateName].expectedAccess);
  }
});

test("checked-in Supabase manifest is deterministic and declares grants and policies", async () => {
  const checkedIn = JSON.parse(await readFile(manifestUrl, "utf8"));
  const generated = await buildSupabaseManifest();
  assert.deepEqual(checkedIn, generated);
  const observations = checkedIn.cases.map((benchmarkCase) => ({
    caseId: benchmarkCase.id,
    present: benchmarkCase.expectedPresence,
  }));
  validateInputs(checkedIn, { status: "completed", observations });

  const report = compare(checkedIn, { status: "completed", observations });
  assert.equal(report.verdict, "passed");
  assert.equal(report.clean, true);
  assert.deepEqual(report.counts, {
    "true-positive": 5,
    "false-positive": 0,
    "true-negative": 11,
    "false-negative": 0,
    inconclusive: 0,
  });
  for (const target of checkedIn.targets) {
    assert.equal(target.layer, "connected");
    assert.equal(target.accessControl.relation, "public.rappor_lab_documents");
    assert.deepEqual(target.accessControl, STATES[target.id.replace("supabase-authorization-", "")].accessControl);
  }
});

test("lifecycle checks anonymous and authenticated reads and writes without row responses", async () => {
  let activeState;
  const applied = [];
  const requests = [];
  let cleaned = false;
  const request = createProtocolFixture(() => activeState, requests);
  const run = await runSupabaseLifecycle({
    config,
    pgService: "rappor-lab-test",
    request,
    applyState: async (stateName) => {
      activeState = stateName;
      applied.push(stateName);
    },
    cleanup: async () => {
      cleaned = true;
    },
  });
  const manifest = await buildSupabaseManifest();
  assert.deepEqual(applied, STATE_ORDER);
  assert.equal(cleaned, true);
  assert.equal(requests.length, STATE_ORDER.length * 5);
  assert.equal(run.observations.length, 16);
  assert.equal(compare(manifest, run).clean, true);

  for (const item of requests.filter((item) => item.options.method === "HEAD")) {
    assert.equal(item.options.body, undefined);
    assert.equal(item.options.headers.prefer, "count=exact");
  }
  for (const item of requests.filter((item) => item.url.includes("/rest/v1/") && item.options.method === "POST")) {
    assert.equal(item.options.headers.prefer, "return=minimal");
    assert.match(item.options.body, /^\{"marker":"RAPPOR_LAB_DUMMY_[A-Z_]+"\}$/);
  }
  const serialized = JSON.stringify(run);
  for (const excluded of [config.publishableKey, config.email, config.password, "RAPPOR_LAB_DUMMY_USER_TOKEN", "content-range"]) {
    assert.doesNotMatch(serialized, new RegExp(excluded));
  }
});

test("lifecycle cleanup runs after a bounded request failure", async () => {
  let cleaned = false;
  await assert.rejects(
    runSupabaseLifecycle({
      config,
      pgService: "rappor-lab-test",
      request: async () => {
        throw new Error("must-not-be-reported");
      },
      applyState: async () => {},
      cleanup: async () => {
        cleaned = true;
      },
    }),
    (error) => {
      assert.equal(error.message, "the bounded Supabase request did not complete");
      return true;
    },
  );
  assert.equal(cleaned, true);
});

test("single-state access results map allowed access to finding semantics", async () => {
  for (const stateName of STATE_ORDER) {
    const requests = [];
    const run = await checkSupabaseState(
      stateName,
      config,
      createProtocolFixture(() => stateName, requests),
    );
    assert.equal(run.status, "completed");
    assert.equal(run.observations.length, 4);
    for (const observation of run.observations) {
      const expected = (await buildSupabaseManifest()).cases.find((item) => item.id === observation.caseId);
      assert.equal(observation.present, expected.expectedPresence);
    }
  }
});

test("reset uses an external pg service and verifies relation removal", async () => {
  const calls = [];
  const runner = async (command, arguments_, options) => {
    calls.push({ command, arguments_, options });
    return { stdout: calls.length === 2 ? "t\n" : "", stderr: "" };
  };
  assert.deepEqual(await resetSupabaseLab("rappor-lab-test", runner), {
    status: "completed",
    reset: true,
    relation: "public.rappor_lab_documents",
  });
  assert.equal(calls.length, 2);
  assert.ok(calls.every((call) => call.command === "psql"));
  assert.ok(calls.every((call) => call.options.env.PGSERVICE === "rappor-lab-test"));
  assert.ok(calls.every((call) => call.arguments_.every((argument) => !argument.includes("password"))));
});

test("browser configuration accepts only URL and a publishable key", async () => {
  assert.deepEqual(
    createPublicSupabaseConfig({ url: config.url, publishableKey: config.publishableKey }),
    { url: config.url, publishableKey: config.publishableKey },
  );
  assert.throws(
    () => createPublicSupabaseConfig({ url: config.url, publishableKey: "sb_secret_NOT_ALLOWED" }),
    /publishable key/,
  );
  assert.deepEqual(loadPublicEnvironment({
    SUPABASE_LAB_URL: config.url,
    SUPABASE_LAB_PUBLISHABLE_KEY: config.publishableKey,
    SUPABASE_LAB_DATABASE_URL: "must-not-be-read",
  }), { url: config.url, publishableKey: config.publishableKey });

  const source = await readFile(
    new URL("../targets/connected/supabase-authorization/browser/public-config.mjs", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(source, /secret|service.role|database|password/i);
});
