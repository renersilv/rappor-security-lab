import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { compare, validateInputs } from "../src/compare.mjs";
import { buildProviderConfigurationManifest } from "../src/generate-provider-configuration-manifest.mjs";
import {
  buildSanitizedReport,
  createVercelAdapter,
  providerReportToMarkdown,
  runSupabaseConfigurationLifecycle,
  runVercelConfigurationLifecycle,
} from "../src/run-provider-configuration.mjs";
import { verifyProviderConfigurationReport } from "../src/verify-provider-configuration-report.mjs";
import { verifyProviderConfigurationTarget } from "../src/verify-provider-configuration-target.mjs";
import {
  STATE_ORDER,
  SUPABASE_STATES,
  VERCEL_STATES,
} from "../targets/connected/provider-configuration/lib/states.mjs";

const manifestUrl = new URL("../manifests/provider-configuration.json", import.meta.url);
const sourceCommit = "1".repeat(40);
const environment = {
  SUPABASE_LAB_URL: "https://rappor-lab.supabase.co",
  SUPABASE_LAB_PUBLISHABLE_KEY: "sb_publishable_RAPPOR_LAB_TEST_ONLY",
  SUPABASE_LAB_AUTH_EMAIL: "auth-user@example.invalid",
  SUPABASE_LAB_AUTH_PASSWORD: "RAPPOR_LAB_DUMMY_PASSWORD",
  SUPABASE_LAB_PGSERVICE: "rappor-lab-test",
};

test("provider configuration fixtures and checked-in manifest are deterministic", async () => {
  const verified = await verifyProviderConfigurationTarget();
  assert.deepEqual(Object.keys(verified.supabase), STATE_ORDER);
  assert.deepEqual(Object.keys(verified.vercel), STATE_ORDER);
  const generated = await buildProviderConfigurationManifest();
  const checkedIn = JSON.parse(await readFile(manifestUrl, "utf8"));
  assert.deepEqual(checkedIn, generated);
  assert.equal(generated.targets.length, 8);
  assert.equal(generated.cases.length, 32);
  const run = {
    status: "completed",
    observations: generated.cases.map((item) => ({ caseId: item.id, present: item.expectedPresence })),
  };
  validateInputs(generated, run);
  assert.equal(compare(generated, run).clean, true);
});

test("Supabase lifecycle proves catalog and authorization states then cleans in finally", async () => {
  const applied = [];
  let activeState;
  let cleaned = 0;
  const lifecycle = await runSupabaseConfigurationLifecycle({
    environment,
    applyState: async (state) => {
      activeState = state;
      applied.push(state);
    },
    readConfiguration: async () => structuredClone(SUPABASE_STATES[activeState].findings),
    checkAuthorization: async () => ({ status: "completed", observations: Array.from({ length: 4 }, () => ({})) }),
    cleanup: async () => {
      cleaned += 1;
      return {
        authorizationRelationAbsent: true,
        configurationObjectsAbsent: true,
        bucketAbsent: true,
        bucketPolicyAbsent: true,
      };
    },
  });
  assert.deepEqual(applied, STATE_ORDER);
  assert.equal(cleaned, 1);
  assert.equal(lifecycle.states.length, 4);
  assert.equal(lifecycle.observations.length, 28);
  assert.ok(lifecycle.states.every((state) => state.authorizationChecks === 4));
});

test("Supabase cleanup still runs when an intermediate catalog assertion fails", async () => {
  let cleaned = false;
  await assert.rejects(
    runSupabaseConfigurationLifecycle({
      environment,
      applyState: async () => {},
      readConfiguration: async () => Object.fromEntries(Object.keys(SUPABASE_STATES.vulnerable.findings).map((key) => [key, false])),
      checkAuthorization: async () => ({ status: "completed", observations: Array.from({ length: 4 }, () => ({})) }),
      cleanup: async () => {
        cleaned = true;
        return {
          authorizationRelationAbsent: true,
          configurationObjectsAbsent: true,
          bucketAbsent: true,
          bucketPolicyAbsent: true,
        };
      },
    }),
    /catalog post-condition did not match ground truth/,
  );
  assert.equal(cleaned, true);
});

function memoryVercelAdapter(events, failState) {
  const values = new Map(Object.values(VERCEL_STATES).map((state) => [state.project, true]));
  return {
    read: async (project) => {
      events.push(["read", project]);
      return { gitForkProtection: values.get(project) };
    },
    update: async (project, value) => {
      events.push(["update", project, value]);
      if (failState && project === VERCEL_STATES[failState].project && value === VERCEL_STATES[failState].gitForkProtection) {
        failState = null;
        throw new Error("synthetic failure");
      }
      values.set(project, value);
      return { gitForkProtection: value };
    },
  };
}

test("Vercel lifecycle observes all four states and restores every project to safe", async () => {
  const events = [];
  const lifecycle = await runVercelConfigurationLifecycle({ adapter: memoryVercelAdapter(events) });
  assert.deepEqual(lifecycle.states, STATE_ORDER.map((state) => ({
    state,
    gitForkProtection: VERCEL_STATES[state].gitForkProtection,
  })));
  assert.deepEqual(lifecycle.cleanup, { gitForkProtection: true, projectsRestored: 4, verified: true });
  assert.equal(lifecycle.observations.length, 4);
  for (const project of Object.values(VERCEL_STATES).map((state) => state.project)) {
    assert.ok(events.some((event) => event[0] === "update" && event[1] === project && event[2] === true));
  }
});

test("Vercel lifecycle restores safe values after a mid-cycle failure", async () => {
  const events = [];
  await assert.rejects(
    runVercelConfigurationLifecycle({ adapter: memoryVercelAdapter(events, "reintroduced") }),
    /synthetic failure/,
  );
  const cleanupTail = events.slice(-8);
  assert.equal(cleanupTail.filter((event) => event[0] === "update" && event[2] === true).length, 4);
  assert.equal(cleanupTail.filter((event) => event[0] === "read").length, 4);
});

test("official Vercel adapter discards response identifiers and sends a typed boolean", async () => {
  const calls = [];
  const runner = async (command, arguments_, options) => {
    calls.push({ command, arguments_, options });
    return {
      stdout: JSON.stringify({
        id: "prj_MUST_NOT_ESCAPE",
        accountId: "team_MUST_NOT_ESCAPE",
        name: "rappor-lab-fixed",
        gitForkProtection: true,
        env: [{ value: "MUST_NOT_ESCAPE" }],
      }),
      stderr: "",
    };
  };
  const adapter = createVercelAdapter({ HOME: "/tmp/test", PATH: "/usr/bin" }, runner);
  assert.deepEqual(await adapter.update("rappor-lab-fixed", true), { gitForkProtection: true });
  assert.deepEqual(calls[0].arguments_.slice(-4), ["--method", "PATCH", "--field", "gitForkProtection=true"]);
  assert.deepEqual(Object.keys(calls[0].options.env).sort(), ["HOME", "PATH"]);
});

test("sanitized provider reports contain only logical cases and verified cleanup", async () => {
  const manifest = await buildProviderConfigurationManifest();
  for (const provider of ["supabase", "vercel"]) {
    const prefix = `${provider}-`;
    const cases = manifest.cases.filter((item) => item.id.startsWith(prefix));
    const lifecycle = {
      provider,
      status: "completed",
      states: STATE_ORDER.map((state) => provider === "supabase"
        ? { state, authorizationChecks: 4 }
        : { state, gitForkProtection: VERCEL_STATES[state].gitForkProtection }),
      observations: cases.map((item) => ({ caseId: item.id, present: item.expectedPresence })),
      cleanup: provider === "supabase"
        ? { authorizationRelationAbsent: true, configurationObjectsAbsent: true, bucketAbsent: true, bucketPolicyAbsent: true }
        : { gitForkProtection: true, projectsRestored: 4, verified: true },
    };
    const report = buildSanitizedReport(manifest, lifecycle, sourceCommit, "2026-09-17T21:30:00.000Z");
    const markdown = providerReportToMarkdown(report);
    const verified = await verifyProviderConfigurationReport(report, markdown);
    assert.equal(verified.provider, provider);
    const serialized = JSON.stringify(report);
    for (const excluded of ["prj_", "team_", "sb_publishable_", "@example.invalid", "rappor-lab-fixed"]) {
      assert.doesNotMatch(serialized, new RegExp(excluded));
    }
  }
});
