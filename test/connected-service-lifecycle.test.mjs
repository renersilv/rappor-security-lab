import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ConnectedServiceClient,
  createCheckpointStore,
  ensureConnectedSetup,
  normalizeConnectedResult,
  pollConnectedAssessment,
  probeVisibleVersion,
  runConnectedServiceLifecycle,
  evaluateLifecycle,
  summarizeOutcomes,
} from "../src/run-connected-service-lifecycle.mjs";
import { verifyConnectedServiceLifecycleReport } from "../src/verify-connected-service-lifecycle-report.mjs";
import {
  SUPABASE_AFFECTED_ITEMS,
  SUPABASE_CANONICAL_RULES,
  SUPABASE_CANONICAL_STATES,
} from "../targets/connected/provider-configuration/lib/connected-analysis.mjs";
import { STATE_ORDER } from "../targets/connected/provider-configuration/lib/states.mjs";

const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const PRODUCT_ID = "11111111-1111-4111-8111-111111111111";
const CONNECTION_ID = "22222222-2222-4222-8222-222222222222";
const RESOURCE_ID = "33333333-3333-4333-8333-333333333333";
const DEFINITION_ID = "44444444-4444-4444-8444-444444444444";
const REVISION_ID = "55555555-5555-4555-8555-555555555555";
const ASSESSMENT_IDS = [
  "66666666-6666-4666-8666-666666666661",
  "66666666-6666-4666-8666-666666666662",
  "66666666-6666-4666-8666-666666666663",
  "66666666-6666-4666-8666-666666666664",
];

function resource(id, displayName) {
  return { id, displayName, state: "Authorized" };
}

function definition({ id = DEFINITION_ID, sourceId = RESOURCE_ID, provider = "Supabase", name = "Supabase lifecycle" } = {}) {
  return {
    id,
    type: "ConnectedService",
    name,
    environment: "Staging",
    state: "Active",
    archivedAt: null,
    currentRevisionId: REVISION_ID,
    version: 1,
    sourceId,
    sourceKind: provider,
    configurationJson: JSON.stringify({ provider, resourceId: sourceId }),
  };
}

function completedDetail(provider = "supabase", findings = [], state = "fixed") {
  const isVercel = provider === "vercel";
  const checks = isVercel
    ? [
        { ruleId: "vercel.git-fork-protection.disabled.v1", state: "Measured" },
        { ruleId: "vercel.preview-deployment-authentication.disabled.v1", state: "Measured" },
      ]
    : Object.values(SUPABASE_CANONICAL_RULES).map(({ ruleFamily }) => ({ ruleId: ruleFamily, state: "Measured" }));
  const score = {
    vulnerable: 20,
    "partially-fixed": 50,
    fixed: 100,
    reintroduced: 20,
  }[state];
  const evolution = {
    vulnerable: { new: findings.length, stillOpen: 0, fixed: 0, reappeared: 0 },
    "partially-fixed": { new: 0, stillOpen: findings.length, fixed: 6, reappeared: 0 },
    fixed: { new: 0, stillOpen: 0, fixed: 3, reappeared: 0 },
    reintroduced: { new: 0, stillOpen: 0, fixed: 0, reappeared: findings.length },
  }[state];
  return {
    assessment: {
      state: "Completed",
      profile: isVercel ? "VercelConfiguration" : "SupabaseConfiguration",
      profileVersion: 1,
      securityScore: { score, presentation: "A", classification: "excellent", coverage: { percentage: 100 } },
      evolution,
    },
    connectedServiceCoverage: {
      status: "Complete",
      resultContractVersion: isVercel ? "vercel-project-configuration.v3" : "supabase-project-configuration.v1",
      rulesVersion: "rules.v1",
      coverageVersion: "coverage.v1",
      checks,
    },
    runs: [{
      scannerKey: isVercel ? "rappor.vercel-configuration" : "rappor.supabase-configuration",
      scannerVersion: "1.2.3",
      state: "Completed",
    }],
    findings,
  };
}

function supabaseFindings(state) {
  return SUPABASE_CANONICAL_STATES[state].flatMap(({ rule, affectedItems }) => affectedItems.map((affectedItem) => ({
    ruleId: SUPABASE_CANONICAL_RULES[rule].ruleFamily,
    severity: SUPABASE_CANONICAL_RULES[rule].severity,
    location: SUPABASE_AFFECTED_ITEMS[affectedItem],
    fingerprint: `${rule}:${affectedItem}`,
  })));
}

class MemoryClient {
  constructor({ provider = "Supabase", connectionState = "Active", definitions = [definition()] } = {}) {
    this.provider = provider;
    this.connectionState = connectionState;
    this.product = { id: PRODUCT_ID, name: "Connected Provider Laboratory", archivedAt: null, version: 1 };
    this.items = definitions;
    this.createdInputs = [];
    this.runCalls = 0;
    this.assessmentCalls = 0;
    this.timeoutFirst = false;
  }

  async products() {
    return { items: [this.product] };
  }

  async createProduct() {
    throw new Error("product should be reused");
  }

  async connectedServices() {
    const resources = this.provider === "Vercel"
      ? [
          resource("33333333-3333-4333-8333-333333333331", "rappor-lab-vulnerable"),
          resource("33333333-3333-4333-8333-333333333332", "rappor-lab-partially-fixed"),
          resource("33333333-3333-4333-8333-333333333333", "rappor-lab-fixed"),
          resource("33333333-3333-4333-8333-333333333334", "rappor-lab-reintroduced"),
        ]
      : [resource(RESOURCE_ID, "rappor-security-lab")];
    return {
      providers: [{ provider: this.provider, available: true, supportsPkce: true }],
      connections: [{ id: CONNECTION_ID, provider: this.provider, state: this.connectionState, resources }],
    };
  }

  async definitions() {
    return { items: this.items };
  }

  async createConnectedDefinition(_productId, input) {
    this.createdInputs.push(input);
    const created = definition({
      id: `77777777-7777-4777-8777-77777777777${this.createdInputs.length}`,
      sourceId: input.resourceId,
      provider: input.provider,
      name: input.name,
    });
    this.items.push(created);
    return this.wrapCreatedDefinition ? { analysisDefinition: { id: created.id } } : created;
  }

  async runDefinition() {
    const id = ASSESSMENT_IDS[this.runCalls];
    this.runCalls += 1;
    return { id };
  }

  async assessment() {
    this.assessmentCalls += 1;
    if (this.timeoutFirst) return { assessment: { state: "Running" } };
    const provider = this.provider.toLowerCase();
    const state = STATE_ORDER[Math.max(0, this.runCalls - 1)];
    return completedDetail(provider, provider === "supabase" ? supabaseFindings(state) : [], state);
  }
}

function memoryAdapter(events) {
  return {
    async apply(state) {
      events.push(`apply:${state}`);
    },
    async cleanup() {
      events.push("cleanup");
      return { verified: true, resourcesRestored: 1 };
    },
  };
}

test("dedicated authentication is exercised through the public CSRF and session contract", async () => {
  const requests = [];
  const responses = [
    new Response(JSON.stringify({ token: "csrf-token-with-enough-length" }), {
      status: 200,
      headers: { "content-type": "application/json", "set-cookie": "csrf=one; Path=/" },
    }),
    new Response(null, { status: 204, headers: { "set-cookie": "session=two; Path=/" } }),
    new Response(JSON.stringify({ authenticated: true, activeTenant: "laboratory" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  ];
  const client = new ConnectedServiceClient("https://hml.example", async (url, options) => {
    requests.push({ path: new URL(url).pathname, method: options.method, hasCookie: Boolean(options.headers.Cookie) });
    return responses.shift();
  });

  await client.login("synthetic@example.invalid", "synthetic-password");
  assert.deepEqual(requests, [
    { path: "/api/auth/csrf", method: "GET", hasCookie: false },
    { path: "/api/auth/login", method: "POST", hasCookie: true },
    { path: "/api/auth/session", method: "GET", hasCookie: true },
  ]);
});

test("connected setup reuses one Product and creates exact Vercel definitions without duplicates", async () => {
  const client = new MemoryClient({ provider: "Vercel", definitions: [] });
  client.wrapCreatedDefinition = true;
  const setup = await ensureConnectedSetup(client, "vercel");

  assert.equal(setup.productReused, true);
  assert.equal(setup.createdDefinitions, 4);
  assert.deepEqual(client.createdInputs.map((item) => item.name), [
    "Vercel vulnerable",
    "Vercel partially-fixed",
    "Vercel fixed",
    "Vercel reintroduced",
  ]);
  assert.deepEqual(client.createdInputs.map((item) => Object.keys(item).sort()), [
    ["environment", "name", "provider", "resourceId"],
    ["environment", "name", "provider", "resourceId"],
    ["environment", "name", "provider", "resourceId"],
    ["environment", "name", "provider", "resourceId"],
  ]);

  const repeated = await ensureConnectedSetup(client, "vercel");
  assert.equal(repeated.createdDefinitions, 0);
  assert.equal(client.createdInputs.length, 4);
});

test("inactive consent fails before a Product execution", async () => {
  const client = new MemoryClient({ connectionState: "Disconnected" });
  await assert.rejects(
    ensureConnectedSetup(client, "supabase"),
    (error) => error.code === "consent-required",
  );
  assert.equal(client.runCalls, 0);
});

test("consent and visible-version failures produce sanitized non-clean reports", async () => {
  const directory = await mkdtemp(join(tmpdir(), "connected-setup-report-"));
  try {
    const report = await runConnectedServiceLifecycle({
      provider: "supabase",
      client: new MemoryClient({ connectionState: "Disconnected" }),
      adapter: memoryAdapter([]),
      checkpointStore: createCheckpointStore(join(directory, "checkpoint.json")),
      expectedVersion: "v0.78.0",
      sourceCommit: COMMIT,
    });
    assert.equal(report.summary.outcome, "BlockedByConsent");
    assert.equal(report.states[0].failureCode, "consent-required");
    assert.equal(report.setup.connectionState, "Unavailable");
    assert.equal(verifyConnectedServiceLifecycleReport(report).clean, false);

    const mismatch = await runConnectedServiceLifecycle({
      provider: "supabase",
      client: new MemoryClient(),
      adapter: memoryAdapter([]),
      checkpointStore: createCheckpointStore(join(directory, "mismatch.json")),
      expectedVersion: "v0.78.0",
      observedVersion: "v0.77.0",
      sourceCommit: COMMIT,
    });
    assert.equal(mismatch.summary.outcome, "Failed");
    assert.equal(mismatch.states[0].failureCode, "deployment-version-mismatch");
    assert.equal(mismatch.application.visibleVersionMatches, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the public page exposes one observed semantic version", async () => {
  const observed = await probeVisibleVersion("https://hml.example/path", async (url, options) => {
    assert.equal(url, "https://hml.example");
    assert.equal(options.headers.Accept, "text/html");
    return new Response("<footer>Rappor Security v0.78.0</footer>", { status: 200 });
  });
  assert.equal(observed, "v0.78.0");
});

test("bounded polling rejects a non-terminal run", async () => {
  const client = { assessment: async () => ({ assessment: { state: "Running" } }) };
  await assert.rejects(
    pollConnectedAssessment(client, ASSESSMENT_IDS[0], { maxPolls: 2, pollIntervalMs: 0, sleep: async () => {} }),
    (error) => error.code === "poll-timeout",
  );
});

test("normalization distinguishes Passed, Inconclusive and Failed without treating missing coverage as clean", () => {
  const vulnerable = normalizeConnectedResult("vercel", "vulnerable", completedDetail("vercel", [
    { ruleId: "vercel.git-fork-protection.disabled.v1", severity: "high" },
  ], "vulnerable"));
  assert.equal(vulnerable.outcome, "Passed");
  assert.equal(vulnerable.expectedMeasuredFinding, true);
  assert.equal(vulnerable.observedMeasuredFinding, true);

  const partial = completedDetail("vercel");
  partial.connectedServiceCoverage.status = "Partial";
  assert.equal(normalizeConnectedResult("vercel", "fixed", partial).outcome, "Inconclusive");

  const notApplicable = completedDetail("vercel", [], "fixed");
  notApplicable.connectedServiceCoverage.checks[0].state = "NotApplicable";
  const unmeasured = normalizeConnectedResult("vercel", "fixed", notApplicable);
  assert.equal(unmeasured.outcome, "Inconclusive");
  assert.equal(unmeasured.expectationMatched, true);
  assert.equal(unmeasured.measuredManifestCaseCount, 0);
  assert.deepEqual(unmeasured.unmeasuredRuleIds, ["vercel.git-fork-protection.disabled.v1"]);

  const failed = completedDetail("vercel");
  failed.assessment.state = "Failed";
  failed.runs[0].state = "Failed";
  failed.runs[0].failureCode = "connected-service-invalid-response";
  failed.connectedServiceCoverage.status = "Unavailable";
  assert.equal(normalizeConnectedResult("vercel", "fixed", failed).outcome, "Failed");
});

test("normalization detects duplicate rule findings and preserves only safe score fields", () => {
  const detail = completedDetail("vercel", [
    { ruleId: "vercel.git-fork-protection.disabled.v1", severity: "high", evidence: "secret" },
    { ruleId: "vercel.git-fork-protection.disabled.v1", severity: "high", evidence: "secret" },
  ], "vulnerable");
  const result = normalizeConnectedResult("vercel", "vulnerable", detail);
  assert.equal(result.duplicateFindings, 1);
  assert.deepEqual(result.score, {
    score: 20,
    presentation: "A",
    classification: "excellent",
    coveragePercentage: 100,
  });
  assert.doesNotMatch(JSON.stringify(result), /secret/u);
});

test("Supabase normalization requires the exact independent rules and severities for each state", () => {
  const matching = normalizeConnectedResult(
    "supabase",
    "partially-fixed",
    completedDetail("supabase", supabaseFindings("partially-fixed"), "partially-fixed"),
  );
  assert.equal(matching.outcome, "Inconclusive");
  assert.equal(matching.expectationMatched, true);
  assert.equal(matching.expectedFindingRuleIds.length, 3);
  assert.equal(matching.unmeasuredCaseIds.length, 3);
  assert.equal(matching.severityMismatches, 0);

  const missing = normalizeConnectedResult(
    "supabase",
    "vulnerable",
    completedDetail("supabase", supabaseFindings("vulnerable").slice(1), "vulnerable"),
  );
  assert.equal(missing.outcome, "Failed");
  assert.equal(missing.expectationMatched, false);

  const wrongSeverity = supabaseFindings("vulnerable");
  wrongSeverity[0] = { ...wrongSeverity[0], severity: "low" };
  const severityMismatch = normalizeConnectedResult(
    "supabase",
    "vulnerable",
    completedDetail("supabase", wrongSeverity, "vulnerable"),
  );
  assert.equal(severityMismatch.outcome, "Failed");
  assert.equal(severityMismatch.severityMismatches, 1);
});

test("canonical grouping distinguishes affected items from true duplicates and item loss", () => {
  const expected = supabaseFindings("vulnerable");
  const matching = normalizeConnectedResult(
    "supabase",
    "vulnerable",
    completedDetail("supabase", expected, "vulnerable"),
  );
  assert.equal(matching.findingCount, 9);
  assert.equal(matching.affectedItemCount, 6);
  assert.equal(matching.duplicateFindings, 0);
  assert.equal(matching.unmappedFindingCount, 0);
  assert.equal(matching.expectationMatched, true);
  assert.deepEqual(
    matching.findingGroups.find((group) => group.ruleId === "supabase.rls.disabled-exposed.v1"),
    {
      ruleId: "supabase.rls.disabled-exposed.v1",
      expectedSeverity: "critical",
      observedSeverities: ["critical"],
      expectedAffectedItems: ["authorizationDocuments", "policyWithoutRls", "rlsDisabled", "sensitiveProfiles"],
      observedAffectedItems: ["authorizationDocuments", "policyWithoutRls", "rlsDisabled", "sensitiveProfiles"],
      expectedAffectedItemCount: 4,
      observedAffectedItemCount: 4,
    },
  );

  const duplicated = normalizeConnectedResult(
    "supabase",
    "vulnerable",
    completedDetail("supabase", [...expected, { ...expected[0], fingerprint: "second-fingerprint" }], "vulnerable"),
  );
  assert.equal(duplicated.duplicateFindings, 1);
  assert.equal(duplicated.expectationMatched, false);
  assert.equal(duplicated.outcome, "Failed");

  const lost = normalizeConnectedResult(
    "supabase",
    "vulnerable",
    completedDetail("supabase", expected.slice(1), "vulnerable"),
  );
  assert.equal(lost.duplicateFindings, 0);
  assert.equal(lost.expectationMatched, false);
  assert.equal(lost.outcome, "Failed");
});

test("lifecycle validation fails score, resolution, reintroduction, and history regressions", () => {
  const states = STATE_ORDER.map((state) => normalizeConnectedResult(
    "supabase",
    state,
    completedDetail("supabase", supabaseFindings(state), state),
  ));
  for (const state of states) {
    state.unmeasuredCaseIds = [];
    state.unmeasuredRuleIds = [];
    state.measuredManifestCaseCount = state.manifestCaseCount;
  }
  const valid = evaluateLifecycle("supabase", states);
  assert.deepEqual(valid, {
    manifestCoverage: "Matched",
    measuredFindingTransitions: "Matched",
    scoreProgression: "Matched",
    measuredResolution: "Matched",
    measuredReintroduction: "Matched",
    history: "Matched",
    duplicateFree: true,
  });

  const repeatedBaseline = structuredClone(states);
  repeatedBaseline.find((item) => item.state === "vulnerable").evolution = {
    new: 0,
    stillOpen: 0,
    fixed: 0,
    reappeared: 9,
  };
  repeatedBaseline.find((item) => item.state === "partially-fixed").evolution = {
    new: 0,
    stillOpen: 0,
    fixed: 6,
    reappeared: 3,
  };
  assert.equal(evaluateLifecycle("supabase", repeatedBaseline).history, "Matched");

  const regressed = structuredClone(states);
  regressed.find((item) => item.state === "partially-fixed").score.score = 10;
  regressed.find((item) => item.state === "fixed").findingCount = 1;
  regressed.find((item) => item.state === "fixed").evolution.fixed = 0;
  regressed.find((item) => item.state === "reintroduced").findingCount = 8;
  regressed.find((item) => item.state === "reintroduced").evolution.reappeared = 0;
  const lifecycle = evaluateLifecycle("supabase", regressed);
  assert.equal(lifecycle.scoreProgression, "Mismatch");
  assert.equal(lifecycle.measuredResolution, "Mismatch");
  assert.equal(lifecycle.measuredReintroduction, "Mismatch");
  assert.equal(lifecycle.history, "Mismatch");
  assert.equal(summarizeOutcomes(regressed, { verified: true }, lifecycle).outcome, "Failed");
});

test("Vercel resolves its single finding at partial remediation and keeps fixed clean", () => {
  const states = STATE_ORDER.map((state) => {
    const findings = new Set(["vulnerable", "reintroduced"]).has(state)
      ? [{ ruleId: "vercel.git-fork-protection.disabled.v1", severity: "high" }]
      : [];
    const detail = completedDetail("vercel", findings, state);
    detail.assessment.securityScore.score = new Set(["vulnerable", "reintroduced"]).has(state) ? 80 : 100;
    detail.assessment.evolution = {
      vulnerable: { new: 1, stillOpen: 0, fixed: 0, reappeared: 0 },
      "partially-fixed": { new: 0, stillOpen: 0, fixed: 1, reappeared: 0 },
      fixed: { new: 0, stillOpen: 0, fixed: 0, reappeared: 0 },
      reintroduced: { new: 0, stillOpen: 0, fixed: 0, reappeared: 1 },
    }[state];
    return normalizeConnectedResult("vercel", state, detail);
  });

  assert.equal(states.every((state) => state.outcome === "Passed"), true);
  assert.deepEqual(evaluateLifecycle("vercel", states), {
    manifestCoverage: "Matched",
    measuredFindingTransitions: "Matched",
    scoreProgression: "Matched",
    measuredResolution: "Matched",
    measuredReintroduction: "Matched",
    history: "Inconclusive",
    duplicateFree: true,
  });
  assert.equal(summarizeOutcomes(states, { verified: true }, evaluateLifecycle("vercel", states)).outcome, "Inconclusive");
});

test("a protected checkpoint resumes a pending execution without duplicating it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "connected-checkpoint-test-"));
  try {
    const checkpointPath = join(directory, "checkpoint.json");
    const checkpoint = createCheckpointStore(checkpointPath);
    const events = [];
    const client = new MemoryClient();
    client.timeoutFirst = true;
    const first = await runConnectedServiceLifecycle({
      provider: "supabase",
      client,
      adapter: memoryAdapter(events),
      checkpointStore: checkpoint,
      expectedVersion: "v0.78.0",
      sourceCommit: COMMIT,
      polling: { maxPolls: 1, pollIntervalMs: 0, sleep: async () => {} },
    });
    assert.equal(first.summary.outcome, "Failed");
    assert.equal(client.runCalls, 1);
    assert.equal((await stat(checkpointPath)).mode & 0o777, 0o600);
    assert.match(await readFile(checkpointPath, "utf8"), new RegExp(ASSESSMENT_IDS[0], "u"));

    client.timeoutFirst = false;
    const renderedLocales = [];
    const second = await runConnectedServiceLifecycle({
      provider: "supabase",
      client,
      adapter: memoryAdapter(events),
      checkpointStore: checkpoint,
      expectedVersion: "v0.78.0",
      sourceCommit: COMMIT,
      polling: { maxPolls: 1, pollIntervalMs: 0, sleep: async () => {} },
      presentationProbe: async ({ locale }) => {
        renderedLocales.push(locale);
        return { locale, route: "execution-detail", rendered: true, navigable: true };
      },
    });
    assert.equal(second.summary.outcome, "Inconclusive", JSON.stringify({ states: second.states, lifecycle: second.lifecycle }));
    assert.equal(second.states.length, 4);
    assert.equal(client.runCalls, 4, "the resumed vulnerable execution was polled instead of duplicated");
    assert.equal(events.filter((item) => item === "cleanup").length, 2);
    assert.deepEqual(renderedLocales, ["pt-BR", "en-US"]);
    assert.deepEqual(second.lifecycle, {
      manifestCoverage: "Inconclusive",
      measuredFindingTransitions: "Matched",
      scoreProgression: "Matched",
      measuredResolution: "Matched",
      measuredReintroduction: "Matched",
      history: "Matched",
      duplicateFree: true,
    });
    assert.deepEqual(evaluateLifecycle("supabase", second.states), second.lifecycle);

    assert.doesNotMatch(JSON.stringify(second), new RegExp(ASSESSMENT_IDS[0], "u"));
    assert.doesNotMatch(JSON.stringify(second), new RegExp(RESOURCE_ID, "u"));
    assert.deepEqual(verifyConnectedServiceLifecycleReport(second), {
      provider: "supabase",
      outcome: "Inconclusive",
      states: 4,
      clean: false,
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("unsafe checkpoint paths and permissive checkpoint modes fail closed", async () => {
  assert.throws(
    () => createCheckpointStore(join(process.cwd(), "checkpoint.json"), process.cwd()),
    (error) => error.code === "unsafe-checkpoint",
  );
  const directory = await mkdtemp(join(tmpdir(), "connected-mode-test-"));
  try {
    const path = join(directory, "checkpoint.json");
    const store = createCheckpointStore(path);
    await store.save({ version: 1, providers: {} });
    await chmod(path, 0o644);
    await assert.rejects(store.load(), (error) => error.code === "unsafe-checkpoint");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a populated checkpoint cannot be relabeled as a different deployment baseline", async () => {
  const directory = await mkdtemp(join(tmpdir(), "connected-baseline-test-"));
  try {
    const path = join(directory, "checkpoint.json");
    const store = createCheckpointStore(path);
    await store.save({
      version: 1,
      providers: {
        supabase: {
          results: { vulnerable: { outcome: "Failed" } },
          assessments: {},
          presentation: [],
          pending: null,
        },
      },
    });
    const legacy = await runConnectedServiceLifecycle({
      provider: "supabase",
      client: new MemoryClient(),
      adapter: memoryAdapter([]),
      checkpointStore: store,
      expectedVersion: "v0.79.0",
      sourceCommit: COMMIT,
    });
    assert.equal(legacy.summary.outcome, "Failed");
    assert.equal(legacy.states[0].failureCode, "checkpoint-baseline-missing");

    await store.save({
      version: 1,
      providers: {
        supabase: {
          baseline: { expectedVersion: "v0.78.0", sourceCommit: COMMIT },
          results: {},
          assessments: {},
          presentation: [],
          pending: null,
        },
      },
    });
    const mismatch = await runConnectedServiceLifecycle({
      provider: "supabase",
      client: new MemoryClient(),
      adapter: memoryAdapter([]),
      checkpointStore: store,
      expectedVersion: "v0.79.0",
      sourceCommit: COMMIT,
    });
    assert.equal(mismatch.summary.outcome, "Failed");
    assert.equal(mismatch.states[0].failureCode, "checkpoint-baseline-mismatch");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("summary keeps failed cleanup and partial execution non-clean", () => {
  assert.deepEqual(summarizeOutcomes([{ outcome: "Passed" }], { verified: false }), {
    outcome: "Failed",
    clean: false,
    counts: { Passed: 1, Failed: 0, BlockedByConsent: 0, Inconclusive: 0 },
  });
  assert.equal(summarizeOutcomes([{ outcome: "Inconclusive" }], { verified: true }).clean, false);
});
