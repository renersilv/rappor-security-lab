import assert from "node:assert/strict";
import test from "node:test";

import { runPublicBlackBox, toBlackBoxMarkdown } from "../src/run-public-black-box.mjs";
import { verifyPublicBlackBoxReport } from "../src/verify-public-black-box-report.mjs";

const BASE_URL = "https://linux-ai2.taile60a95.ts.net:8443";
const TARGET_PREFIX = "https://rappor-lab-";
const STATES = ["vulnerable", "partially-fixed", "fixed", "reintroduced"];

const signalDefinitions = [
  ["technology.framework.nextjs.v1", "Next.js"],
  ["technology.provider.vercel.v1", "Vercel"],
  ["technology.platform.lovable.v1", "Lovable"],
  ["technology.client.supabase.v1", "Supabase client"],
];

const findingDefinitions = {
  header: ["http.header.csp.missing.v1", "Low"],
  cookie: ["cookie.secure.missing.v1", "Medium"],
  form: ["html.form.sensitive-get.v1", "Medium"],
  mixed: ["html.mixed-content.passive.v1", "Medium"],
  secret: ["secret.rappor-lab.elevated.v1", "High"],
};

const findingsByState = {
  vulnerable: ["header", "cookie", "form", "mixed", "secret"],
  "partially-fixed": ["form", "mixed", "secret"],
  fixed: [],
  reintroduced: ["header", "cookie", "form", "mixed", "secret"],
};

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function resultFor(state, coverageStatus, failed = false) {
  if (failed) {
    return {
      contractVersion: "v1",
      status: "Failed",
      coverageStatus: "Failed",
      failureReason: "must-not-retain-failure-reason",
      accessToken: "must-not-retain-status-token",
      scanId: 999,
    };
  }
  const findings = findingsByState[state].map((key) => {
    const [ruleId, severity] = findingDefinitions[key];
    return {
      ruleId,
      title: `Synthetic ${key} title`,
      category: "Browser Security",
      severity,
      confidence: "Certain",
      maskedEvidence: "must-not-retain-masked-evidence",
      remediation: "must-not-retain-remediation",
      presentationSource: "RapporCatalog",
    };
  });
  const signals = signalDefinitions.flatMap(([signalId, technology]) => [
    {
      signalId,
      technology,
      category: "Technology",
      confidence: "Certain",
      source: `document:${TARGET_PREFIX}${state}.vercel.app/`,
      evidence: "must-not-retain-signal-evidence",
    },
    ...(signalId.includes("vercel") ? [{
      signalId,
      technology,
      category: "Technology",
      confidence: "Certain",
      source: `script:${TARGET_PREFIX}${state}.vercel.app/example.js`,
      evidence: "must-not-retain-duplicate-signal-evidence",
    }] : []),
  ]);
  return {
    contractVersion: "v1",
    status: "Completed",
    coverageStatus,
    retryAfterSeconds: null,
    failureReason: null,
    findings,
    signals,
    accessToken: "must-not-retain-status-token",
    scanId: 999,
  };
}

function createMockFetch({ partialState, failedState } = {}) {
  const requests = [];
  const fetchImpl = async (input, options = {}) => {
    const url = new URL(input);
    const method = options.method ?? "GET";
    requests.push({ url: url.href, method, body: options.body ?? null, headers: options.headers ?? {} });

    if (url.href === `${BASE_URL}/` && method === "GET") {
      return new Response('<footer>v0.10.0</footer><script src="/_next/static/client.js"></script>', {
        headers: { "content-type": "text/html" },
      });
    }
    if (url.href === `${BASE_URL}/_next/static/client.js`) {
      return new Response('const path="/api/public/v1/scans"; const terms="2026-08-20.v1";', {
        headers: { "content-type": "application/javascript" },
      });
    }
    if (url.href === `${BASE_URL}/api/public/v1/scans` && method === "GET") {
      return json({ code: "method-not-allowed" }, 405, { allow: "POST" });
    }
    if (url.href === `${BASE_URL}/api/public/v1/scans` && method === "POST") {
      const body = JSON.parse(options.body);
      const state = STATES.find((candidate) => body.url === `${TARGET_PREFIX}${candidate}.vercel.app`);
      assert.ok(state, "create request must use an approved controlled target");
      assert.deepEqual(body, {
        url: `${TARGET_PREFIX}${state}.vercel.app`,
        acceptedResponsibleUseTerms: true,
        responsibleUseTermsVersion: "2026-08-20.v1",
      });
      return json({
        contractVersion: "v1",
        scanId: STATES.indexOf(state) + 1,
        accessToken: `must-not-retain-create-token-${state}`,
        statusUrl: `/api/public/v1/scans/${state}`,
        status: "Queued",
      });
    }
    const statusState = STATES.find((candidate) => url.href === `${BASE_URL}/api/public/v1/scans/${candidate}`);
    if (statusState) {
      assert.match(options.headers["X-Public-Scan-Token"], /^must-not-retain-create-token-/);
      return json(resultFor(statusState, partialState === statusState ? "Partial" : "Complete", failedState === statusState));
    }
    const targetState = STATES.find((candidate) => url.href === `${TARGET_PREFIX}${candidate}.vercel.app/`);
    if (targetState) {
      return new Response(`<main data-lab-state="${targetState}"></main>`, {
        headers: { "content-type": "text/html" },
      });
    }
    throw new Error(`unexpected request: ${method} ${url.href}`);
  };
  return { fetchImpl, requests };
}

test("executes the selected public contract and separates comparison dimensions", async () => {
  const { fetchImpl, requests } = createMockFetch();
  const report = await runPublicBlackBox({
    fetchImpl,
    now: () => new Date("2026-09-08T19:00:00.000Z"),
    sleep: async () => {},
  });

  assert.equal(report.application.observedVisibleVersion, "v0.10.0");
  assert.equal(report.application.visibleVersionMatches, false);
  assert.equal(report.application.clientContractExposed, true);
  assert.equal(report.summary.runStatus, "completed");
  assert.equal(report.summary.verdict, "blocked");
  assert.equal(report.summary.clean, false);
  assert.deepEqual(report.summary.counts, {
    "true-positive": 29,
    "false-positive": 0,
    "true-negative": 11,
    "false-negative": 0,
    inconclusive: 0,
  });
  assert.equal(report.dimensions.detection.status, "passed");
  assert.equal(report.dimensions.normalization.status, "passed");
  assert.equal(report.dimensions.grouping.status, "not-exposed");
  assert.equal(report.dimensions.score.status, "not-exposed");
  assert.equal(report.dimensions.lifecycle.status, "passed");
  assert.equal(report.dimensions.presentation.status, "passed");
  assert.equal(report.scans.every((scan) => scan.uniqueSignalCount === 4), true);
  assert.equal(requests.filter((request) => request.method === "POST").length, 4);

  const serialized = `${JSON.stringify(report)}\n${toBlackBoxMarkdown(report)}`;
  for (const forbidden of [
    "must-not-retain-masked-evidence",
    "must-not-retain-remediation",
    "must-not-retain-signal-evidence",
    "must-not-retain-create-token",
    "must-not-retain-status-token",
    '"scanId"',
    '"statusUrl"',
  ]) {
    assert.equal(serialized.includes(forbidden), false, `report retained ${forbidden}`);
  }
});

test("partial coverage makes the controlled result non-clean and inconclusive", async () => {
  const { fetchImpl } = createMockFetch({ partialState: "vulnerable" });
  const report = await runPublicBlackBox({
    fetchImpl,
    now: () => new Date("2026-09-08T19:00:00.000Z"),
    sleep: async () => {},
  });

  assert.equal(report.summary.runStatus, "partial");
  assert.equal(report.summary.clean, false);
  assert.equal(report.summary.verdict, "blocked");
  assert.equal(report.summary.counts.inconclusive, 10);
  assert.equal(report.dimensions.detection.status, "inconclusive");
  assert.equal(report.dimensions.lifecycle.status, "inconclusive");
  assert.ok(report.discrepancies.some((item) => item.id === "coverage-vulnerable"));
  assert.ok(report.discrepancies.some((item) => item.id === "lifecycle-not-proven"));
});

test("failed scans remain bounded, non-clean and sanitized", async () => {
  const { fetchImpl } = createMockFetch({ failedState: "fixed" });
  const report = await runPublicBlackBox({
    fetchImpl,
    now: () => new Date("2026-09-08T19:00:00.000Z"),
    sleep: async () => {},
  });

  const failed = report.scans.find((scan) => scan.state === "fixed");
  assert.equal(report.summary.runStatus, "failed");
  assert.equal(report.summary.clean, false);
  assert.equal(failed.runStatus, "failed");
  assert.equal(failed.observations.every((item) => item.classification === "inconclusive"), true);
  assert.equal(JSON.stringify(report).includes("must-not-retain-failure-reason"), false);
});

test("checked-in controlled report is complete, reproducible and sanitized", async () => {
  assert.deepEqual(await verifyPublicBlackBoxReport(), {
    recordPath: "observations/public-controlled/2026-09-08T181522Z-v0.10.0.json",
    status: "partial",
    verdict: "blocked",
    scans: 4,
    cases: 40,
    discrepancies: 13,
  });
});
