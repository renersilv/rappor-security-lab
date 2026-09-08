#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const STATES = ["vulnerable", "partially-fixed", "fixed", "reintroduced"];
const TERMINAL_STATUSES = new Set(["completed", "failed"]);
const PRODUCT_STATUSES = new Map([
  ["completed", "completed"],
  ["failed", "failed"],
]);
const COVERAGE_STATUSES = new Map([
  ["complete", "completed"],
  ["partial", "partial"],
  ["failed", "failed"],
]);
const SEVERITIES = new Map([
  ["info", "info"],
  ["informational", "info"],
  ["low", "low"],
  ["medium", "medium"],
  ["high", "high"],
  ["critical", "critical"],
]);
const CONFIDENCES = new Map([
  ["tentative", "low"],
  ["low", "low"],
  ["firm", "moderate"],
  ["moderate", "moderate"],
  ["certain", "high"],
  ["high", "high"],
]);

function assertObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function assertString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function normalizedWord(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function normalizeSeverity(value) {
  return SEVERITIES.get(normalizedWord(value)) ?? null;
}

function normalizeConfidence(value) {
  return CONFIDENCES.get(normalizedWord(value)) ?? null;
}

function safeCategory(value) {
  return typeof value === "string"
    ? value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")
    : "unknown";
}

function sameOriginPath(baseUrl, path) {
  const base = new URL(baseUrl);
  const resolved = new URL(path, base);
  if (resolved.origin !== base.origin) throw new Error("public status URL changed origin");
  return resolved;
}

function withTimeout(milliseconds) {
  return AbortSignal.timeout(milliseconds);
}

async function responseText(response, label) {
  if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
  return response.text();
}

async function responseJson(response, label) {
  if (!response.ok) throw new Error(`${label} returned HTTP ${response.status}`);
  const value = await response.json();
  assertObject(value, label);
  return value;
}

function scriptUrls(document, baseUrl) {
  const urls = [];
  const expression = /<script\b[^>]*\bsrc=(?:"([^"]+)"|'([^']+)')[^>]*>/gi;
  for (const match of document.matchAll(expression)) {
    const resolved = new URL(match[1] ?? match[2], baseUrl);
    if (resolved.origin === new URL(baseUrl).origin && !urls.includes(resolved.href)) {
      urls.push(resolved.href);
    }
  }
  return urls.slice(0, 20);
}

export async function probePublicContract(profile, fetchImpl = fetch) {
  const baseUrl = new URL(profile.application.publicFlow, profile.application.baseUrl).href;
  const root = await fetchImpl(baseUrl, {
    headers: { Accept: "text/html" },
    signal: withTimeout(profile.execution.requestTimeoutMs),
  });
  const document = await responseText(root, "public flow");
  const versions = [...new Set(document.match(/v\d+\.\d+\.\d+/g) ?? [])];
  if (versions.length !== 1) throw new Error("public flow must expose exactly one visible semantic version");

  const contractUrl = sameOriginPath(profile.application.baseUrl, profile.application.createPath);
  const methodProbe = await fetchImpl(contractUrl, {
    headers: { Accept: "application/json" },
    signal: withTimeout(profile.execution.requestTimeoutMs),
  });
  const allowedMethods = (methodProbe.headers.get("allow") ?? "")
    .split(",")
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
  if (methodProbe.status !== 405 || !allowedMethods.includes("POST")) {
    throw new Error("public scan create contract is not exposed as POST");
  }

  const assets = [];
  for (const url of scriptUrls(document, baseUrl)) {
    const response = await fetchImpl(url, {
      headers: { Accept: "application/javascript" },
      signal: withTimeout(profile.execution.requestTimeoutMs),
    });
    assets.push(await responseText(response, "public flow script"));
  }
  const clientContract = assets.join("\n");
  if (!clientContract.includes(profile.application.createPath)) {
    throw new Error("public client does not expose the selected create path");
  }
  if (!clientContract.includes(profile.application.responsibleUseTermsVersion)) {
    throw new Error("public client does not expose the selected responsible-use terms version");
  }

  return {
    selectedVisibleVersion: profile.application.selectedVisibleVersion,
    observedVisibleVersion: versions[0],
    visibleVersionMatches: versions[0] === profile.application.selectedVisibleVersion,
    createMethod: "POST",
    createPath: profile.application.createPath,
    contractVersion: profile.application.contractVersion,
    responsibleUseTermsVersion: profile.application.responsibleUseTermsVersion,
    clientContractExposed: true,
  };
}

async function probeTarget(state, targetUrl, profile, fetchImpl) {
  const response = await fetchImpl(`${targetUrl}/`, {
    headers: { Accept: "text/html" },
    signal: withTimeout(profile.execution.requestTimeoutMs),
  });
  const document = await responseText(response, `${state} target`);
  const marker = document.match(/\bdata-lab-state=(?:"([^"]+)"|'([^']+)')/i);
  const observedState = marker?.[1] ?? marker?.[2] ?? null;
  if (observedState !== state) throw new Error(`${state} target returned state ${observedState ?? "without-marker"}`);
  return { available: true, observedState };
}

async function createScan(targetUrl, profile, fetchImpl) {
  const response = await fetchImpl(
    sameOriginPath(profile.application.baseUrl, profile.application.createPath),
    {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        url: targetUrl,
        acceptedResponsibleUseTerms: true,
        responsibleUseTermsVersion: profile.application.responsibleUseTermsVersion,
      }),
      signal: withTimeout(profile.execution.requestTimeoutMs),
    },
  );
  const created = await responseJson(response, "public scan create");
  if (!Number.isSafeInteger(created.scanId) || created.scanId <= 0) {
    throw new Error("public scan create returned an invalid scan identifier");
  }
  assertString(created.accessToken, "public scan access token");
  assertString(created.statusUrl, "public scan status URL");
  if (created.contractVersion !== profile.application.contractVersion) {
    throw new Error(`public scan create returned contract ${created.contractVersion ?? "unknown"}`);
  }
  return created;
}

async function pollScan(created, profile, fetchImpl, sleep, progress) {
  const statusUrl = sameOriginPath(profile.application.baseUrl, created.statusUrl);
  if (!statusUrl.pathname.startsWith(`${profile.application.createPath}/`)) {
    throw new Error("public scan status URL is outside the selected contract");
  }
  for (let poll = 1; poll <= profile.execution.maxPolls; poll += 1) {
    const response = await fetchImpl(statusUrl, {
      headers: { Accept: "application/json", "X-Public-Scan-Token": created.accessToken },
      cache: "no-store",
      signal: withTimeout(profile.execution.requestTimeoutMs),
    });
    const result = await responseJson(response, "public scan status");
    if (result.contractVersion !== profile.application.contractVersion) {
      throw new Error(`public scan status returned contract ${result.contractVersion ?? "unknown"}`);
    }
    const productStatus = normalizedWord(result.status);
    progress?.({ poll, status: productStatus });
    if (TERMINAL_STATUSES.has(productStatus)) return result;
    const retryMilliseconds = Number.isInteger(result.retryAfterSeconds)
      ? Math.max(result.retryAfterSeconds * 1000, profile.execution.pollIntervalMs)
      : profile.execution.pollIntervalMs;
    await sleep(retryMilliseconds);
  }
  throw new Error("public scan did not reach a terminal state within the bounded poll limit");
}

function itemIdentifier(item, channel) {
  return channel === "signal" ? item.signalId : item.ruleId;
}

function compileMappings(profile) {
  return new Map(profile.mappings.map((mapping) => [mapping.ruleFamily, {
    ...mapping,
    expressions: mapping.identifierPatterns.map((pattern) => new RegExp(pattern, "i")),
  }]));
}

function matchingItems(result, mapping) {
  const items = mapping.channel === "signal" ? result.signals : result.findings;
  return items.filter((item) => {
    const identifier = itemIdentifier(item, mapping.channel);
    return typeof identifier === "string" && mapping.expressions.some((expression) => expression.test(identifier));
  });
}

function classify(expectedPresence, observedPresence, runStatus) {
  if (runStatus !== "completed") return "inconclusive";
  if (expectedPresence) return observedPresence ? "true-positive" : "false-negative";
  return observedPresence ? "false-positive" : "true-negative";
}

function runStatus(result) {
  const product = PRODUCT_STATUSES.get(normalizedWord(result.status)) ?? "failed";
  if (product === "failed") return "failed";
  return COVERAGE_STATUSES.get(normalizedWord(result.coverageStatus)) ?? "partial";
}

function presentationSummary(items, channel) {
  if (items.length === 0) {
    return { available: false, complete: false, itemCount: 0, sources: [] };
  }
  const required = channel === "signal"
    ? ["technology", "category", "confidence", "source", "evidence"]
    : ["title", "category", "confidence", "maskedEvidence", "remediation", "presentationSource"];
  const complete = items.every((item) => required.every((field) => typeof item[field] === "string" && item[field].length > 0));
  const sources = channel === "signal"
    ? items.map((item) => String(item.source).split(":", 1)[0])
    : items.map((item) => item.presentationSource);
  return {
    available: true,
    complete,
    itemCount: items.length,
    sources: [...new Set(sources)].sort(),
  };
}

function caseObservation(benchmarkCase, result, mapping, status) {
  const items = matchingItems(result, mapping);
  const observedPresence = items.length > 0;
  const observedSeverities = mapping.channel === "signal"
    ? (observedPresence ? ["info"] : [])
    : [...new Set(items.map((item) => normalizeSeverity(item.severity)).filter(Boolean))].sort();
  let normalization = "not-applicable";
  if (benchmarkCase.expectedSeverity !== null && observedPresence) {
    normalization = observedSeverities.includes(benchmarkCase.expectedSeverity) ? "matched" : "mismatch";
  } else if (benchmarkCase.expectedSeverity !== null) {
    normalization = "not-observed";
  } else if (observedPresence) {
    normalization = "unexpected-observation";
  }
  const presentation = presentationSummary(items, mapping.channel);
  return {
    caseId: benchmarkCase.id,
    ruleFamily: benchmarkCase.ruleFamily,
    channel: mapping.channel,
    expectedPresence: benchmarkCase.expectedPresence,
    observedPresence,
    classification: classify(benchmarkCase.expectedPresence, observedPresence, status),
    expectedSeverity: benchmarkCase.expectedSeverity,
    observedSeverities,
    normalization,
    expectedGroupingKey: benchmarkCase.groupingKey,
    observedGroupingKey: null,
    grouping: benchmarkCase.groupingKey !== null && observedPresence ? "not-exposed" : "not-applicable",
    presentation,
  };
}

function unmappedProductItems(result, mappings) {
  const output = [];
  for (const channel of ["finding", "signal"]) {
    const items = channel === "signal" ? result.signals : result.findings;
    for (const item of items) {
      const identifier = itemIdentifier(item, channel);
      const mapped = [...mappings.values()].some((mapping) =>
        mapping.channel === channel && mapping.expressions.some((expression) => expression.test(identifier)),
      );
      if (!mapped && !output.some((entry) => entry.channel === channel && entry.identifier === identifier)) {
        output.push({
          channel,
          identifier,
          severity: channel === "finding" ? normalizeSeverity(item.severity) : "info",
          confidence: normalizeConfidence(item.confidence),
          category: safeCategory(item.category),
        });
      }
    }
  }
  return output.sort((left, right) => `${left.channel}:${left.identifier}`.localeCompare(`${right.channel}:${right.identifier}`));
}

function sanitizeScan(state, target, targetCases, result, mappings, observedAt) {
  assertObject(result, `${state} result`);
  const productStatus = PRODUCT_STATUSES.get(normalizedWord(result.status)) ?? "failed";
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const signals = Array.isArray(result.signals) ? result.signals : [];
  if (productStatus === "completed" && (!Array.isArray(result.findings) || !Array.isArray(result.signals))) {
    throw new Error(`${state} result must contain findings and signals arrays`);
  }
  const sanitizedResult = { ...result, findings, signals };
  const status = runStatus(sanitizedResult);
  const observations = targetCases.map((benchmarkCase) => {
    const mapping = mappings.get(benchmarkCase.ruleFamily);
    if (!mapping) throw new Error(`no product mapping for ${benchmarkCase.ruleFamily}`);
    return caseObservation(benchmarkCase, sanitizedResult, mapping, status);
  });
  const score = Number.isFinite(sanitizedResult.score)
    ? { exposed: true, value: sanitizedResult.score, status: "observed" }
    : { exposed: false, value: null, status: "not-exposed" };
  return {
    state,
    targetId: target.id,
    targetRevision: target.revision,
    url: target.url,
    observedAt,
    productStatus,
    coverageStatus: normalizedWord(sanitizedResult.coverageStatus) || "unknown",
    runStatus: status,
    findingCount: findings.length,
    signalCount: signals.length,
    uniqueSignalCount: new Set(signals.map((item) => item.signalId)).size,
    score,
    observations,
    unmappedProductItems: unmappedProductItems(sanitizedResult, mappings),
  };
}

function countClassifications(scans) {
  const names = ["true-positive", "false-positive", "true-negative", "false-negative", "inconclusive"];
  return Object.fromEntries(names.map((name) => [
    name,
    scans.flatMap((scan) => scan.observations).filter((item) => item.classification === name).length,
  ]));
}

function aggregateStatus(scans) {
  if (scans.some((scan) => scan.runStatus === "failed")) return "failed";
  if (scans.some((scan) => scan.runStatus === "partial")) return "partial";
  return "completed";
}

function buildLifecycle(manifest, scans) {
  const ruleFamilies = [...new Set(manifest.cases.map((item) => item.ruleFamily))];
  return ruleFamilies.map((ruleFamily) => {
    const states = STATES.map((state) => {
      const expected = manifest.cases.find((item) => item.state === state && item.ruleFamily === ruleFamily);
      const scan = scans.find((item) => item.state === state);
      const observed = scan.observations.find((item) => item.ruleFamily === ruleFamily);
      return {
        state,
        expectedPresence: expected.expectedPresence,
        observedPresence: observed.observedPresence,
        classification: observed.classification,
      };
    });
    const mismatch = states.some((item) => ["false-positive", "false-negative"].includes(item.classification));
    const inconclusive = states.some((item) => item.classification === "inconclusive");
    return {
      ruleFamily,
      status: mismatch ? "mismatch" : inconclusive ? "inconclusive" : "matched",
      states,
    };
  });
}

function discrepancy(id, dimension, caseIds, states, expected, observed, evidence) {
  return {
    id,
    dimension,
    caseIds,
    states,
    expected,
    observed,
    reproductionSteps: [
      "Use the selected public POST contract with the exact controlled target URL and accepted responsible-use terms version.",
      "Poll only the returned same-origin status path with its ephemeral token until a terminal status.",
      "Discard the token and compare sanitized rule and signal identifiers with the pinned manifest and mapping profile.",
    ],
    sanitizedEvidence: evidence,
  };
}

function buildDiscrepancies(contract, scans, lifecycle) {
  const output = [];
  if (!contract.visibleVersionMatches) {
    output.push(discrepancy(
      "deployment-visible-version",
      "presentation",
      [],
      STATES,
      `Visible deployment version ${contract.selectedVisibleVersion}.`,
      `Visible deployment version ${contract.observedVisibleVersion}.`,
      "Only the public footer version marker was retained.",
    ));
  }
  for (const scan of scans) {
    if (scan.runStatus !== "completed") {
      output.push(discrepancy(
        `coverage-${scan.state}`,
        "detection",
        scan.observations.map((item) => item.caseId),
        [scan.state],
        "Complete passive coverage is required before absence can be classified.",
        `The public contract reported ${scan.coverageStatus} coverage and the laboratory mapped the run to ${scan.runStatus}.`,
        `Only terminal and coverage states plus aggregate counts were retained for ${scan.targetId}.`,
      ));
    }
  }
  const normalizationMismatches = scans.flatMap((scan) =>
    scan.observations.filter((item) => item.normalization === "mismatch").map((item) => ({ scan, item })),
  );
  for (const { scan, item } of normalizationMismatches) {
    output.push(discrepancy(
      `severity-${item.caseId}`,
      "normalization",
      [item.caseId],
      [scan.state],
      `Normalized severity ${item.expectedSeverity}.`,
      `Normalized public result severity ${item.observedSeverities.join(", ") || "not exposed"}.`,
      "The rule identifier and normalized severity were retained; title, remediation and evidence text were discarded.",
    ));
  }
  const classificationMismatches = scans.flatMap((scan) =>
    scan.observations.filter((item) => ["false-positive", "false-negative"].includes(item.classification)).map((item) => ({ scan, item })),
  );
  for (const { scan, item } of classificationMismatches) {
    output.push(discrepancy(
      `classification-${item.caseId}`,
      "detection",
      [item.caseId],
      [scan.state],
      `Presence expected: ${item.expectedPresence}.`,
      `Presence observed: ${item.observedPresence}; classification: ${item.classification}.`,
      "Only the mapped rule or signal identifier was used; response evidence was discarded.",
    ));
  }
  const lifecycleGaps = lifecycle.filter((item) => item.status !== "matched");
  if (lifecycleGaps.length > 0) {
    output.push(discrepancy(
      "lifecycle-not-proven",
      "lifecycle",
      scans.flatMap((scan) => scan.observations.filter((item) => lifecycleGaps.some((gap) => gap.ruleFamily === item.ruleFamily)).map((item) => item.caseId)),
      STATES,
      "Vulnerable, partially-fixed, fixed and reintroduced states must all have conclusive comparable coverage.",
      `${lifecycleGaps.length} rule-family lifecycle sequence(s) are not proven by conclusive coverage.`,
      "The report retains only expected and observed booleans plus classifications for each pinned state.",
    ));
  }
  const groupedCases = scans.flatMap((scan) => scan.observations.filter((item) => item.grouping === "not-exposed"));
  if (groupedCases.length > 0) {
    output.push(discrepancy(
      "grouping-not-exposed",
      "grouping",
      [...new Set(groupedCases.map((item) => item.caseId))],
      [...new Set(scans.filter((scan) => scan.observations.some((item) => item.grouping === "not-exposed")).map((scan) => scan.state))],
      "The manifest declares stable grouping keys for detected cases.",
      "The selected public v1 response exposes no grouping key.",
      "No product grouping identifier was inferred or retained.",
    ));
  }
  if (scans.some((scan) => !scan.score.exposed)) {
    output.push(discrepancy(
      "score-not-exposed",
      "score",
      [],
      scans.filter((scan) => !scan.score.exposed).map((scan) => scan.state),
      "Score behavior must be directly observable to support black-box comparison.",
      "The selected public v1 response exposes no score field.",
      "No score was inferred from severity counts.",
    ));
  }
  return output;
}

function buildDimensions(scans, counts, lifecycle) {
  const normalizations = scans.flatMap((scan) => scan.observations);
  const presentationItems = normalizations.filter((item) => item.presentation.available);
  const incomplete = scans.some((scan) => scan.runStatus !== "completed");
  return {
    detection: {
      status: counts["false-positive"] + counts["false-negative"] > 0
        ? "mismatch"
        : counts.inconclusive > 0 ? "inconclusive" : "passed",
      counts,
    },
    normalization: {
      status: normalizations.some((item) => item.normalization === "mismatch")
        ? "mismatch"
        : incomplete ? "inconclusive" : "passed",
      evaluated: normalizations.filter((item) => ["matched", "mismatch"].includes(item.normalization)).length,
      mismatches: normalizations.filter((item) => item.normalization === "mismatch").length,
    },
    grouping: {
      status: normalizations.some((item) => item.grouping === "not-exposed")
        ? "not-exposed"
        : incomplete ? "inconclusive" : "passed",
      expected: normalizations.filter((item) => item.expectedGroupingKey !== null && item.observedPresence).length,
      exposed: normalizations.filter((item) => item.observedGroupingKey !== null).length,
    },
    score: {
      status: scans.every((scan) => scan.score.exposed) ? "passed" : "not-exposed",
      exposed: scans.filter((scan) => scan.score.exposed).length,
      total: scans.length,
    },
    lifecycle: {
      status: lifecycle.some((item) => item.status === "mismatch")
        ? "mismatch"
        : lifecycle.some((item) => item.status === "inconclusive") ? "inconclusive" : "passed",
      matched: lifecycle.filter((item) => item.status === "matched").length,
      mismatches: lifecycle.filter((item) => item.status === "mismatch").length,
      inconclusive: lifecycle.filter((item) => item.status === "inconclusive").length,
    },
    presentation: {
      status: presentationItems.length === 0 && incomplete
        ? "inconclusive"
        : presentationItems.every((item) => item.presentation.complete) ? "passed" : "mismatch",
      available: presentationItems.length,
      complete: presentationItems.filter((item) => item.presentation.complete).length,
    },
  };
}

export function toBlackBoxMarkdown(report) {
  const lines = [
    `# Controlled public black-box comparison — ${report.application.observedVisibleVersion}`,
    "",
    `- Recorded at: \`${report.recordedAt}\``,
    `- Laboratory version: \`${report.laboratory.version}\``,
    `- Benchmark version: \`${report.benchmarkVersion}\``,
    `- Selected visible version: \`${report.application.selectedVisibleVersion}\``,
    `- Observed visible version: \`${report.application.observedVisibleVersion}\``,
    `- Public contract: \`${report.application.contractVersion}\` at \`${report.application.createPath}\``,
    `- Overall status: **${report.summary.runStatus}**`,
    `- Verdict: **${report.summary.verdict}**`,
    `- Clean: **${report.summary.clean ? "yes" : "no"}**`,
    "",
    "## Separate evaluation dimensions",
    "",
    "| Dimension | Status | Sanitized result |",
    "| --- | --- | --- |",
    `| Detection | ${report.dimensions.detection.status} | TP ${report.summary.counts["true-positive"]}; FP ${report.summary.counts["false-positive"]}; TN ${report.summary.counts["true-negative"]}; FN ${report.summary.counts["false-negative"]}; inconclusive ${report.summary.counts.inconclusive} |`,
    `| Normalization | ${report.dimensions.normalization.status} | ${report.dimensions.normalization.mismatches} severity mismatch(es) across ${report.dimensions.normalization.evaluated} evaluated observations |`,
    `| Grouping | ${report.dimensions.grouping.status} | ${report.dimensions.grouping.exposed}/${report.dimensions.grouping.expected} expected grouping keys exposed |`,
    `| Score | ${report.dimensions.score.status} | ${report.dimensions.score.exposed}/${report.dimensions.score.total} scans exposed a score |`,
    `| Lifecycle | ${report.dimensions.lifecycle.status} | ${report.dimensions.lifecycle.matched} matched; ${report.dimensions.lifecycle.mismatches} mismatch; ${report.dimensions.lifecycle.inconclusive} inconclusive |`,
    `| Presentation | ${report.dimensions.presentation.status} | ${report.dimensions.presentation.complete}/${report.dimensions.presentation.available} returned mapped items had complete presentation metadata |`,
    "",
    "## Controlled lifecycle scans",
    "",
    "| State | Target revision | Product / coverage | Findings | Signals | Classification counts |",
    "| --- | --- | --- | ---: | ---: | --- |",
  ];
  for (const scan of report.scans) {
    const counts = Object.fromEntries(["true-positive", "false-positive", "true-negative", "false-negative", "inconclusive"].map((name) => [
      name,
      scan.observations.filter((item) => item.classification === name).length,
    ]));
    lines.push(`| ${scan.state} | \`${scan.targetRevision}\` | ${scan.productStatus} / ${scan.coverageStatus} | ${scan.findingCount} | ${scan.signalCount} (${scan.uniqueSignalCount} unique) | TP ${counts["true-positive"]}; FP ${counts["false-positive"]}; TN ${counts["true-negative"]}; FN ${counts["false-negative"]}; inconclusive ${counts.inconclusive} |`);
  }
  lines.push("", "## Reproducible discrepancies", "");
  for (const item of report.discrepancies) {
    lines.push(
      `### ${item.id}`,
      "",
      `- Dimension: \`${item.dimension}\``,
      `- Expected: ${item.expected}`,
      `- Observed: ${item.observed}`,
      `- Sanitized evidence: ${item.sanitizedEvidence}`,
      "- Bounded reproduction:",
      ...item.reproductionSteps.map((step, index) => `  ${index + 1}. ${step}`),
      "",
    );
  }
  lines.push(
    "Raw response bodies, masked evidence text, remediation text, ephemeral access tokens, status URLs and internal scan identifiers were discarded. Unmapped product items are retained only by public rule or signal identifier and normalized metadata; they are not classified without independent ground truth.",
    "",
  );
  return lines.join("\n");
}

export async function runPublicBlackBox({
  repositoryRoot = REPOSITORY_ROOT,
  fetchImpl = fetch,
  now = () => new Date(),
  sleep = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)),
  progress,
} = {}) {
  const manifestPath = resolve(repositoryRoot, "manifests/public-vibe-coding.json");
  const profilePath = resolve(repositoryRoot, "scanner-profiles/rappor-public-black-box.json");
  const packagePath = resolve(repositoryRoot, "package.json");
  const [manifestContent, profileContent, packageContent] = await Promise.all([
    readFile(manifestPath, "utf8"),
    readFile(profilePath, "utf8"),
    readFile(packagePath, "utf8"),
  ]);
  const manifest = JSON.parse(manifestContent);
  const profile = JSON.parse(profileContent);
  const packageConfiguration = JSON.parse(packageContent);
  if (Object.keys(profile.targets).length !== profile.execution.maxTargets || STATES.length !== profile.execution.maxTargets) {
    throw new Error("black-box profile must contain exactly the four approved lifecycle targets");
  }
  const targetMap = new Map(manifest.targets.map((target) => [target.id, target]));
  const mappings = compileMappings(profile);
  const contract = await probePublicContract(profile, fetchImpl);
  progress?.({ phase: "contract", observedVisibleVersion: contract.observedVisibleVersion });

  const targets = [];
  for (const state of STATES) {
    const id = `public-vibe-coding-${state}`;
    const manifestTarget = targetMap.get(id);
    if (!manifestTarget) throw new Error(`manifest target ${id} is missing`);
    const url = profile.targets[state];
    await probeTarget(state, url, profile, fetchImpl);
    targets.push({ ...manifestTarget, state, url });
  }

  const scans = [];
  for (const target of targets) {
    progress?.({ phase: "create", state: target.state });
    let result;
    try {
      const created = await createScan(target.url, profile, fetchImpl);
      result = await pollScan(created, profile, fetchImpl, sleep, (status) => progress?.({ phase: "poll", state: target.state, ...status }));
    } catch {
      progress?.({ phase: "scan-failed", state: target.state });
      result = { status: "Failed", coverageStatus: "Failed", findings: [], signals: [] };
    }
    scans.push(sanitizeScan(
      target.state,
      target,
      manifest.cases.filter((item) => item.targetId === target.id),
      result,
      mappings,
      now().toISOString(),
    ));
  }

  const counts = countClassifications(scans);
  const lifecycle = buildLifecycle(manifest, scans);
  const dimensions = buildDimensions(scans, counts, lifecycle);
  const discrepancies = buildDiscrepancies(contract, scans, lifecycle);
  const status = aggregateStatus(scans);
  const clean = status === "completed"
    && counts["false-positive"] === 0
    && counts["false-negative"] === 0
    && counts.inconclusive === 0
    && discrepancies.length === 0;
  return {
    $schema: "../../schemas/public-black-box-report.schema.json",
    schemaVersion: "1.0.0",
    benchmarkVersion: manifest.benchmarkVersion,
    recordedAt: now().toISOString(),
    laboratory: {
      version: packageConfiguration.version,
      targetSourceCommit: profile.targetSourceCommit,
    },
    application: {
      baseUrl: profile.application.baseUrl,
      publicFlow: profile.application.publicFlow,
      selectedVisibleVersion: contract.selectedVisibleVersion,
      observedVisibleVersion: contract.observedVisibleVersion,
      visibleVersionMatches: contract.visibleVersionMatches,
      createPath: contract.createPath,
      createMethod: contract.createMethod,
      contractVersion: contract.contractVersion,
      responsibleUseTermsVersion: contract.responsibleUseTermsVersion,
      clientContractExposed: contract.clientContractExposed,
    },
    execution: {
      interface: "public-http-contract",
      scope: "passive",
      authenticated: false,
      activeTesting: false,
      groundTruthProfile: manifest.cases[0].scannerProfile,
      groundTruthRulesetDigest: manifest.cases[0].rulesetDigest,
      mappingProfile: `${profile.id}@${profile.version}`,
      mappingProfileDigest: sha256(profileContent),
    },
    summary: {
      runStatus: status,
      verdict: clean ? "passed" : "blocked",
      clean,
      counts,
      discrepancyCount: discrepancies.length,
    },
    dimensions,
    scans,
    lifecycle,
    discrepancies,
  };
}

function parseArguments(arguments_) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    if (!["--json", "--markdown"].includes(arguments_[index]) || !arguments_[index + 1]) {
      throw new Error("usage: run-public-black-box.mjs --json report.json --markdown report.md");
    }
    options[arguments_[index].slice(2)] = arguments_[index + 1];
  }
  if (!options.json || !options.markdown) {
    throw new Error("both --json and --markdown outputs are required");
  }
  return options;
}

async function main() {
  const outputs = parseArguments(process.argv.slice(2));
  const report = await runPublicBlackBox({
    progress: (event) => process.stderr.write(`${JSON.stringify(event)}\n`),
  });
  await Promise.all([
    writeFile(outputs.json, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 }),
    writeFile(outputs.markdown, toBlackBoxMarkdown(report), { encoding: "utf8", mode: 0o600 }),
  ]);
  process.stdout.write(`${JSON.stringify(report.summary)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Public black-box run failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
