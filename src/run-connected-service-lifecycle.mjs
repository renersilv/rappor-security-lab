#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { readFile, rename, stat, writeFile, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import { HmlClient } from "./run-windows-agent-lab.mjs";
import { probeConnectedServicePresentation } from "./probe-connected-service-presentation.mjs";
import {
  applySupabaseState,
  cleanupSupabaseConfiguration,
  createVercelAdapter,
  readSupabaseConfiguration,
} from "./run-provider-configuration.mjs";
import { checkSupabaseState, loadPublicEnvironment } from "./run-supabase-authorization.mjs";
import {
  SUPABASE_ADVISOR_CANONICAL_RULES,
  SUPABASE_AFFECTED_ITEMS,
  SUPABASE_CANONICAL_RULES,
  SUPABASE_CANONICAL_STATES,
} from "../targets/connected/provider-configuration/lib/connected-analysis.mjs";
import {
  STATE_ORDER,
  SUPABASE_RULES,
  SUPABASE_STATES,
  VERCEL_RULE,
  VERCEL_STATES,
} from "../targets/connected/provider-configuration/lib/states.mjs";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const PRODUCT_NAME = "Connected Provider Laboratory";
const PRODUCT_DESCRIPTION = "Disposable black-box connected provider validation";
const CHECKPOINT_VERSION = 1;
const TERMINAL_STATES = new Set(["Completed", "Failed", "Partial", "Cancelled", "Canceled", "TimedOut"]);
const CLEAN_COVERAGE = new Set(["Complete", "Completed"]);
const MEASURED_COVERAGE = new Set(["Passed", "Failed", "Informational", "Measured", "Complete", "Completed"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f-]{27,}$/iu;
const execFile = promisify(execFileCallback);

const PROVIDERS = {
  vercel: {
    label: "Vercel",
    sourceKind: "Vercel",
    scannerKey: "rappor.vercel-configuration",
    expectedRules: [
      VERCEL_RULE.ruleFamily,
      "vercel.preview-deployment-authentication.disabled.v1",
    ],
    measuredRule: VERCEL_RULE.ruleFamily,
    resourceName(state) {
      return VERCEL_STATES[state].project;
    },
    expectedPresence(state) {
      return !VERCEL_STATES[state].gitForkProtection;
    },
    expectedFindings(state) {
      return VERCEL_STATES[state].gitForkProtection
        ? []
        : [{ ruleId: VERCEL_RULE.ruleFamily, severity: VERCEL_RULE.severity, affectedItem: state }];
    },
    manifestCases(state) {
      return [{
        caseId: `vercel-${VERCEL_RULE.id}-${state}`,
        canonicalRuleId: VERCEL_RULE.ruleFamily,
      }];
    },
    affectedItem(_finding, state) {
      return state;
    },
  },
  supabase: {
    label: "Supabase",
    sourceKind: "Supabase",
    scannerKey: "rappor.supabase-configuration",
    expectedRules: Object.values(SUPABASE_CANONICAL_RULES).map((rule) => rule.ruleFamily),
    measuredRule: null,
    resourceName(_state, resources) {
      return resources.length === 1 ? resources[0].displayName : null;
    },
    expectedPresence() {
      return null;
    },
    expectedFindings(state) {
      return SUPABASE_CANONICAL_STATES[state].flatMap(({ rule, affectedItems }) => affectedItems.map((affectedItem) => ({
        ruleId: SUPABASE_CANONICAL_RULES[rule].ruleFamily,
        severity: SUPABASE_CANONICAL_RULES[rule].severity,
        affectedItem,
      })));
    },
    manifestCases(state) {
      return Object.entries(SUPABASE_RULES).map(([key, rule]) => {
        const canonical = SUPABASE_ADVISOR_CANONICAL_RULES[key];
        return {
          caseId: `supabase-${rule.id}-${state}`,
          canonicalRuleId: canonical === null ? null : SUPABASE_CANONICAL_RULES[canonical].ruleFamily,
        };
      });
    },
    affectedItem(finding) {
      const searchable = JSON.stringify([finding?.location, finding?.maskedEvidence, finding?.title]);
      const matches = Object.entries(SUPABASE_AFFECTED_ITEMS)
        .filter(([, marker]) => searchable.includes(marker))
        .map(([key]) => key);
      return matches.length === 1 ? matches[0] : null;
    },
  },
};

function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function required(value, name) {
  if (typeof value !== "string" || value.length === 0) fail("missing-configuration", `${name} is required`);
  return value;
}

function exactOne(items, predicate, code, message) {
  const matches = items.filter(predicate);
  if (matches.length !== 1) fail(code, message);
  return matches[0];
}

function parseConfiguration(value) {
  try {
    const result = JSON.parse(value);
    if (result === null || typeof result !== "object" || Array.isArray(result)) throw new Error("object required");
    return result;
  } catch {
    fail("contract-changed", "the connected analysis configuration changed its public schema");
  }
}

function normalizedFindings(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  return [];
}

function findingRule(finding) {
  for (const key of ["ruleId", "ruleFamily", "ruleKey", "checkId", "canonicalRuleId"]) {
    if (typeof finding?.[key] === "string" && finding[key].length > 0) return finding[key];
  }
  return "unknown";
}

function safeSeverity(value) {
  const result = typeof value === "string" ? value.toLowerCase() : "unknown";
  return new Set(["info", "low", "medium", "high", "critical", "unknown"]).has(result) ? result : "unknown";
}

function safeScore(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const result = {};
  if (typeof value.score === "number" && Number.isFinite(value.score)) result.score = value.score;
  if (typeof value.presentation === "string") result.presentation = value.presentation;
  if (typeof value.classification === "string") result.classification = value.classification;
  const percentage = value.coverage?.percentage;
  if (typeof percentage === "number" && Number.isFinite(percentage)) result.coveragePercentage = percentage;
  return Object.keys(result).length > 0 ? result : null;
}

function safeEvolution(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const result = {};
  for (const key of ["new", "stillOpen", "fixed", "reappeared"]) {
    if (Number.isSafeInteger(value[key]) && value[key] >= 0) result[key] = value[key];
  }
  return Object.keys(result).length > 0 ? result : null;
}

function resultOutcome({
  assessmentState,
  coverageStatus,
  scannerState,
  expectationMatched,
  unmeasuredCaseIds,
  failureCode,
}) {
  if (/consent|authorization|credential/u.test(failureCode ?? "")) return "BlockedByConsent";
  if (/plan|limit|unsupported/u.test(failureCode ?? "")) return "Inconclusive";
  if (assessmentState !== "Completed" || scannerState !== "Completed") return "Failed";
  if (!CLEAN_COVERAGE.has(coverageStatus)) return coverageStatus === "Partial" ? "Inconclusive" : "Failed";
  if (!expectationMatched) return "Failed";
  return unmeasuredCaseIds.length > 0 ? "Inconclusive" : "Passed";
}

export class ConnectedServiceClient extends HmlClient {
  products() {
    return this.request("/api/products");
  }

  definitions(productId) {
    return this.request(`/api/products/${encodeURIComponent(productId)}/analysis-definitions`);
  }

  connectedServices() {
    return this.request("/api/integrations/connected-services/");
  }

  createConnectedDefinition(productId, input) {
    return this.request(`/api/products/${encodeURIComponent(productId)}/connected-service-analyses`, {
      method: "POST",
      csrf: true,
      body: input,
      operation: "create-connected-definition",
    });
  }
}

function definitionsArray(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  fail("contract-changed", "the analysis definition catalog changed its public schema");
}

export async function ensureConnectedSetup(client, providerName) {
  const spec = PROVIDERS[providerName];
  if (!spec) fail("invalid-provider", "provider must be supabase or vercel");

  const productCatalog = await client.products();
  if (!Array.isArray(productCatalog?.items)) fail("contract-changed", "the product catalog changed its public schema");
  const activeProducts = productCatalog.items.filter((item) => item.name === PRODUCT_NAME && item.archivedAt === null);
  if (activeProducts.length > 1) fail("duplicate-product", "more than one active connected laboratory Product exists");
  const reusedProduct = activeProducts.length === 1;
  const product = activeProducts[0] ?? await client.createProduct(PRODUCT_NAME, PRODUCT_DESCRIPTION);
  if (!product?.id || typeof product.version !== "number") fail("contract-changed", "the connected laboratory Product response changed");

  const inventory = await client.connectedServices();
  if (!Array.isArray(inventory?.providers) || !Array.isArray(inventory?.connections)) {
    fail("contract-changed", "the connected-service inventory changed its public schema");
  }
  const providerAvailable = inventory.providers.some((item) => item.provider === spec.label && item.available === true);
  if (!providerAvailable) fail("provider-unavailable", `${spec.label} is unavailable to the dedicated laboratory identity`);
  const connection = exactOne(
    inventory.connections,
    (item) => item.provider === spec.label,
    "consent-required",
    `${spec.label} must have exactly one existing connection`,
  );
  if (connection.state !== "Active") fail("consent-required", `${spec.label} connection is not Active`);
  if (!Array.isArray(connection.resources) || connection.resources.length === 0) {
    fail("resource-unavailable", `${spec.label} has no inventoried resource`);
  }
  if (connection.resources.some((item) => item.state !== "Authorized" || !item.id || !item.displayName)) {
    fail("consent-required", `${spec.label} resources are not all Authorized`);
  }

  const expectedNames = new Set(STATE_ORDER.map((state) => spec.resourceName(state, connection.resources)));
  if (expectedNames.has(null) || expectedNames.has(undefined)) {
    fail("resource-unavailable", `${spec.label} resource selection is ambiguous`);
  }
  const resources = new Map();
  for (const name of expectedNames) {
    resources.set(name, exactOne(
      connection.resources,
      (item) => item.displayName === name,
      "resource-unavailable",
      `the controlled ${spec.label} resource inventory is incomplete`,
    ));
  }

  let definitions = definitionsArray(await client.definitions(product.id)).filter((item) => item.archivedAt === null);
  const byState = {};
  let createdDefinitions = 0;
  for (const state of STATE_ORDER) {
    const resource = resources.get(spec.resourceName(state, connection.resources));
    const matches = definitions.filter((item) => item.type === "ConnectedService" && item.sourceId === resource.id);
    if (matches.length > 1) fail("duplicate-definition", `more than one active ${spec.label} definition selects ${state}`);
    let definition = matches[0];
    if (!definition) {
      const created = await client.createConnectedDefinition(product.id, {
        resourceId: resource.id,
        provider: spec.label,
        name: `${spec.label} ${state}`,
        environment: "Staging",
      });
      createdDefinitions += 1;
      const createdId = created?.id ?? created?.analysisDefinition?.id;
      definitions = definitionsArray(await client.definitions(product.id)).filter((item) => item.archivedAt === null);
      definition = definitions.find((item) => item.sourceId === resource.id || (createdId && item.id === createdId));
    }
    if (!definition?.id || !definition.currentRevisionId || definition.type !== "ConnectedService") {
      fail("contract-changed", `the ${spec.label} definition response changed its public schema`);
    }
    const configuration = parseConfiguration(definition.configurationJson);
    if (configuration.provider !== spec.label || configuration.resourceId !== resource.id) {
      fail("contract-changed", `the ${spec.label} definition does not select its authorized resource`);
    }
    byState[state] = definition;
  }

  return {
    product,
    definitions: byState,
    connection,
    resources: [...resources.values()],
    productReused: reusedProduct,
    createdDefinitions,
  };
}

function checkpointInsideRepository(path, repositoryRoot) {
  const result = relative(repositoryRoot, path);
  return result === "" || (!result.startsWith("..") && !isAbsolute(result));
}

export function createCheckpointStore(path, repositoryRoot = REPOSITORY_ROOT) {
  if (!isAbsolute(path)) fail("unsafe-checkpoint", "the checkpoint path must be absolute");
  const checkpointPath = resolve(path);
  if (checkpointInsideRepository(checkpointPath, repositoryRoot)) {
    fail("unsafe-checkpoint", "the protected checkpoint must remain outside the repository");
  }
  return {
    path: checkpointPath,
    async load() {
      try {
        const metadata = await stat(checkpointPath);
        if ((metadata.mode & 0o077) !== 0) fail("unsafe-checkpoint", "the checkpoint must have mode 0600");
        const value = JSON.parse(await readFile(checkpointPath, "utf8"));
        if (value?.version !== CHECKPOINT_VERSION) fail("checkpoint-changed", "the checkpoint version is unsupported");
        return value;
      } catch (error) {
        if (error?.code === "ENOENT") return { version: CHECKPOINT_VERSION, providers: {} };
        throw error;
      }
    },
    async save(value) {
      await mkdir(dirname(checkpointPath), { recursive: true, mode: 0o700 });
      const temporary = `${checkpointPath}.${process.pid}.${randomUUID()}.tmp`;
      await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
      await rename(temporary, checkpointPath);
    },
  };
}

export async function pollConnectedAssessment(client, assessmentId, {
  maxPolls = 120,
  pollIntervalMs = 2_000,
  sleep = (milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)),
} = {}) {
  for (let poll = 1; poll <= maxPolls; poll += 1) {
    const detail = await client.assessment(assessmentId);
    const state = detail?.assessment?.state;
    if (TERMINAL_STATES.has(state)) return { detail, polls: poll };
    if (typeof state !== "string") fail("contract-changed", "the connected assessment changed its public state schema");
    if (poll < maxPolls) await sleep(pollIntervalMs);
  }
  fail("poll-timeout", "the connected assessment exceeded its bounded polling interval");
}

function findingIdentity(ruleId, affectedItem) {
  return `${ruleId}::${affectedItem}`;
}

function duplicateFindingCount(findings) {
  const duplicates = new Set();
  for (const identity of [
    (item) => item.affectedItem === null ? null : findingIdentity(item.ruleId, item.affectedItem),
    (item) => typeof item.raw.fingerprint === "string" && item.raw.fingerprint.length > 0
      ? `fingerprint::${item.raw.fingerprint}`
      : null,
  ]) {
    const first = new Map();
    findings.forEach((item, index) => {
      const key = identity(item);
      if (key === null) return;
      if (first.has(key)) duplicates.add(index);
      else first.set(key, index);
    });
  }
  return duplicates.size;
}

function findingGroups(expectedFindings, observedFindings) {
  const rules = [...new Set([
    ...expectedFindings.map((item) => item.ruleId),
    ...observedFindings.map((item) => item.ruleId),
  ])].sort();
  return rules.map((ruleId) => {
    const expected = expectedFindings.filter((item) => item.ruleId === ruleId);
    const observed = observedFindings.filter((item) => item.ruleId === ruleId);
    return {
      ruleId,
      expectedSeverity: expected[0]?.severity ?? null,
      observedSeverities: [...new Set(observed.map((item) => item.severity))].sort(),
      expectedAffectedItems: [...new Set(expected.map((item) => item.affectedItem))].sort(),
      observedAffectedItems: [...new Set(observed.flatMap((item) => item.affectedItem === null ? [] : [item.affectedItem]))].sort(),
    };
  }).map((group) => ({
    ...group,
    expectedAffectedItemCount: group.expectedAffectedItems.length,
    observedAffectedItemCount: group.observedAffectedItems.length,
  }));
}

export function normalizeConnectedResult(providerName, state, detail, polls = 1) {
  const spec = PROVIDERS[providerName];
  const assessment = detail?.assessment ?? {};
  const runs = Array.isArray(detail?.runs) ? detail.runs : [];
  const run = runs.find((item) => item.scannerKey === spec.scannerKey) ?? runs[0] ?? {};
  const coverage = detail?.connectedServiceCoverage ?? {};
  const coverageChecks = Array.isArray(coverage.checks) ? coverage.checks : [];
  const coverageStates = new Map(coverageChecks
    .filter((item) => typeof item?.ruleId === "string" && typeof item?.state === "string")
    .map((item) => [item.ruleId, item.state]));
  const measuredRules = new Set([...coverageStates]
    .filter(([, coverageState]) => MEASURED_COVERAGE.has(coverageState))
    .map(([ruleId]) => ruleId));
  const expectedRuleSet = new Set(spec.expectedRules);
  const expectedFindings = spec.expectedFindings(state);
  const observedFindings = normalizedFindings(detail?.findings).map((finding) => ({
    raw: finding,
    ruleId: findingRule(finding),
    severity: safeSeverity(finding.severity),
    affectedItem: spec.affectedItem(finding, state),
  }));
  const comparableExpected = expectedFindings.filter((item) => measuredRules.has(item.ruleId));
  const comparableObserved = observedFindings.filter((item) => (
    measuredRules.has(item.ruleId) || !expectedRuleSet.has(item.ruleId)
  ));
  const expectedKeys = comparableExpected.map((item) => findingIdentity(item.ruleId, item.affectedItem)).sort();
  const observedKeys = comparableObserved.flatMap((item) => item.affectedItem === null
    ? []
    : [findingIdentity(item.ruleId, item.affectedItem)]).sort();
  const duplicateFindings = duplicateFindingCount(observedFindings);
  const unmappedFindingCount = observedFindings.filter((item) => item.affectedItem === null).length;
  const unmappedComparableCount = comparableObserved.filter((item) => item.affectedItem === null).length;
  const coverageFindingMismatches = observedFindings.filter((item) => (
    expectedRuleSet.has(item.ruleId) && !measuredRules.has(item.ruleId)
  )).length;
  const severityMismatches = comparableExpected.filter((expectedFinding) => {
    const matching = comparableObserved.filter((item) => (
      item.ruleId === expectedFinding.ruleId && item.affectedItem === expectedFinding.affectedItem
    ));
    return matching.length !== 1 || matching[0].severity !== expectedFinding.severity;
  }).length;
  const manifestCases = spec.manifestCases(state);
  const unmeasuredCases = manifestCases.filter((item) => (
    item.canonicalRuleId === null || !measuredRules.has(item.canonicalRuleId)
  ));
  const unmeasuredCaseIds = unmeasuredCases.map((item) => item.caseId).sort();
  const unmeasuredRuleIds = [...new Set(unmeasuredCases.flatMap((item) => (
    item.canonicalRuleId === null ? [] : [item.canonicalRuleId]
  )))].sort();
  const expectationMatched = duplicateFindings === 0
    && unmappedComparableCount === 0
    && coverageFindingMismatches === 0
    && severityMismatches === 0
    && JSON.stringify(expectedKeys) === JSON.stringify(observedKeys);
  const rules = observedFindings.map((item) => item.ruleId);
  const uniqueRules = [...new Set(rules)].sort();
  const expectedFindingRuleIds = [...new Set(expectedFindings.map((item) => item.ruleId))].sort();
  const expected = spec.expectedPresence(state);
  const observed = spec.measuredRule === null ? null : uniqueRules.includes(spec.measuredRule);
  const failureCode = run.failureCode ?? coverage.failureReason ?? null;
  const outcome = resultOutcome({
    assessmentState: assessment.state,
    coverageStatus: coverage.status,
    scannerState: run.state,
    expectationMatched,
    unmeasuredCaseIds,
    failureCode,
  });
  return {
    state,
    outcome,
    assessmentState: assessment.state ?? "Unknown",
    scannerState: run.state ?? "Unknown",
    scannerKey: run.scannerKey ?? spec.scannerKey,
    scannerVersion: typeof run.scannerVersion === "string" ? run.scannerVersion : "unknown",
    profile: assessment.profile ?? "unknown",
    profileVersion: Number.isSafeInteger(assessment.profileVersion) ? assessment.profileVersion : null,
    coverageStatus: coverage.status ?? "Unknown",
    resultContractVersion: coverage.resultContractVersion ?? null,
    rulesVersion: coverage.rulesVersion ?? null,
    coverageVersion: coverage.coverageVersion ?? null,
    expectedRuleCount: spec.expectedRules.length,
    coveredRuleCount: spec.expectedRules.filter((rule) => measuredRules.has(rule)).length,
    manifestCaseCount: manifestCases.length,
    measuredManifestCaseCount: manifestCases.length - unmeasuredCaseIds.length,
    unmeasuredCaseIds,
    unmeasuredRuleIds,
    expectedFindingCount: expectedFindings.length,
    findingCount: observedFindings.length,
    expectedAffectedItemCount: new Set(expectedFindings.map((item) => item.affectedItem)).size,
    affectedItemCount: new Set(observedFindings.flatMap((item) => item.affectedItem === null ? [] : [item.affectedItem])).size,
    findingGroups: findingGroups(expectedFindings, observedFindings),
    expectedFindingRuleIds,
    findingRuleIds: uniqueRules,
    severities: [...new Set(observedFindings.map((item) => item.severity))].sort(),
    duplicateFindings,
    unmappedFindingCount,
    coverageFindingMismatches,
    severityMismatches,
    expectedMeasuredFinding: expected,
    observedMeasuredFinding: observed,
    expectationMatched,
    failureCode,
    score: safeScore(assessment.securityScore),
    evolution: safeEvolution(assessment.evolution),
    polls,
  };
}

function lifecycleStatus(comparable, matched) {
  if (!comparable) return "Inconclusive";
  return matched ? "Matched" : "Mismatch";
}

export function evaluateLifecycle(provider, states) {
  const byState = Object.fromEntries(states.map((item) => [item.state, item]));
  const complete = STATE_ORDER.every((state) => byState[state] !== undefined);
  const comparableFindings = complete && states.every((item) => item.unmeasuredRuleIds.length === 0);
  const manifestCoverage = complete
    && states.every((item) => item.measuredManifestCaseCount === item.manifestCaseCount)
    ? "Matched"
    : "Inconclusive";
  const measuredFindingTransitions = lifecycleStatus(
    comparableFindings,
    states.every((item) => item.expectationMatched),
  );
  const duplicateFree = states.every((item) => item.duplicateFindings === 0);
  if (!complete) {
    return {
      manifestCoverage,
      measuredFindingTransitions,
      scoreProgression: "Inconclusive",
      measuredResolution: "Inconclusive",
      measuredReintroduction: "Inconclusive",
      history: "Inconclusive",
      duplicateFree,
    };
  }

  const vulnerable = byState.vulnerable;
  const partial = byState["partially-fixed"];
  const fixed = byState.fixed;
  const reintroduced = byState.reintroduced;
  const lifecycleStates = [vulnerable, partial, fixed, reintroduced];
  const historyAvailable = lifecycleStates.every((item) => (
    item.evolution !== null
    && ["new", "stillOpen", "fixed", "reappeared"]
      .every((key) => Number.isSafeInteger(item.evolution[key]) && item.evolution[key] >= 0)
  ));
  const activeHistoryCount = (item) => item.evolution.new + item.evolution.stillOpen + item.evolution.reappeared;
  const comparableHistory = comparableFindings && historyAvailable && provider !== "vercel";
  const scores = [vulnerable, partial, fixed, reintroduced].map((item) => item.score?.score);
  const scoresAvailable = scores.every((score) => typeof score === "number" && Number.isFinite(score));
  const scoreProgression = lifecycleStatus(scoresAvailable, scoresAvailable
    && scores[0] < scores[1]
    && scores[1] <= scores[2]
    && scores[3] < scores[2]
    && Math.abs(scores[0] - scores[3]) < 1e-9);
  const measuredResolution = lifecycleStatus(comparableFindings, comparableFindings
    && vulnerable.findingCount > partial.findingCount
    && partial.findingCount >= fixed.findingCount
    && fixed.findingCount === 0);
  const measuredReintroduction = lifecycleStatus(comparableFindings, comparableFindings
    && reintroduced.findingCount === vulnerable.findingCount
    && reintroduced.findingCount > fixed.findingCount);
  const history = lifecycleStatus(comparableHistory, comparableHistory
    && activeHistoryCount(vulnerable) === vulnerable.findingCount
    && activeHistoryCount(partial) === partial.findingCount
    && partial.evolution.fixed + partial.findingCount === vulnerable.findingCount
    && activeHistoryCount(fixed) === fixed.findingCount
    && fixed.evolution.fixed + fixed.findingCount === partial.findingCount
    && activeHistoryCount(reintroduced) === reintroduced.findingCount
    && reintroduced.evolution.reappeared === reintroduced.findingCount);
  return {
    manifestCoverage,
    measuredFindingTransitions,
    scoreProgression,
    measuredResolution,
    measuredReintroduction,
    history,
    duplicateFree,
  };
}

export function summarizeOutcomes(states, cleanup, lifecycle = null) {
  const counts = Object.fromEntries(["Passed", "Failed", "BlockedByConsent", "Inconclusive"]
    .map((outcome) => [outcome, states.filter((item) => item.outcome === outcome).length]));
  const lifecycleStatuses = lifecycle === null
    ? []
    : Object.entries(lifecycle).flatMap(([key, value]) => key === "duplicateFree" ? [] : [value]);
  let outcome = "Passed";
  if (!cleanup?.verified || counts.Failed > 0 || lifecycle?.duplicateFree === false || lifecycleStatuses.includes("Mismatch")) outcome = "Failed";
  else if (counts.BlockedByConsent > 0) outcome = "BlockedByConsent";
  else if (counts.Inconclusive > 0 || states.length !== STATE_ORDER.length || lifecycleStatuses.includes("Inconclusive")) outcome = "Inconclusive";
  return { outcome, clean: outcome === "Passed", counts };
}

function outcomeForError(error) {
  if (error?.code === "consent-required") return "BlockedByConsent";
  if (new Set([
    "provider-unavailable",
    "resource-unavailable",
    "supabase-target-unavailable",
    "supabase-catalog-unavailable",
    "supabase-authorization-unavailable",
    "plan-limited",
  ]).has(error?.code)) {
    return "Inconclusive";
  }
  return "Failed";
}

function failedState(spec, state, error) {
  return {
    state,
    outcome: outcomeForError(error),
    assessmentState: "Unavailable",
    scannerState: "Unavailable",
    scannerKey: spec.scannerKey,
    scannerVersion: "unknown",
    profile: "unknown",
    profileVersion: null,
    coverageStatus: "Unavailable",
    resultContractVersion: null,
    rulesVersion: null,
    coverageVersion: null,
    expectedRuleCount: spec.expectedRules.length,
    coveredRuleCount: 0,
    manifestCaseCount: state === "unknown" ? 0 : spec.manifestCases(state).length,
    measuredManifestCaseCount: 0,
    unmeasuredCaseIds: state === "unknown" ? [] : spec.manifestCases(state).map((item) => item.caseId).sort(),
    unmeasuredRuleIds: state === "unknown" ? [] : [...new Set(spec.manifestCases(state)
      .flatMap((item) => item.canonicalRuleId === null ? [] : [item.canonicalRuleId]))].sort(),
    expectedFindingCount: state === "unknown" ? 0 : spec.expectedFindings(state).length,
    findingCount: 0,
    expectedAffectedItemCount: state === "unknown" ? 0 : new Set(spec.expectedFindings(state).map((item) => item.affectedItem)).size,
    affectedItemCount: 0,
    findingGroups: state === "unknown" ? [] : findingGroups(spec.expectedFindings(state), []),
    expectedFindingRuleIds: state === "unknown" ? [] : [...new Set(spec.expectedFindings(state).map((item) => item.ruleId))].sort(),
    findingRuleIds: [],
    severities: [],
    duplicateFindings: 0,
    unmappedFindingCount: 0,
    coverageFindingMismatches: 0,
    severityMismatches: 0,
    expectedMeasuredFinding: state === "unknown" ? null : spec.expectedPresence(state),
    observedMeasuredFinding: null,
    expectationMatched: false,
    failureCode: error?.code ?? "runner-failed",
    score: null,
    evolution: null,
    polls: 0,
  };
}

function buildReport({
  provider,
  expectedVersion,
  observedVersion,
  sourceCommit,
  recordedAt,
  resumed,
  setup,
  states,
  presentation,
  cleanup,
}) {
  const lifecycle = evaluateLifecycle(provider, states);
  return {
    $schema: "../../schemas/connected-service-lifecycle-report.schema.json",
    schemaVersion: "1.1.0",
    recordedAt,
    laboratory: { version: "0.0.0", sourceCommit },
    application: {
      selectedVisibleVersion: expectedVersion,
      observedVisibleVersion: observedVersion,
      visibleVersionMatches: observedVersion === expectedVersion,
    },
    provider,
    execution: {
      interface: "public-web-and-api",
      pollingBounded: true,
      rawResponsesRetained: false,
      resumed,
    },
    setup,
    summary: summarizeOutcomes(states, cleanup, lifecycle),
    states,
    lifecycle,
    presentation: [...presentation].sort((left, right) => left.locale.localeCompare(right.locale)),
    cleanup,
    sanitization: {
      retained: ["versions", "logical-states", "coverage", "canonical-rules", "logical-affected-items", "counts", "classifications", "scores", "lifecycle", "cleanup"],
      excluded: [
        "credentials", "cookies", "provider-resource-ids", "product-ids", "execution-ids",
        "finding-fingerprints", "finding-issue-ids", "finding-occurrence-ids", "locations",
        "users", "urls", "raw-responses", "evidence",
      ],
    },
  };
}

export async function probeVisibleVersion(baseUrl, fetchImpl = fetch) {
  const response = await fetchImpl(new URL(baseUrl).origin, {
    headers: { Accept: "text/html" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) fail("deployment-unavailable", `the visible deployment returned HTTP ${response.status}`);
  const versions = [...new Set((await response.text()).match(/v\d+\.\d+\.\d+/gu) ?? [])];
  if (versions.length !== 1) fail("contract-changed", "the visible deployment must expose exactly one semantic version");
  return versions[0];
}

export async function runConnectedServiceLifecycle({
  provider,
  client,
  adapter,
  checkpointStore,
  expectedVersion,
  observedVersion = expectedVersion,
  sourceCommit,
  recordedAt = new Date().toISOString(),
  polling,
  presentationProbe,
}) {
  const spec = PROVIDERS[provider];
  if (!spec) fail("invalid-provider", "provider must be supabase or vercel");
  if (!/^[a-f0-9]{40}$/u.test(sourceCommit ?? "")) fail("invalid-source-commit", "sourceCommit must be a full Git commit");
  if (!/^v\d+\.\d+\.\d+$/u.test(expectedVersion ?? "")) fail("invalid-version", "expectedVersion must use vMAJOR.MINOR.PATCH");
  const checkpoint = await checkpointStore.load();
  const selectedBaseline = { expectedVersion, sourceCommit };
  const existingProviderCheckpoint = checkpoint.providers[provider];
  checkpoint.providers[provider] ??= {
    baseline: selectedBaseline,
    results: {},
    assessments: {},
    presentation: [],
    pending: null,
  };
  const providerCheckpoint = checkpoint.providers[provider];
  providerCheckpoint.assessments ??= {};
  providerCheckpoint.presentation ??= [];
  const resumed = providerCheckpoint.pending !== null || Object.keys(providerCheckpoint.results).length > 0;
  let baselineError = null;
  if (existingProviderCheckpoint && providerCheckpoint.baseline === undefined && resumed) {
    baselineError = Object.assign(new Error("the checkpoint predates explicit baseline binding"), {
      code: "checkpoint-baseline-missing",
    });
  } else if (providerCheckpoint.baseline === undefined) {
    providerCheckpoint.baseline = selectedBaseline;
  } else if (
    providerCheckpoint.baseline.expectedVersion !== selectedBaseline.expectedVersion
    || providerCheckpoint.baseline.sourceCommit !== selectedBaseline.sourceCommit
  ) {
    baselineError = Object.assign(new Error("the checkpoint belongs to a different benchmark baseline"), {
      code: "checkpoint-baseline-mismatch",
    });
  }
  let setup;
  try {
    if (baselineError) throw baselineError;
    if (observedVersion !== expectedVersion) fail("deployment-version-mismatch", "the visible HML version did not match the selected version");
    setup = await ensureConnectedSetup(client, provider);
  } catch (error) {
    const states = [failedState(spec, "vulnerable", error)];
    return buildReport({
      provider,
      expectedVersion,
      observedVersion,
      sourceCommit,
      recordedAt,
      resumed,
      setup: { productReused: false, createdDefinitions: 0, connectionState: "Unavailable", authorizedResourceCount: 0 },
      states,
      presentation: providerCheckpoint.presentation,
      cleanup: { verified: true, resourcesRestored: 0 },
    });
  }
  const states = [];
  let cleanup = { verified: false, resourcesRestored: 0 };
  try {
    for (const state of STATE_ORDER) {
      if (providerCheckpoint.results[state]) {
        states.push(providerCheckpoint.results[state]);
        continue;
      }
      await adapter.apply(state);
      let assessmentId;
      if (providerCheckpoint.pending?.state === state) {
        assessmentId = providerCheckpoint.pending.assessmentId;
      } else {
        const created = await client.runDefinition(setup.definitions[state]);
        if (!created?.id || !UUID.test(created.id)) fail("contract-changed", "the connected execution response changed");
        assessmentId = created.id;
        providerCheckpoint.pending = { state, assessmentId };
        await checkpointStore.save(checkpoint);
      }
      const { detail, polls } = await pollConnectedAssessment(client, assessmentId, polling);
      const result = normalizeConnectedResult(provider, state, detail, polls);
      providerCheckpoint.assessments[state] = assessmentId;
      const locale = state === "vulnerable" ? "pt-BR" : state === "reintroduced" ? "en-US" : null;
      if (locale && presentationProbe && !providerCheckpoint.presentation.some((item) => item.locale === locale)) {
        const proof = await presentationProbe({ locale, state, assessmentId });
        if (proof?.locale !== locale || proof.route !== "execution-detail" || proof.rendered !== true || proof.navigable !== true) {
          fail("presentation-failed", `the ${locale} execution detail was not rendered and navigable`);
        }
        providerCheckpoint.presentation.push(proof);
      }
      providerCheckpoint.results[state] = result;
      providerCheckpoint.pending = null;
      await checkpointStore.save(checkpoint);
      states.push(result);
    }
  } catch (error) {
    const state = providerCheckpoint.pending?.state ?? STATE_ORDER[states.length] ?? "unknown";
    states.push(failedState(spec, state, error));
  } finally {
    try {
      cleanup = await adapter.cleanup();
    } catch {
      cleanup = { verified: false, resourcesRestored: 0 };
    }
  }
  return buildReport({
    provider,
    expectedVersion,
    observedVersion,
    sourceCommit,
    recordedAt,
    resumed,
    setup: {
      productReused: setup.productReused,
      createdDefinitions: setup.createdDefinitions,
      connectionState: setup.connection.state,
      authorizedResourceCount: setup.resources.length,
    },
    states,
    presentation: providerCheckpoint.presentation,
    cleanup,
  });
}

export function createVercelLifecycleAdapter(environment = process.env) {
  const provider = createVercelAdapter(environment);
  const projects = [...new Set(Object.values(VERCEL_STATES).map((item) => item.project))];
  return {
    async apply(state) {
      const expected = VERCEL_STATES[state].gitForkProtection;
      await provider.update(VERCEL_STATES[state].project, expected);
      const result = await provider.read(VERCEL_STATES[state].project);
      if (result.gitForkProtection !== expected) fail("provider-state-mismatch", `Vercel ${state} did not match ground truth`);
    },
    async cleanup() {
      let restored = 0;
      for (const project of projects) {
        try {
          await provider.update(project, true);
          if ((await provider.read(project)).gitForkProtection === true) restored += 1;
        } catch {
          // Try every controlled project before failing closed.
        }
      }
      return { verified: restored === projects.length, resourcesRestored: restored };
    },
  };
}

export function createSupabaseLifecycleAdapter(environment = process.env) {
  const config = {
    ...loadPublicEnvironment(environment),
    email: required(environment.SUPABASE_LAB_AUTH_EMAIL, "SUPABASE_LAB_AUTH_EMAIL"),
    password: required(environment.SUPABASE_LAB_AUTH_PASSWORD, "SUPABASE_LAB_AUTH_PASSWORD"),
  };
  return {
    async apply(state) {
      try {
        await applySupabaseState(state, environment);
      } catch {
        fail("supabase-target-unavailable", "the disposable Supabase target is unavailable");
      }
      let findings;
      try {
        findings = await readSupabaseConfiguration(environment);
      } catch {
        fail("supabase-catalog-unavailable", "the Supabase catalog assertion is unavailable");
      }
      if (JSON.stringify(findings) !== JSON.stringify(SUPABASE_STATES[state].findings)) {
        fail("provider-state-mismatch", `Supabase ${state} did not match ground truth`);
      }
      let authorization;
      try {
        authorization = await checkSupabaseState(state, config);
      } catch {
        fail("supabase-authorization-unavailable", "the Supabase authorization assertion is unavailable");
      }
      if (authorization.status !== "completed") fail("provider-state-mismatch", `Supabase ${state} authorization was incomplete`);
    },
    async cleanup() {
      const result = await cleanupSupabaseConfiguration(environment);
      return { verified: Object.values(result).every(Boolean), resourcesRestored: 1 };
    },
  };
}

async function loadCredentials(path) {
  const metadata = await stat(path);
  if ((metadata.mode & 0o077) !== 0) fail("unsafe-credentials", "the HML credentials file must have mode 0600");
  let result;
  try {
    result = await execFile("/bin/bash", [
      "-c",
      "set -a\nsource \"$1\"\nset +a\nprintf '%s\\0%s' \"$RAPPOR_HML_EMAIL\" \"$RAPPOR_HML_PASSWORD\"",
      "rappor-connected-credential-loader",
      path,
    ], { encoding: "buffer", maxBuffer: 64 * 1024, timeout: 10_000 });
  } catch {
    fail("unsafe-credentials", "the HML credentials file could not be loaded safely");
  }
  const separator = result.stdout.indexOf(0);
  if (separator <= 0 || separator === result.stdout.length - 1 || result.stdout.indexOf(0, separator + 1) !== -1) {
    fail("unsafe-credentials", "the HML credentials file did not provide exactly two values");
  }
  return {
    email: result.stdout.subarray(0, separator).toString("utf8"),
    password: result.stdout.subarray(separator + 1).toString("utf8"),
  };
}

function parseArguments(arguments_) {
  const options = { provider: null, json: null, checkpoint: null, expectedVersion: null, sourceCommit: null };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (["--provider", "--json", "--checkpoint", "--expected-version", "--source-commit"].includes(argument) && arguments_[index + 1]) {
      const key = argument.slice(2).replace(/-([a-z])/gu, (_match, letter) => letter.toUpperCase());
      options[key] = arguments_[++index];
    } else {
      fail("usage", "usage: run-connected-service-lifecycle.mjs --provider <supabase|vercel> --checkpoint PATH --expected-version vX.Y.Z --source-commit SHA --json PATH");
    }
  }
  if (!PROVIDERS[options.provider] || !options.json || !options.checkpoint || !options.expectedVersion || !options.sourceCommit) {
    fail("usage", "provider, checkpoint, expected-version, source-commit and json are required");
  }
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const baseUrl = required(process.env.RAPPOR_CONNECTED_HML_BASE_URL ?? process.env.RAPPOR_WINDOWS_HML_BASE_URL, "RAPPOR_CONNECTED_HML_BASE_URL");
  const credentialsPath = required(process.env.RAPPOR_CONNECTED_HML_CREDENTIALS_FILE ?? process.env.RAPPOR_WINDOWS_HML_CREDENTIALS_FILE, "RAPPOR_CONNECTED_HML_CREDENTIALS_FILE");
  const credentials = await loadCredentials(credentialsPath);
  const client = new ConnectedServiceClient(baseUrl);
  const observedVersion = await probeVisibleVersion(baseUrl);
  await client.login(credentials.email, credentials.password);
  const adapter = options.provider === "vercel"
    ? createVercelLifecycleAdapter()
    : createSupabaseLifecycleAdapter();
  const report = await runConnectedServiceLifecycle({
    provider: options.provider,
    client,
    adapter,
    checkpointStore: createCheckpointStore(options.checkpoint),
    expectedVersion: options.expectedVersion,
    observedVersion,
    sourceCommit: options.sourceCommit,
    presentationProbe: ({ locale, assessmentId }) => probeConnectedServicePresentation({
      baseUrl,
      email: credentials.email,
      password: credentials.password,
      assessmentId,
      locale,
    }),
  });
  await writeFile(resolve(options.json), `${JSON.stringify(report, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({ provider: report.provider, outcome: report.summary.outcome, clean: report.summary.clean, states: report.states.length, cleanupVerified: report.cleanup.verified })}\n`);
  if (!report.summary.clean) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Connected service lifecycle failed: ${error.code ?? "runner-failed"}\n`);
    process.exitCode = 1;
  });
}
