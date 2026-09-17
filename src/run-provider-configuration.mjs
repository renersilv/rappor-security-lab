#!/usr/bin/env node

import { execFile as execFileCallback } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import { compare } from "./compare.mjs";
import { buildProviderConfigurationManifest } from "./generate-provider-configuration-manifest.mjs";
import { checkSupabaseState, loadPublicEnvironment } from "./run-supabase-authorization.mjs";
import {
  STATE_ORDER,
  SUPABASE_RULES,
  SUPABASE_STATES,
  VERCEL_RULE,
  VERCEL_SCOPE,
  VERCEL_STATES,
} from "../targets/connected/provider-configuration/lib/states.mjs";

const execFile = promisify(execFileCallback);
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "..");
const AUTHORIZATION_TARGET = resolve(REPOSITORY_ROOT, "targets", "connected", "supabase-authorization");
const CONFIGURATION_TARGET = resolve(REPOSITORY_ROOT, "targets", "connected", "provider-configuration");
const VERCEL_CLI_VERSION = "59.20.0";

const CATALOG_QUERY = String.raw`
select json_build_object(
  'policyExistsRlsDisabled', exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'rappor_lab_policy_without_rls'
      and not c.relrowsecurity and exists (select 1 from pg_policy p where p.polrelid = c.oid)
  ),
  'rlsEnabledNoPolicy', exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'rappor_lab_no_policy'
      and c.relrowsecurity and not exists (select 1 from pg_policy p where p.polrelid = c.oid)
  ),
  'securityDefinerView', exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'rappor_lab_security_view' and c.relkind = 'v'
      and not (lower(coalesce(c.reloptions::text, '{}'))::text[] && array['security_invoker=1','security_invoker=true','security_invoker=yes','security_invoker=on'])
  ),
  'rlsDisabledInPublic', exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'rappor_lab_rls_disabled' and not c.relrowsecurity
  ),
  'sensitiveColumnsExposed', exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    join pg_attribute a on a.attrelid = c.oid and a.attname = 'password' and not a.attisdropped
    where n.nspname = 'public' and c.relname = 'rappor_lab_sensitive_profiles' and not c.relrowsecurity
  ),
  'permissiveRlsPolicy', exists (
    select 1 from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname = 'rappor_lab_permissive_policy'
      and p.polname = 'rappor_lab_permissive_policy_owner' and p.polpermissive and p.polcmd = 'w'
      and regexp_replace(pg_get_expr(p.polqual, p.polrelid), '[()[:space:]]', '', 'g') = 'true'
      and regexp_replace(pg_get_expr(p.polwithcheck, p.polrelid), '[()[:space:]]', '', 'g') = 'true'
  ),
  'publicBucketAllowsListing', exists (
    select 1 from storage.buckets b
    where b.id = 'rappor-lab-public-listing' and b.public
      and exists (
        select 1 from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'storage' and c.relname = 'objects'
          and p.polname = 'rappor_lab_public_bucket_list' and p.polpermissive and p.polcmd in ('r', '*')
      )
  )
)::text;
`;

const CLEANUP_QUERY = String.raw`
select json_build_object(
  'authorizationRelationAbsent', to_regclass('public.rappor_lab_documents') is null,
  'configurationObjectsAbsent', not exists (
    select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relname in (
      'rappor_lab_rls_disabled', 'rappor_lab_policy_without_rls', 'rappor_lab_sensitive_profiles',
      'rappor_lab_permissive_policy', 'rappor_lab_no_policy', 'rappor_lab_security_view'
    )
  ),
  'bucketAbsent', not exists (select 1 from storage.buckets where id = 'rappor-lab-public-listing'),
  'bucketPolicyAbsent', not exists (
    select 1 from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'storage' and c.relname = 'objects' and p.polname = 'rappor_lab_public_bucket_list'
  )
)::text;
`;

function required(environment, name) {
  const value = environment[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function exactBooleanObject(value, expectedKeys, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} did not return an object`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expectedKeys].sort())) {
    throw new Error(`${label} changed its schema`);
  }
  for (const key of expectedKeys) {
    if (typeof value[key] !== "boolean") throw new Error(`${label}.${key} is not boolean`);
  }
  return value;
}

function postgresEnvironment(environment, pgService) {
  const allowed = ["HOME", "PATH", "PGSERVICEFILE", "PGPASSFILE", "PGSSLCERT", "PGSSLKEY", "PGSSLROOTCERT"];
  const result = { PGSERVICE: pgService };
  for (const name of allowed) if (environment[name]) result[name] = environment[name];
  return result;
}

async function psql(arguments_, environment = process.env, runner = execFile) {
  try {
    return await runner("psql", arguments_, {
      env: postgresEnvironment(environment, required(environment, "SUPABASE_LAB_PGSERVICE")),
      maxBuffer: 1024 * 1024,
    });
  } catch {
    throw new Error("the bounded PostgreSQL provider operation failed");
  }
}

function targetFile(root, relativePath) {
  return resolve(root, relativePath);
}

async function applySupabaseState(stateName, environment = process.env, runner = execFile) {
  const state = SUPABASE_STATES[stateName];
  await psql([
    "--no-psqlrc",
    "--set=ON_ERROR_STOP=on",
    "--quiet",
    "--file", targetFile(AUTHORIZATION_TARGET, "migrations/001_schema.sql"),
    "--file", targetFile(AUTHORIZATION_TARGET, stateName === "partially-fixed" ? "migrations/020_partially_fixed.sql" : `migrations/${stateName === "vulnerable" ? "010_vulnerable" : stateName === "fixed" ? "030_fixed" : "040_reintroduced"}.sql`),
    "--file", targetFile(CONFIGURATION_TARGET, "supabase/migrations/001_schema.sql"),
    "--file", targetFile(CONFIGURATION_TARGET, state.migration),
  ], environment, runner);
}

async function querySupabaseBooleans(query, keys, label, environment = process.env, runner = execFile) {
  const { stdout } = await psql([
    "--no-psqlrc",
    "--set=ON_ERROR_STOP=on",
    "--tuples-only",
    "--no-align",
    "--command", query,
  ], environment, runner);
  let parsed;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    throw new Error(`${label} was not valid JSON`);
  }
  return exactBooleanObject(parsed, keys, label);
}

export async function readSupabaseConfiguration(environment = process.env, runner = execFile) {
  return querySupabaseBooleans(
    CATALOG_QUERY,
    Object.keys(SUPABASE_RULES),
    "the Supabase catalog post-condition",
    environment,
    runner,
  );
}

export async function cleanupSupabaseConfiguration(environment = process.env, runner = execFile) {
  await psql([
    "--no-psqlrc",
    "--set=ON_ERROR_STOP=on",
    "--quiet",
    "--file", targetFile(CONFIGURATION_TARGET, "supabase/migrations/900_reset.sql"),
    "--file", targetFile(AUTHORIZATION_TARGET, "migrations/900_reset.sql"),
  ], environment, runner);
  const cleanup = await querySupabaseBooleans(
    CLEANUP_QUERY,
    ["authorizationRelationAbsent", "configurationObjectsAbsent", "bucketAbsent", "bucketPolicyAbsent"],
    "the Supabase cleanup post-condition",
    environment,
    runner,
  );
  if (!Object.values(cleanup).every(Boolean)) throw new Error("the Supabase cleanup post-condition was not satisfied");
  return cleanup;
}

export async function runSupabaseConfigurationLifecycle({
  environment = process.env,
  applyState,
  readConfiguration,
  checkAuthorization,
  cleanup,
} = {}) {
  const publicConfig = loadPublicEnvironment(environment);
  const config = {
    ...publicConfig,
    email: required(environment, "SUPABASE_LAB_AUTH_EMAIL"),
    password: required(environment, "SUPABASE_LAB_AUTH_PASSWORD"),
  };
  const apply = applyState ?? ((stateName) => applySupabaseState(stateName, environment));
  const read = readConfiguration ?? (() => readSupabaseConfiguration(environment));
  const authorize = checkAuthorization ?? ((stateName) => checkSupabaseState(stateName, config));
  const clean = cleanup ?? (() => cleanupSupabaseConfiguration(environment));
  const states = [];
  let cleanupResult;
  try {
    for (const stateName of STATE_ORDER) {
      await apply(stateName);
      const findings = await read();
      const expected = SUPABASE_STATES[stateName].findings;
      if (JSON.stringify(findings) !== JSON.stringify(expected)) {
        throw new Error(`the Supabase ${stateName} catalog post-condition did not match ground truth`);
      }
      const authorization = await authorize(stateName);
      if (authorization?.status !== "completed" || authorization.observations?.length !== 4) {
        throw new Error(`the Supabase ${stateName} authorization check was incomplete`);
      }
      states.push({ state: stateName, findings, authorizationChecks: 4 });
    }
  } finally {
    cleanupResult = await clean();
  }
  return {
    provider: "supabase",
    status: "completed",
    states,
    cleanup: cleanupResult,
    observations: states.flatMap(({ state, findings }) => Object.entries(SUPABASE_RULES).map(([key, rule]) => ({
      caseId: `supabase-${rule.id}-${state}`,
      present: findings[key],
    }))),
  };
}

function vercelEnvironment(environment) {
  const allowed = ["HOME", "PATH", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "NPM_CONFIG_CACHE"];
  return Object.fromEntries(allowed.filter((name) => environment[name]).map((name) => [name, environment[name]]));
}

async function invokeVercelApi(project, mutation, environment = process.env, runner = execFile) {
  const arguments_ = [
    "--yes",
    `vercel@${VERCEL_CLI_VERSION}`,
    "api",
    `/v9/projects/${project}`,
    "--scope", VERCEL_SCOPE,
    "--raw",
  ];
  if (mutation !== undefined) {
    arguments_.push("--method", "PATCH", "--field", `gitForkProtection=${mutation}`);
  }
  let stdout;
  try {
    ({ stdout } = await runner("npx", arguments_, {
      env: vercelEnvironment(environment),
      maxBuffer: 4 * 1024 * 1024,
    }));
  } catch {
    throw new Error("the bounded official Vercel project request failed");
  }
  let payload;
  try {
    payload = JSON.parse(stdout);
  } catch {
    throw new Error("the official Vercel project response was not valid JSON");
  }
  if (payload?.name !== project || typeof payload.gitForkProtection !== "boolean") {
    throw new Error("the official Vercel project response changed its required schema");
  }
  return { gitForkProtection: payload.gitForkProtection };
}

export function createVercelAdapter(environment = process.env, runner = execFile) {
  return {
    read: (project) => invokeVercelApi(project, undefined, environment, runner),
    update: (project, value) => invokeVercelApi(project, value, environment, runner),
  };
}

async function setAndVerifyVercel(adapter, project, expected) {
  await adapter.update(project, expected);
  const observed = await adapter.read(project);
  if (observed.gitForkProtection !== expected) {
    throw new Error("the Vercel Git fork protection post-condition was not satisfied");
  }
  return observed.gitForkProtection;
}

export async function runVercelConfigurationLifecycle({ adapter = createVercelAdapter() } = {}) {
  const projects = [...new Set(Object.values(VERCEL_STATES).map((state) => state.project))];
  const states = [];
  let cleanupResult;
  try {
    for (const project of projects) {
      const initial = await adapter.read(project);
      if (typeof initial?.gitForkProtection !== "boolean") {
        throw new Error("the Vercel Git fork protection precondition changed its schema");
      }
      await setAndVerifyVercel(adapter, project, true);
    }
    for (const stateName of STATE_ORDER) {
      const state = VERCEL_STATES[stateName];
      const gitForkProtection = await setAndVerifyVercel(adapter, state.project, state.gitForkProtection);
      states.push({ state: stateName, gitForkProtection });
    }
  } finally {
    const restored = [];
    for (const project of projects) {
      try {
        restored.push(await setAndVerifyVercel(adapter, project, true));
      } catch {
        throw new Error("the Vercel safe cleanup did not restore every controlled project");
      }
    }
    cleanupResult = {
      gitForkProtection: true,
      projectsRestored: restored.filter(Boolean).length,
      verified: restored.length === projects.length && restored.every(Boolean),
    };
  }
  return {
    provider: "vercel",
    status: "completed",
    states,
    cleanup: cleanupResult,
    observations: states.map(({ state, gitForkProtection }) => ({
      caseId: `vercel-${VERCEL_RULE.id}-${state}`,
      present: !gitForkProtection,
    })),
  };
}

function providerManifest(manifest, provider) {
  const prefix = `${provider}-`;
  const cases = manifest.cases.filter((item) => item.id.startsWith(prefix));
  const targetIds = new Set(cases.map((item) => item.targetId));
  return {
    benchmarkVersion: manifest.benchmarkVersion,
    targets: manifest.targets.filter((item) => targetIds.has(item.id)),
    cases,
  };
}

export function buildSanitizedReport(manifest, lifecycle, sourceCommit, recordedAt = new Date().toISOString()) {
  if (!/^[a-f0-9]{40}$/.test(sourceCommit)) throw new Error("sourceCommit must be a full Git commit");
  const selectedManifest = providerManifest(manifest, lifecycle.provider);
  const comparison = compare(selectedManifest, {
    status: lifecycle.status,
    observations: lifecycle.observations,
  });
  const comparedCases = new Map(comparison.cases.map((item) => [item.caseId, item]));
  const targets = new Map(selectedManifest.targets.map((item) => [item.id, item]));
  const manifestCases = new Map(selectedManifest.cases.map((item) => [item.id, item]));
  const states = lifecycle.states.map((state) => {
    const cases = lifecycle.observations
      .filter((item) => manifestCases.get(item.caseId)?.state === state.state)
      .map((item) => ({
        caseId: item.caseId,
        present: item.present,
        classification: comparedCases.get(item.caseId).classification,
      }));
    const targetId = manifestCases.get(cases[0].caseId).targetId;
    const result = {
      state: state.state,
      targetRevision: targets.get(targetId).revision,
      cases,
    };
    if (lifecycle.provider === "supabase") result.authorizationChecks = state.authorizationChecks;
    return result;
  });
  return {
    $schema: "../../schemas/provider-configuration-report.schema.json",
    schemaVersion: "1.0.0",
    benchmarkVersion: manifest.benchmarkVersion,
    recordedAt,
    laboratory: { version: "0.0.0", sourceCommit },
    provider: lifecycle.provider,
    execution: {
      scope: "active-owner-authorized",
      interface: lifecycle.provider === "supabase" ? "postgresql-catalog-and-data-api" : "vercel-rest-api-v9",
      rawProviderResponseRetained: false,
    },
    summary: {
      runStatus: comparison.runStatus,
      verdict: comparison.verdict,
      clean: comparison.clean,
      counts: comparison.counts,
    },
    states,
    cleanup: lifecycle.cleanup,
    sanitization: {
      retained: ["logical-case-ids", "boolean-post-conditions", "state-revisions", "classifications", "cleanup-confirmation"],
      excluded: ["credentials", "provider-resource-ids", "project-references", "users", "rows", "logs", "source-code", "raw-responses"],
    },
  };
}

export function providerReportToMarkdown(report) {
  const lines = [
    `# ${report.provider === "supabase" ? "Supabase" : "Vercel"} provider configuration ground truth`,
    "",
    `- Recorded at: \`${report.recordedAt}\``,
    `- Run status: **${report.summary.runStatus}**`,
    `- Verdict: **${report.summary.verdict}**`,
    `- Clean: **${report.summary.clean ? "yes" : "no"}**`,
    `- Cleanup verified: **${Object.values(report.cleanup).every((value) => value === true || Number.isInteger(value)) ? "yes" : "no"}**`,
    "",
    "| State | True positive | True negative | False positive | False negative |",
    "| --- | ---: | ---: | ---: | ---: |",
  ];
  for (const state of report.states) {
    const count = (classification) => state.cases.filter((item) => item.classification === classification).length;
    lines.push(`| ${state.state} | ${count("true-positive")} | ${count("true-negative")} | ${count("false-positive")} | ${count("false-negative")} |`);
  }
  lines.push("", "Only logical case identifiers, booleans, immutable fixture revisions, classifications and cleanup confirmation are retained.", "");
  return lines.join("\n");
}

function parseArguments(arguments_) {
  const options = { provider: null, json: null, markdown: null, sourceCommit: null };
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (["--provider", "--json", "--markdown", "--source-commit"].includes(argument) && arguments_[index + 1]) {
      options[argument.slice(2).replace("-commit", "Commit")] = arguments_[++index];
    } else {
      throw new Error("usage: run-provider-configuration.mjs --provider <supabase|vercel> --source-commit SHA [--json PATH] [--markdown PATH]");
    }
  }
  if (!new Set(["supabase", "vercel"]).has(options.provider) || !options.sourceCommit) {
    throw new Error("--provider and --source-commit are required");
  }
  return options;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const manifest = await buildProviderConfigurationManifest();
  const lifecycle = options.provider === "supabase"
    ? await runSupabaseConfigurationLifecycle()
    : await runVercelConfigurationLifecycle();
  const report = buildSanitizedReport(manifest, lifecycle, options.sourceCommit);
  const json = `${JSON.stringify(report, null, 2)}\n`;
  const markdown = providerReportToMarkdown(report);
  if (options.json) await writeFile(resolve(process.cwd(), options.json), json, "utf8");
  if (options.markdown) await writeFile(resolve(process.cwd(), options.markdown), markdown, "utf8");
  if (!options.json && !options.markdown) process.stdout.write(json);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Provider configuration run failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}
